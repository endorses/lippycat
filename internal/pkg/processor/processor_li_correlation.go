//go:build (processor || tap || all) && li

package processor

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/uuid"
)

func (p *Processor) prepareLICorrelation() error {
	config := p.config.LICallCorrelation.Normalized()
	if err := config.Validate(); err != nil {
		return fmt.Errorf("configure LI call correlation: %w", err)
	}
	if !config.Enabled() {
		return nil
	}
	// A stateless manager can reuse task generations after restart. Give its
	// memberships a fresh instance context; persistent managers use their stable
	// authenticated administrative incarnation instead.
	context := uuid.Nil
	if p.liManager != nil {
		context = p.liManager.StateIncarnation()
	}
	if context == uuid.Nil {
		var err error
		context, err = uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("allocate LI correlation task context: %w", err)
		}
	}
	p.liStorage.correlationContext = context
	var store *li.CallCorrelationStore
	if config.StoreFile != "" {
		path, err := filepath.Abs(config.StoreFile)
		if err != nil {
			return fmt.Errorf("resolve LI correlation store: %w", err)
		}
		for _, protected := range []string{p.config.FilterFile, p.config.LIStateFile, p.config.LIRADIUSCorrelationStateFile} {
			if protected == "" {
				continue
			}
			other, err := filepath.Abs(protected)
			if err != nil {
				return fmt.Errorf("resolve protected LI storage: %w", err)
			}
			if path == other {
				return errors.New("LI correlation store must be separate from other stores")
			}
		}
		store, err = li.OpenCallCorrelationStore(path, config.StoreKeys, config.MaxRecords)
		if err != nil {
			return fmt.Errorf("authenticate LI call correlation store: %w", err)
		}
	}
	var persistence li.CallCorrelationPersistence
	if store != nil {
		persistence = store
	}
	correlator, err := li.NewCallCorrelator(config, voip.GetConfig().CallExpirationTime, persistence)
	if err != nil {
		if store != nil {
			err = errors.Join(err, store.Close())
		}
		return err
	}
	p.liStorage.correlation, p.liStorage.correlationStore = correlator, store
	return nil
}

func (p *Processor) liCorrelationKeyring() *securestore.Keyring {
	if p.liStorage == nil || p.liStorage.correlationStore == nil {
		return nil
	}
	return p.liStorage.correlationStore.Keyring()
}

func (p *Processor) publishLICorrelation(decision *li.CallCorrelationDecision) {
	if decision != nil && p.liStorage != nil && p.liStorage.correlation != nil {
		p.liStorage.correlation.Published(*decision)
	}
}

func (p *Processor) startLICorrelationMaintenance() {
	if p.liStorage == nil || p.liStorage.correlation == nil {
		return
	}
	p.liStorage.correlationStop = make(chan struct{})
	p.liStorage.correlationWorkers.Add(1)
	go func() {
		defer p.liStorage.correlationWorkers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var lastWarning time.Time
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-p.liStorage.correlationStop:
				return
			case now := <-ticker.C:
				if err := p.liStorage.correlation.Maintain(); err != nil && (lastWarning.IsZero() || now.Sub(lastWarning) >= time.Minute) {
					// Store errors can include paths. Status supplies aggregate fault
					// state; keep periodic logs free of call identities and key paths.
					logger.Warn("LI call correlation persistence retry failed", "unresolved_writes", p.liStorage.correlation.Stats().UnresolvedWrites)
					lastWarning = now
				}
			}
		}
	}()
}

// deferredLICorrelationPacket owns the mutable packet/task input and remembers
// lifecycle identity without retaining an admission across storage I/O.
type deferredLICorrelationPacket struct {
	packet      *types.PacketDisplay
	tasks       []*li.InterceptTask
	bytes       int
	generation  uint64
	incarnation uuid.UUID
	admittedAt  time.Time
	provenance  any
}

func (p *Processor) snapshotLICorrelationPacket(pkt *types.PacketDisplay, tasks []*li.InterceptTask) (*deferredLICorrelationPacket, bool) {
	snapshot := &deferredLICorrelationPacket{tasks: make([]*li.InterceptTask, 0, len(tasks)), bytes: 2048, admittedAt: time.Now()}
	clone := *pkt
	clone.RawData = append([]byte(nil), pkt.RawData...)
	// These protocol metadata objects are never consumed by the SIP/RTP LI path.
	clone.DNSData, clone.EmailData, clone.TLSData, clone.HTTPData, clone.RADIUSData = nil, nil, nil, nil, nil
	snapshot.bytes += len(clone.RawData) + len(clone.SrcIP) + len(clone.DstIP) + len(clone.SrcPort) + len(clone.DstPort) + len(clone.Info) + len(clone.NodeID) + len(clone.Interface) + len(clone.Protocol)
	if pkt.VoIPData != nil {
		voip := *pkt.VoIPData
		voip.RawSIP = append([]byte(nil), voip.RawSIP...)
		voip.Headers = make(map[string]string, len(voip.Headers))
		for key, value := range pkt.VoIPData.Headers {
			voip.Headers[key] = value
			snapshot.bytes += 128 + len(key) + len(value)
		}
		if voip.AccessNetworkInfo != nil {
			access := *voip.AccessNetworkInfo
			access.Parameters = make(map[string]string, len(access.Parameters))
			for key, value := range voip.AccessNetworkInfo.Parameters {
				access.Parameters[key] = value
				snapshot.bytes += 128 + len(key) + len(value)
			}
			snapshot.bytes += len(access.AccessType) + len(access.BSSID) + len(access.CellID) + len(access.LocalIP)
			voip.AccessNetworkInfo = &access
		}
		snapshot.bytes += len(voip.RawSIP)
		for _, value := range []string{voip.CallID, voip.Method, voip.CSeqMethod, voip.ViaBranch, voip.From, voip.To, voip.FromTag, voip.ToTag, voip.User, voip.ContentType, voip.Body, voip.IMSI, voip.IMEI, voip.VisitedNetworkID, voip.Codec, voip.MergeFromCallID} {
			snapshot.bytes += len(value)
		}
		clone.VoIPData = &voip
		if shared, ok := p.liPacketAdmissions.Load(pkt); ok {
			original := shared.(*CallAdmission)
			snapshot.incarnation, snapshot.admittedAt = original.Incarnation(), original.admittedAt
			if voip.IsRTP {
				snapshot.generation = original.Generation()
			}
		} else if voip.IsRTP && voip.CallID != "" && p.callLifecycle != nil {
			original, err := p.callLifecycle.Admit(voip.CallID)
			if err != nil {
				return nil, false
			}
			snapshot.generation, snapshot.incarnation, snapshot.admittedAt = original.Generation(), original.Incarnation(), original.admittedAt
			original.Release()
		}
	}
	for _, task := range tasks {
		copied := *task
		copied.Targets = append([]li.TargetIdentity(nil), task.Targets...)
		copied.DestinationIDs = append([]uuid.UUID(nil), task.DestinationIDs...)
		snapshot.tasks = append(snapshot.tasks, &copied)
		snapshot.bytes += 512 + len(copied.DestinationIDs)*16 + len(copied.LastError) + len(copied.Definition.ConflictReason) + len(copied.RADIUSMACProfile)
		for _, target := range copied.Targets {
			snapshot.bytes += 64 + len(target.Value)
		}
	}
	if p.liStorage != nil {
		snapshot.provenance, _ = p.liStorage.packetProvenance.Load(pkt)
	}
	snapshot.packet = &clone
	return snapshot, true
}
func (p *Processor) deliverLICorrelationSnapshot(snapshot *deferredLICorrelationPacket, decision li.CallCorrelationDecision, process func(*li.InterceptTask, *types.PacketDisplay, *li.CallCorrelationDecision)) {
	if p.ctx.Err() != nil {
		return
	}
	if snapshot.generation != 0 {
		admission, err := p.callLifecycle.AdmitGeneration(snapshot.packet.VoIPData.CallID, snapshot.generation)
		if err != nil {
			return
		}
		defer admission.Release()
		if admission.Incarnation() != snapshot.incarnation {
			return
		}
		// Queueing must not extend the original delivery admission deadline.
		admission.admittedAt = snapshot.admittedAt
		p.liPacketAdmissions.Store(snapshot.packet, admission)
		defer p.liPacketAdmissions.Delete(snapshot.packet)
	} else if snapshot.packet.VoIPData != nil && !snapshot.packet.VoIPData.IsRTP {
		// Signaling remains subject to task admission, including late BYE. This
		// metadata stamp preserves capture admission time without imposing the
		// stricter media lifecycle gate on X2 signaling.
		stamp := &CallAdmission{admittedAt: snapshot.admittedAt}
		if snapshot.incarnation != uuid.Nil {
			stamp.call = &lifecycleCall{incarnation: snapshot.incarnation}
		}
		p.liPacketAdmissions.Store(snapshot.packet, stamp)
		defer p.liPacketAdmissions.Delete(snapshot.packet)
	}
	if snapshot.provenance != nil {
		p.liStorage.packetProvenance.Store(snapshot.packet, snapshot.provenance)
		defer p.liStorage.packetProvenance.Delete(snapshot.packet)
	}
	for _, task := range snapshot.tasks {
		process(task, snapshot.packet, &decision)
	}
}
