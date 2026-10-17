//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"google.golang.org/protobuf/proto"
)

func (p *Processor) rejectLIOwnedFilterMutation(id string) error {
	if p.config.LIHandover.Enabled && strings.HasPrefix(id, "li-") {
		return errors.New("LI capture-policy filters are owned by the central task manager")
	}
	return nil
}

func (p *Processor) liCapturePolicyFilters() ([]*management.Filter, error) {
	if !p.config.LIHandover.Enabled || p.liManager == nil {
		return nil, li.ErrCaptureAuthority
	}
	return p.liManager.HandoverFilters()
}

func (p *Processor) startLIHandoverPolicy(ctx context.Context) error {
	config, err := p.config.LIHandover.Normalize()
	if err != nil {
		return err
	}
	if !config.Enabled {
		return nil
	}
	p.config.LIHandover = config
	if p.sharedPolicy == nil || p.sharedPolicy.config.Owner != "li" || p.sharedPolicy.signer == nil || !p.isLIEnabled() {
		return fmt.Errorf("LI handover requires a signing LI shared-policy owner and enabled LI manager")
	}
	if err := p.publishLIHandoverPolicy(time.Now()); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	p.liHandoverCancel = cancel
	p.liHandoverWG.Add(1)
	go func() {
		defer p.liHandoverWG.Done()
		ticker := time.NewTicker(max(config.LeaseDuration/3, time.Nanosecond))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := p.publishLIHandoverPolicy(time.Now()); err != nil {
					// Failure never renews the old lease. Consumers independently
					// enforce its signed deadline, including disconnected ones.
					logger.Error("LI capture policy renewal failed", "error", err)
				}
			}
		}
	}()
	return nil
}

func (p *Processor) closeLIHandoverPolicy() {
	if p.liHandoverCancel != nil {
		p.liHandoverCancel()
	}
	p.liHandoverWG.Wait()
}

func (p *Processor) publishLIHandoverPolicy(now time.Time) error {
	runtime := p.sharedPolicy
	if runtime == nil || runtime.signer == nil || p.liManager == nil {
		return li.ErrCaptureAuthority
	}
	runtime.publicationMu.Lock()
	defer runtime.publicationMu.Unlock()
	var revision uint64
	if previous := runtime.state.Latest(); previous != nil {
		revision = previous.Snapshot.Revision
		if now.Before(time.Unix(0, previous.Snapshot.ValidFromNs).Add(-p.config.LIHandover.ClockUncertainty)) {
			// A wall-clock rollback cannot mint a new, apparently fresh lease.
			return li.ErrCaptureAuthority
		}
	}
	if revision == ^uint64(0) {
		return li.ErrCaptureAuthority
	}
	return p.liManager.PublishHandoverAuthority(p.config.LIHandover, now, func(filters []*management.Filter, authority []byte) error {
		snapshot := &management.PolicySnapshot{ProtocolVersion: 1, Domain: runtime.config.Domain, AuthorityId: runtime.config.AuthorityID, OwnerKind: "li", Revision: revision + 1, Filters: filters}
		if err := p.completeLICapturePolicy(snapshot, authority, p.config.LIHandover, now); err != nil {
			return err
		}
		signed, err := runtime.state.Verifier().SignSnapshot(runtime.signer, snapshot)
		if err != nil {
			return err
		}
		return runtime.install(signed)
	})
}

// buildLICapturePolicy bridges the actual local LI owner into a signed snapshot.
// The generic publisher signs the returned fields without renaming LI filters.
func (p *Processor) buildLICapturePolicy(snapshot *management.PolicySnapshot, now time.Time) error {
	if snapshot.GetOwnerKind() != "li" {
		if p.config.LIHandover.Enabled {
			return li.ErrCaptureAuthority
		}
		return nil
	}
	config, err := p.config.LIHandover.Normalize()
	if err != nil || !config.Enabled || !p.isLIEnabled() || p.liManager == nil {
		return errors.Join(li.ErrCaptureAuthority, err)
	}
	encoded, err := p.liManager.BuildHandoverAuthority(snapshot.Filters, config, now)
	if err != nil {
		return err
	}
	return p.completeLICapturePolicy(snapshot, encoded, config, now)
}

func (p *Processor) completeLICapturePolicy(snapshot *management.PolicySnapshot, encoded []byte, config li.HandoverConfig, now time.Time) error {
	until, err := li.HandoverLeaseBounds(encoded, now, config.LeaseDuration)
	if err != nil {
		return err
	}
	snapshot.CaptureAuthority = encoded
	// The generic hunter enforces these already narrowed bounds without needing
	// to interpret task JSON or becoming an X1 task manager.
	snapshot.ValidFromNs = now.Add(config.ClockUncertainty).UnixNano()
	snapshot.ValidUntilNs = until.Add(-config.ClockUncertainty).UnixNano()
	snapshot.AllowOfflineCapture = config.AllowOffline
	snapshot.SourceIds = append([]string(nil), config.SourceIDs...)
	return nil
}

func (p *Processor) verifiedLICaptureSnapshot(encoded []byte) (*management.PolicySnapshot, error) {
	if len(encoded) == 0 || len(encoded) > filterpolicy.MaxSnapshotBytes || p.sharedPolicy == nil || !p.config.LIHandover.Enabled || !p.isLIEnabled() {
		return nil, li.ErrCaptureAuthority
	}
	signed := &management.SignedPolicySnapshot{}
	if err := proto.Unmarshal(encoded, signed); err != nil {
		return nil, li.ErrCaptureAuthority
	}
	if err := p.sharedPolicy.state.Verifier().Verify(signed); err != nil || signed.GetSnapshot().GetOwnerKind() != "li" {
		return nil, li.ErrCaptureAuthority
	}
	config, err := p.config.LIHandover.Normalize()
	if err != nil || signed.Snapshot.ValidFromNs <= 0 || signed.Snapshot.ValidUntilNs <= signed.Snapshot.ValidFromNs || time.Duration(signed.Snapshot.ValidUntilNs-signed.Snapshot.ValidFromNs) > config.LeaseDuration || (signed.Snapshot.AllowOfflineCapture && !config.AllowOffline) {
		return nil, li.ErrCaptureAuthority
	}
	return signed.Snapshot, nil
}

func capturePacketFilterIDs(packet *data.CapturedPacket) []string {
	ids := append([]string(nil), packet.MatchedFilterIds...)
	ids = append(ids, packet.DirectMatchedFilterIds...)
	return append(ids, packet.InheritedMatchedFilterIds...)
}

// validateLICapturePolicy gates raw custody before acceptance. Transport receipt
// still means durable raw ingestion, never permission or success at the MDF.
func (p *Processor) validateLICapturePolicy(batch *data.PacketBatch) error {
	if batch == nil {
		return li.ErrCaptureAuthority
	}
	if !p.config.LIHandover.Enabled {
		if len(batch.SignedCapturePolicy) == 0 || !p.isLIEnabled() {
			// A generic relay transports opaque policy without acquiring LI
			// authority or needing LI consumer configuration.
			return nil
		}
		owner := &management.SignedPolicySnapshot{}
		if err := proto.Unmarshal(batch.SignedCapturePolicy, owner); err != nil {
			return li.ErrCaptureAuthority
		}
		if owner.GetSnapshot().GetOwnerKind() != "li" {
			return nil // ordinary shared capture remains independent of LI
		}
	}
	snapshot, err := p.verifiedLICaptureSnapshot(batch.SignedCapturePolicy)
	if err != nil {
		return err
	}
	for _, packet := range batch.Packets {
		if packet == nil {
			return li.ErrCaptureAuthority
		}
		ids := capturePacketFilterIDs(packet)
		if packet.Radius != nil {
			// RADIUS carries additional generation-aware attribution internally.
			// Bind its entire owner snapshot here; its dedicated LI admission still
			// checks byte provenance, source delegation and current task ownership.
			for _, filter := range snapshot.Filters {
				ids = append(ids, filter.Id)
			}
		}
		if err := p.liManager.ValidateHandoverAuthority(snapshot.CaptureAuthority, snapshot.Filters, ids, batch.HunterId, time.Unix(0, packet.TimestampNs), time.Now(), p.config.LIHandover); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) liPacketCaptureAuthority(packet *types.PacketDisplay, direct, inherited []string, encoded []byte) (*li.HandoverAuthority, error) {
	if packet == nil {
		return nil, li.ErrCaptureAuthority
	}
	if !p.config.LIHandover.Enabled {
		owner := &management.SignedPolicySnapshot{}
		if err := proto.Unmarshal(encoded, owner); err != nil {
			return nil, li.ErrCaptureAuthority
		}
		if owner.GetSnapshot().GetOwnerKind() != "li" {
			return nil, nil
		}
	}
	snapshot, err := p.verifiedLICaptureSnapshot(encoded)
	if err != nil {
		return nil, err
	}
	ids := append(append([]string(nil), direct...), inherited...)
	if err := p.liManager.ValidateHandoverAuthority(snapshot.CaptureAuthority, snapshot.Filters, ids, packet.NodeID, packet.Timestamp, time.Now(), p.config.LIHandover); err != nil {
		return nil, err
	}
	return li.DecodeHandoverAuthority(snapshot.CaptureAuthority)
}

// processLIPacketWithCapturePolicy rechecks capture generations immediately at
// the LI lookup, while all existing call, task and destination gates still run.
func (p *Processor) processLIPacketWithCapturePolicy(packet *types.PacketDisplay, direct, inherited []string, admission *CallAdmission, encoded []byte) {
	p.processLIPacketWithAdmission(packet, direct, inherited, admission, encoded)
}
