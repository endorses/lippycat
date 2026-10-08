//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type processorBlockingCorrelationStore struct {
	entered, release  chan struct{}
	once, releaseOnce sync.Once
	outcome           securestore.Outcome
}

func (s *processorBlockingCorrelationStore) Load() ([]li.StoredCallCorrelation, error) {
	return nil, nil
}
func (s *processorBlockingCorrelationStore) Close() error { return nil }
func (s *processorBlockingCorrelationStore) Save([]li.StoredCallCorrelation) (securestore.Outcome, error) {
	first := false
	s.once.Do(func() { first = true; close(s.entered); <-s.release })
	if !first {
		return securestore.Committed, nil
	}
	if s.outcome != securestore.Committed {
		return s.outcome, errors.New("synthetic write failure")
	}
	return s.outcome, nil
}
func (s *processorBlockingCorrelationStore) unblock() { s.releaseOnce.Do(func() { close(s.release) }) }

func injectBlockingCorrelationStore(t *testing.T, p *Processor, outcome securestore.Outcome) *processorBlockingCorrelationStore {
	t.Helper()
	// Join the startup maintenance owner before replacing its correlator. Packet
	// processing has not begun, so no live callback can observe the replacement.
	p.liStorage.correlationStopOnce.Do(func() { close(p.liStorage.correlationStop) })
	p.liStorage.correlationWorkers.Wait()
	require.NoError(t, p.liStorage.correlation.Close())
	store := &processorBlockingCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), outcome: outcome}
	correlator, err := li.NewCallCorrelator(p.config.LICallCorrelation, 10*time.Minute, store)
	require.NoError(t, err)
	p.liStorage.correlation = correlator
	t.Cleanup(store.unblock)
	return store
}
func awaitCorrelationBarrier(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

func correlationBlockingCapturedSIP(t *testing.T, packet *types.PacketDisplay, filters []string) *data.CapturedPacket {
	t.Helper()
	frame := liTestSIPFrame(t, packet.VoIPData.RawSIP, false)
	return &data.CapturedPacket{TimestampNs: packet.Timestamp.UnixNano(), Data: frame, CaptureLength: uint32(len(frame)), OriginalLength: uint32(len(frame)), LinkType: uint32(layers.LinkTypeEthernet), MatchedFilterIds: filters, DirectMatchedFilterIds: filters,
		Metadata: &data.PacketMetadata{SrcIp: packet.SrcIP, DstIp: packet.DstIP, SrcPort: 5060, DstPort: 5060, Protocol: "SIP", Sip: &data.SIPMetadata{CallId: packet.VoIPData.CallID, Method: "INVITE", CseqMethod: "INVITE", CseqNumber: 1, ViaBranch: packet.VoIPData.ViaBranch, FromTag: "caller", FromUri: dirTargetURI, ToUri: dirRemoteURI}}}
}

func TestProcessorCallCorrelationBlockedWritePreservesTLSDelivery(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			port, products := correlationMDF(t)
			config := storageKeyStartupConfig(t)
			config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-blocked-store", "localhost:0", 1
			config.LICallCorrelation = li.DefaultCallCorrelationConfig()
			config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
			config.LICallCorrelation.DecisionHorizon = time.Nanosecond
			p, err := newTestProcessor(t, config)
			require.NoError(t, err)
			p.ctx, p.cancel = context.WithCancel(context.Background())
			require.NoError(t, p.startLIManager())
			// Cleanup releases the explicit test barrier before production shutdown joins.
			var store *processorBlockingCorrelationStore
			t.Cleanup(func() {
				if store != nil {
					store.unblock()
				}
				require.NoError(t, p.Shutdown())
			})
			store = injectBlockingCorrelationStore(t, p, outcome)
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true}))
			require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only}))
			filters := []string{"li-" + xid.String() + "-0"}
			at := time.Now().UTC()
			root := correlationIntegrationSIP("blocked-root", dirTargetURI, at)
			p.processLIPacketWithProvenance(root, filters, nil)
			var rootID uint64
			select {
			case product := <-products:
				rootID = product.Header.CorrelationID
			case <-time.After(5 * time.Second):
				t.Fatal("root not delivered")
			}
			child := correlationIntegrationSIP("blocked-child", dirTargetURI, at.Add(time.Millisecond))
			// Batch content policy runs before LI; compare a body-free input.
			child.VoIPData.RawSIP = []byte(strings.Replace(strings.TrimSuffix(string(child.VoIPData.RawSIP), "secret"), "Content-Length: 6", "Content-Length: 0", 1))
			child.RawData = child.VoIPData.RawSIP
			independent := correlationIntegrationSIP("unrelated-leg", dirTargetURI, at.Add(2*time.Millisecond))
			independent.VoIPData.RawSIP = []byte(strings.Replace(string(independent.VoIPData.RawSIP), "shared;complete=value", "unrelated;complete=value", 1))
			independent.RawData = independent.VoIPData.RawSIP
			childDone := make(chan struct{})
			go func() {
				p.processBatch(source.FromProtoBatch(&data.PacketBatch{HunterId: "blocked-store-fixture", Packets: []*data.CapturedPacket{
					correlationBlockingCapturedSIP(t, child, filters),
					correlationBlockingCapturedSIP(t, root, filters),
					correlationBlockingCapturedSIP(t, independent, filters),
				}}))
				close(childDone)
			}()
			awaitCorrelationBarrier(t, store.entered, "adoption did not reach test write barrier")
			awaitCorrelationBarrier(t, childDone, "held Save blocked later packets in the same real batch")
			// Save remains held until both unrelated authorized products reach real TLS.
			got := map[string]uint64{}
			for range 2 {
				select {
				case product := <-products:
					require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
					require.Equal(t, xid, product.Header.XID)
					if strings.Contains(string(product.Payload), "Call-ID: blocked-root\r\n") {
						got["root"] = product.Header.CorrelationID
					} else if strings.Contains(string(product.Payload), "Call-ID: unrelated-leg\r\n") {
						got["unrelated"] = product.Header.CorrelationID
					} else {
						t.Fatal("unexpected delivery while adoption held")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("held Save blocked unrelated TLS delivery")
				}
			}
			require.Equal(t, rootID, got["root"])
			require.NotZero(t, got["unrelated"])
			require.NotEqual(t, rootID, got["unrelated"])
			store.unblock()
			awaitCorrelationBarrier(t, childDone, "adoption did not finish after explicit release")
			select {
			case product := <-products:
				require.Equal(t, child.VoIPData.RawSIP, product.Payload)
				if outcome == securestore.NotCommitted {
					require.NotEqual(t, rootID, product.Header.CorrelationID)
				} else {
					require.Equal(t, rootID, product.Header.CorrelationID)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("released adoption not delivered")
			}
		})
	}
}

func TestProcessorCallCorrelationBlockedWritePreservesJournalAdmission(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	f.config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	f.config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	store := injectBlockingCorrelationStore(t, p, securestore.Committed)
	t.Cleanup(func() { store.unblock(); require.NoError(t, p.Shutdown()) })
	filters := []string{"li-" + f.xid.String() + "-0"}
	at := time.Now().UTC()
	p.processLIPacketWithProvenance(correlationIntegrationSIP("journal-root", f.target, at), filters, nil)
	p.processLIPacketWithProvenance(correlationIntegrationRTP("journal-root", 0, at), nil, filters)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 1, liDeliveryClient.X3JournalStats().Persisted)
	childDone := make(chan struct{})
	go func() {
		p.processLIPacketWithProvenance(correlationIntegrationSIP("journal-child", f.target, at.Add(time.Millisecond)), filters, nil)
		close(childDone)
	}()
	awaitCorrelationBarrier(t, store.entered, "journal adoption did not reach write barrier")
	unrelated := correlationIntegrationSIP("journal-unrelated", f.target, at.Add(2*time.Millisecond))
	unrelated.VoIPData.RawSIP = []byte(strings.Replace(string(unrelated.VoIPData.RawSIP), "shared;complete=value", "unrelated;complete=value", 1))
	unrelated.RawData = unrelated.VoIPData.RawSIP
	admitted := make(chan struct{})
	go func() {
		p.processLIPacketWithProvenance(correlationIntegrationRTP("journal-root", 1, at.Add(2*time.Millisecond)), nil, filters)
		p.processLIPacketWithProvenance(unrelated, filters, nil)
		p.processLIPacketWithProvenance(correlationIntegrationRTP("journal-unrelated", 2, at.Add(3*time.Millisecond)), nil, filters)
		close(admitted)
	}()
	awaitCorrelationBarrier(t, admitted, "held correlation Save blocked X3 journal admission")
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 3, liDeliveryClient.X3JournalStats().Persisted, "held Save must not block durable unrelated publication")
	store.unblock()
	awaitCorrelationBarrier(t, childDone, "journal adoption did not finish after release")
}

func TestProcessorCallCorrelationSnapshotIsOwnedAndLifetimeBound(t *testing.T) {
	p := &Processor{ctx: context.Background(), callLifecycle: NewCallLifecycleRegistry(CallLifecycleConfig{}), liStorage: &liStoragePreparation{}}
	packet := correlationIntegrationSIP("snapshot-leg", dirTargetURI, time.Now())
	packet.VoIPData.IsRTP = true
	packet.VoIPData.Headers = map[string]string{"X-Test-Session": "original"}
	packet.VoIPData.AccessNetworkInfo = &types.AccessNetworkInfo{Parameters: map[string]string{"synthetic": "original"}}
	task := &li.InterceptTask{XID: uuid.New(), ActivationGeneration: 1, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{uuid.New()}}
	snapshot, ok := p.snapshotLICorrelationPacket(packet, []*li.InterceptTask{task})
	require.True(t, ok)
	raw := append([]byte(nil), snapshot.packet.RawData...)
	destination := snapshot.tasks[0].DestinationIDs[0]
	packet.RawData[0] = 'X'
	packet.VoIPData.Headers["X-Test-Session"] = "modified"
	packet.VoIPData.AccessNetworkInfo.Parameters["synthetic"] = "modified"
	task.Targets[0].Value = "modified"
	task.DestinationIDs[0] = uuid.New()
	require.Equal(t, raw, snapshot.packet.RawData)
	require.Equal(t, "original", snapshot.packet.VoIPData.Headers["X-Test-Session"])
	require.Equal(t, "original", snapshot.packet.VoIPData.AccessNetworkInfo.Parameters["synthetic"])
	require.Equal(t, dirTarget, snapshot.tasks[0].Targets[0])
	require.Equal(t, destination, snapshot.tasks[0].DestinationIDs[0])
	called := false
	p.deliverLICorrelationSnapshot(snapshot, li.CallCorrelationDecision{}, func(_ *li.InterceptTask, packet *types.PacketDisplay, _ *li.CallCorrelationDecision) {
		called = true
		grant, found := p.liPacketAdmissions.Load(packet)
		require.True(t, found)
		require.Equal(t, snapshot.generation, grant.(*CallAdmission).Generation())
		require.Equal(t, snapshot.incarnation, grant.(*CallAdmission).Incarnation())
		require.Equal(t, snapshot.admittedAt, grant.(*CallAdmission).admittedAt)
	})
	require.True(t, called)
	require.True(t, p.callLifecycle.Finalize("snapshot-leg", CallFinalizationProtocolComplete).Finalized, "snapshot must hold no admission across the storage wait")
	newLifetime, err := p.callLifecycle.RestartInvite("snapshot-leg")
	require.NoError(t, err)
	newLifetime.Release()
	require.NotEqual(t, snapshot.generation, newLifetime.Generation())
	p.deliverLICorrelationSnapshot(snapshot, li.CallCorrelationDecision{}, func(*li.InterceptTask, *types.PacketDisplay, *li.CallCorrelationDecision) {
		t.Fatal("deferred packet crossed a call lifetime")
	})
}

func TestProcessorCallCorrelationLateAuthorizedBYERetainsX2(t *testing.T) {
	port, products := correlationMDF(t)
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-late-signaling", "localhost:0", 1
	config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true}))
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only}))
	filters := []string{"li-" + xid.String() + "-0"}
	packet := correlationIntegrationSIP("late-signaling-leg", dirTargetURI, time.Now())
	p.processLIPacketWithProvenance(packet, filters, nil)
	var selected uint64
	select {
	case product := <-products:
		selected = product.Header.CorrelationID
	case <-time.After(5 * time.Second):
		t.Fatal("initial signaling not delivered")
	}
	grant, err := p.callLifecycle.Admit(packet.VoIPData.CallID)
	require.NoError(t, err)
	grant.Release()
	require.True(t, p.callLifecycle.Finalize(packet.VoIPData.CallID, CallFinalizationProtocolComplete).Finalized)
	bye := *packet
	metadata := *packet.VoIPData
	bye.VoIPData = &metadata
	metadata.Method, metadata.CSeqMethod, metadata.CSeqNumber = "BYE", "BYE", 2
	metadata.RawSIP = []byte(strings.Replace(strings.TrimSuffix(string(metadata.RawSIP), "secret"), "Content-Length: 6", "Content-Length: 0", 1))
	metadata.RawSIP = []byte(strings.Replace(strings.Replace(string(metadata.RawSIP), "INVITE ", "BYE ", 1), "CSeq: 1 INVITE", "CSeq: 2 BYE", 1))
	bye.RawData = metadata.RawSIP
	p.processLIPacketWithProvenance(&bye, filters, nil)
	select {
	case product := <-products:
		require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
		require.Equal(t, selected, product.Header.CorrelationID)
		require.Equal(t, metadata.RawSIP, product.Payload)
	case <-time.After(5 * time.Second):
		t.Fatal("media finalization suppressed authorized late X2 BYE")
	}
}

func TestProcessorCallCorrelationDeferredPacketRechecksTask(t *testing.T) {
	port, products := correlationMDF(t)
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-deferred-task", "localhost:0", 1
	config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	store := injectBlockingCorrelationStore(t, p, securestore.Committed)
	t.Cleanup(func() { store.unblock(); require.NoError(t, p.Shutdown()) })
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true}))
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2Only}))
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	filters := []string{"li-" + xid.String() + "-0"}
	at := time.Now()
	p.processLIPacketWithProvenance(correlationIntegrationSIP("task-root", dirTargetURI, at), filters, nil)
	select {
	case <-products:
	case <-time.After(5 * time.Second):
		t.Fatal("initial authorized product not delivered")
	}
	child := correlationIntegrationSIP("task-child", dirTargetURI, at.Add(time.Millisecond))
	p.processLIPacketWithProvenance(child, filters, nil)
	awaitCorrelationBarrier(t, store.entered, "task child did not reach held write")
	before := p.getLIEncodingStats()
	require.NoError(t, p.liManager.DeactivateTask(xid))
	// This FIFO sentinel runs only after the actual processor packet callback.
	// It supplies an explicit completion barrier without waiting for non-delivery.
	callbackDone := make(chan struct{})
	require.NoError(t, p.liStorage.correlation.ResolveAsync(p.ctx, child, []li.CallCorrelationTask{{StateIncarnation: p.liStorage.correlationContext, XID: xid, Generation: task.ActivationGeneration}}, 0, func(li.CallCorrelationDecision) { close(callbackDone) }))
	store.unblock()
	awaitCorrelationBarrier(t, callbackDone, "deferred callbacks did not drain")
	require.Equal(t, before, p.getLIEncodingStats(), "task revocation must suppress deferred encoding before queue admission")
	select {
	case <-products:
		t.Fatal("revoked deferred packet reached TLS")
	default:
	}
}

func TestProcessorCallCorrelationDeferredMediaRejectsReusedLifetime(t *testing.T) {
	port, products := correlationMDF(t)
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-deferred-media", "localhost:0", 1
	config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	store := injectBlockingCorrelationStore(t, p, securestore.Committed)
	t.Cleanup(func() { store.unblock(); require.NoError(t, p.Shutdown()) })
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X3Enabled: true}))
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX3Only}))
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	filters := []string{"li-" + xid.String() + "-0"}
	at := time.Now()
	p.processLIPacketWithProvenance(correlationIntegrationSIP("media-root", dirTargetURI, at), filters, nil)
	p.processLIPacketWithProvenance(correlationIntegrationRTP("media-root", 0, at), nil, filters)
	// The real reorder worker produces the single admitted root media product.
	select {
	case product := <-products:
		require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("initial media not delivered")
	}
	child := correlationIntegrationSIP("media-child", dirTargetURI, at.Add(time.Millisecond))
	p.processLIPacketWithProvenance(child, filters, nil)
	awaitCorrelationBarrier(t, store.entered, "child media association did not reach held write")
	p.processLIPacketWithProvenance(correlationIntegrationRTP("media-child", 1, at.Add(2*time.Millisecond)), nil, filters)
	before := p.getLIEncodingStats()
	require.True(t, p.callLifecycle.Finalize("media-child", CallFinalizationProtocolComplete).Finalized)
	replacement, err := p.callLifecycle.RestartInvite("media-child")
	require.NoError(t, err)
	replacement.Release()
	callbackDone := make(chan struct{})
	require.NoError(t, p.liStorage.correlation.ResolveAsync(p.ctx, child, []li.CallCorrelationTask{{StateIncarnation: p.liStorage.correlationContext, XID: xid, Generation: task.ActivationGeneration}}, 0, func(li.CallCorrelationDecision) { close(callbackDone) }))
	store.unblock()
	awaitCorrelationBarrier(t, callbackDone, "deferred media callbacks did not drain")
	require.Equal(t, before, p.getLIEncodingStats(), "held old-lifetime media must not encode into a replacement call")
	select {
	case <-products:
		t.Fatal("old lifetime media reached TLS")
	default:
	}
}
