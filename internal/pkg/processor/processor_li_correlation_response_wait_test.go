//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func responseWaitProcessor(t *testing.T, destinations int) (*Processor, uuid.UUID, []string, []<-chan *x2x3.PDU) {
	t.Helper()
	cfg := storageKeyStartupConfig(t)
	cfg.ProcessorID, cfg.ListenAddr, cfg.MaxHunters = "response-wait-integration", "localhost:0", 1
	cfg.LICallCorrelation = li.DefaultCallCorrelationConfig()
	cfg.LICallCorrelation.AddressChaining = true
	cfg.LICallCorrelation.ResponseWait = true
	// A matching request, rather than an elapsed timer, releases these tests.
	cfg.LICallCorrelation.ResponseWaitWindow = time.Hour
	cfg.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	xid := uuid.New()
	var dids []uuid.UUID
	var streams []<-chan *x2x3.PDU
	for range destinations {
		port, stream := correlationMDF(t)
		did := uuid.New()
		require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true}))
		dids, streams = append(dids, did), append(streams, stream)
	}
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: dids, DeliveryType: li.DeliveryX2andX3}))
	return p, xid, []string{"li-" + xid.String() + "-0"}, streams
}

func responseWaitLeg(id string, hop int, at time.Time) *types.PacketDisplay {
	p := correlationIntegrationSIP(id, dirTargetURI, at)
	p.SrcIP, p.DstIP = fmt.Sprintf("192.0.2.%d", hop+1), fmt.Sprintf("192.0.2.%d", hop+2)
	return p
}

func responseWaitTrying(invite *types.PacketDisplay) *types.PacketDisplay {
	p := *invite
	m := *invite.VoIPData
	p.VoIPData = &m
	p.SrcIP, p.DstIP = invite.DstIP, invite.SrcIP
	m.Method, m.Status = "", 100
	lineEnd := strings.Index(string(m.RawSIP), "\r\n")
	m.RawSIP = []byte("SIP/2.0 100 Trying" + string(m.RawSIP[lineEnd:]))
	p.RawData = m.RawSIP
	return &p
}

func responseWaitProduct(t *testing.T, stream <-chan *x2x3.PDU) *x2x3.PDU {
	t.Helper()
	select {
	case product := <-stream:
		return product
	case <-time.After(5 * time.Second):
		t.Fatal("authorized response-wait product did not reach TLS MDF")
		return nil
	}
}

// Appending a callback after processor submissions supplies an explicit FIFO
// completion barrier. It does not encode another packet or publish a product.
func responseWaitBarrier(t *testing.T, p *Processor, xid uuid.UUID, packet *types.PacketDisplay, generation uint64) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	tasks := []li.CallCorrelationTask{{StateIncarnation: p.liStorage.correlationContext, XID: xid, Generation: generation}}
	require.NoError(t, p.liStorage.correlation.ResolveAsync(p.ctx, packet, tasks, 0, func(li.CallCorrelationDecision) { close(done) }))
	return done
}

func TestProcessorCallCorrelationResponseWaitTLSFanoutAndMedia(t *testing.T) {
	p, xid, filters, streams := responseWaitProcessor(t, 2)
	at := time.Now().UTC().Add(-time.Hour)
	root := responseWaitLeg("response-wait-root", 0, at)
	p.processLIPacketWithProvenance(root, filters, nil)
	var selected uint64
	for _, stream := range streams {
		product := responseWaitProduct(t, stream)
		if selected == 0 {
			selected = product.Header.CorrelationID
		}
		require.Equal(t, selected, product.Header.CorrelationID)
	}
	invite := responseWaitLeg("response-wait-child", 1, at.Add(time.Millisecond))
	trying := responseWaitTrying(invite)
	wantTrying := append([]byte(nil), trying.VoIPData.RawSIP...)
	media := correlationIntegrationRTP(invite.VoIPData.CallID, 1, at.Add(2*time.Millisecond))
	wantMedia := append([]byte(nil), media.RawData...)
	before := p.getLIEncodingStats()
	p.processLIPacketWithProvenance(trying, filters, nil)
	p.processLIPacketWithProvenance(media, nil, filters)
	require.Equal(t, before, p.getLIEncodingStats(), "undecided response and associated X3 must not encode")
	require.Equal(t, 2, p.liStorage.correlation.Stats().PendingPackets)
	// Inputs are caller-owned and may change after asynchronous submission.
	trying.VoIPData.RawSIP[0], media.RawData[len(media.RawData)-1] = 'X', 99
	p.processLIPacketWithProvenance(invite, filters, nil)
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	awaitCorrelationBarrier(t, responseWaitBarrier(t, p, xid, invite, task.ActivationGeneration), "request-backed response FIFO did not drain")
	third := responseWaitLeg("response-wait-third", 2, at.Add(3*time.Millisecond))
	p.processLIPacketWithProvenance(third, filters, nil)
	liReorderBuffers.Range(func(_, value any) bool {
		value.(*delivery.ReorderBuffer).Stop()
		value.(*delivery.ReorderBuffer).Wait()
		return true
	})
	var firstDestination map[string][]byte
	for destination, stream := range streams {
		products := map[string][]byte{}
		x2Sequences := map[string]uint32{}
		for range 4 {
			product := responseWaitProduct(t, stream)
			require.Equal(t, xid, product.Header.XID)
			require.Equal(t, selected, product.Header.CorrelationID)
			key := fmt.Sprintf("%d/%s", product.Header.Type, product.Payload)
			require.NotContains(t, products, key, "each retained input reaches each destination once")
			encoded, err := product.MarshalBinary()
			require.NoError(t, err)
			products[key] = encoded
			sequence := binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value)
			if product.Header.Type == x2x3.PDUTypeX3 {
				require.Equal(t, wantMedia, product.Payload)
				require.Zero(t, sequence)
			} else {
				x2Sequences[string(product.Payload)] = sequence
			}
		}
		require.Len(t, x2Sequences, 3)
		require.EqualValues(t, 1, x2Sequences[string(wantTrying)], "response retains admission order before its late request")
		require.EqualValues(t, 2, x2Sequences[string(invite.VoIPData.RawSIP)])
		require.EqualValues(t, 3, x2Sequences[string(third.VoIPData.RawSIP)])
		if destination == 0 {
			firstDestination = products
		} else {
			require.Equal(t, firstDestination, products, "fan-out reuses immutable selected-context bytes")
		}
	}
	require.EqualValues(t, 1, p.liStorage.correlation.Stats().ResponseWait["request"])
	require.EqualValues(t, 2, p.liStorage.correlation.Stats().Adopted["R1"])
}

func TestProcessorCallCorrelationResponseWaitRevalidatesTaskAndMediaLifetime(t *testing.T) {
	for _, scenario := range []string{"task deactivation", "media lifetime replacement"} {
		t.Run(scenario, func(t *testing.T) {
			p, xid, filters, streams := responseWaitProcessor(t, 1)
			at := time.Now().UTC()
			invite := responseWaitLeg("response-wait-invalidated", 0, at)
			task, err := p.liManager.GetTaskDetails(xid)
			require.NoError(t, err)
			p.processLIPacketWithProvenance(responseWaitTrying(invite), filters, nil)
			p.processLIPacketWithProvenance(correlationIntegrationRTP(invite.VoIPData.CallID, 1, at), nil, filters)
			require.Equal(t, 2, p.liStorage.correlation.Stats().PendingPackets)
			before := p.getLIEncodingStats()
			if scenario == "task deactivation" {
				require.NoError(t, p.liManager.DeactivateTask(xid))
			} else {
				require.True(t, p.callLifecycle.Finalize(invite.VoIPData.CallID, CallFinalizationProtocolComplete).Finalized)
				replacement, err := p.callLifecycle.RestartInvite(invite.VoIPData.CallID)
				require.NoError(t, err)
				replacement.Release()
			}
			// Supply request evidence directly so even a now-revoked task can
			// release its wait; actual delivery still uses the owned old snapshot.
			awaitCorrelationBarrier(t, responseWaitBarrier(t, p, xid, invite, task.ActivationGeneration), "invalidated response wait did not release")
			after := p.getLIEncodingStats()
			require.Equal(t, before.X3Encoded, after.X3Encoded, "held media must revalidate its task and original call lifetime")
			if scenario == "task deactivation" {
				require.Equal(t, before, after)
			} else {
				require.Equal(t, before.X2Encoded+1, after.X2Encoded, "authorized signaling survives media finalization")
				require.Equal(t, before.X3FinalizedSuppressed+1, after.X3FinalizedSuppressed, "stale buffered media has exactly one lifecycle rejection owner")
				require.Equal(t, x2x3.PDUTypeX2, responseWaitProduct(t, streams[0]).Header.Type)
			}
		})
	}
}

func TestProcessorCallCorrelationResponseWaitShutdownDiscards(t *testing.T) {
	p, _, filters, _ := responseWaitProcessor(t, 1)
	invite := responseWaitLeg("response-wait-shutdown", 0, time.Now())
	p.processLIPacketWithProvenance(responseWaitTrying(invite), filters, nil)
	p.processLIPacketWithProvenance(correlationIntegrationRTP(invite.VoIPData.CallID, 1, invite.Timestamp), nil, filters)
	require.Equal(t, 2, p.liStorage.correlation.Stats().PendingPackets)
	before := p.getLIEncodingStats()
	correlator := p.liStorage.correlation
	require.NoError(t, p.Shutdown())
	require.Zero(t, correlator.Stats().PendingPackets)
	require.Zero(t, correlator.Stats().PendingDialogs)
	require.EqualValues(t, 2, correlator.Stats().ResponseWait["cancelled_packets"]+correlator.Stats().ResponseWait["shutdown_packets"])
	require.Equal(t, before, p.getLIEncodingStats(), "shutdown cannot publish undecided snapshots")
}

func TestProcessorCallCorrelationResponseSnapshotIncarnationSuppression(t *testing.T) {
	p := &Processor{ctx: context.Background(), callLifecycle: NewCallLifecycleRegistry(CallLifecycleConfig{}), liStorage: &liStoragePreparation{}}
	packet := correlationIntegrationRTP("response-incarnation-mismatch", 0, time.Now())
	task := &li.InterceptTask{XID: uuid.New(), ActivationGeneration: 1}
	snapshot, ok := p.snapshotLICorrelationPacket(packet, []*li.InterceptTask{task})
	require.True(t, ok)
	// A restored/replaced lifetime may have the same numeric generation but
	// must never inherit the old snapshot's distinct incarnation.
	snapshot.incarnation = uuid.New()
	before := p.getLIEncodingStats()
	p.deliverLICorrelationSnapshot(snapshot, li.CallCorrelationDecision{}, func(*li.InterceptTask, *types.PacketDisplay, *li.CallCorrelationDecision) {
		t.Fatal("stale incarnation reached encoding")
	})
	expected := before
	expected.X3FinalizedSuppressed++
	require.Equal(t, expected, p.getLIEncodingStats())
	require.True(t, p.callLifecycle.Finalize(packet.VoIPData.CallID, CallFinalizationProtocolComplete).Finalized, "rejected snapshot must release its temporary lifecycle admission")
}

func TestProcessorCallCorrelationResponseWaitJournalAdmissionAndReplay(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	f.config.LICallCorrelation.AddressChaining = true
	f.config.LICallCorrelation.ResponseWait = true
	f.config.LICallCorrelation.ResponseWaitWindow = time.Hour
	f.config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	filters := []string{"li-" + f.xid.String() + "-0"}
	at := time.Now().UTC().Add(-time.Hour)
	root := correlationIntegrationSIP("response-journal-root", f.target, at)
	invite := correlationIntegrationSIP("response-journal-child", f.target, at.Add(time.Millisecond))
	invite.SrcIP, invite.DstIP = root.DstIP, "192.0.2.3"
	p.processLIPacketWithProvenance(root, filters, nil)
	selected := p.liStorage.correlation.Resolve(root, nil).CorrelationID
	p.processLIPacketWithProvenance(correlationIntegrationRTP(root.VoIPData.CallID, 0, at), nil, filters)
	require.Eventually(t, func() bool {
		return liDeliveryClient.FlushPersistence(context.Background()) == nil && liDeliveryClient.X3JournalStats().Persisted == 1
	}, 5*time.Second, time.Millisecond, "root media must enter real durable publication")
	p.processLIPacketWithProvenance(responseWaitTrying(invite), filters, nil)
	p.processLIPacketWithProvenance(correlationIntegrationRTP(invite.VoIPData.CallID, 1, at.Add(time.Millisecond)), nil, filters)
	require.Equal(t, 2, p.liStorage.correlation.Stats().PendingPackets)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 1, liDeliveryClient.X3JournalStats().Persisted, "undecided media cannot reach the journal")
	p.processLIPacketWithProvenance(invite, filters, nil)
	task, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	awaitCorrelationBarrier(t, responseWaitBarrier(t, p, f.xid, invite, task.ActivationGeneration), "journal response wait did not drain")
	liReorderBuffers.Range(func(_, value any) bool {
		value.(*delivery.ReorderBuffer).Stop()
		value.(*delivery.ReorderBuffer).Wait()
		return true
	})
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 2, liDeliveryClient.X3JournalStats().Persisted)
	products := f.listenMDF(t)
	seen := map[byte]bool{}
	for range 2 {
		product := responseWaitProduct(t, products)
		require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
		require.Equal(t, selected, product.Header.CorrelationID)
		require.Equal(t, f.xid, product.Header.XID)
		marker := product.Payload[len(product.Payload)-1]
		require.False(t, seen[marker], "journal replay publishes each admitted observation once")
		seen[marker] = true
		require.EqualValues(t, marker, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
		require.Equal(t, correlationIntegrationRTP("unused", marker, at).RawData, product.Payload)
	}
	require.Equal(t, map[byte]bool{0: true, 1: true}, seen)
}

func TestProcessorCallCorrelationResponseWaitStorageOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			p, xid, filters, streams := responseWaitProcessor(t, 1)
			store := injectBlockingCorrelationStore(t, p, outcome)
			at := time.Now().UTC()
			root := responseWaitLeg("response-storage-root", 0, at)
			p.processLIPacketWithProvenance(root, filters, nil)
			selected := responseWaitProduct(t, streams[0]).Header.CorrelationID
			invite := responseWaitLeg("response-storage-child", 1, at.Add(time.Millisecond))
			p.processLIPacketWithProvenance(responseWaitTrying(invite), filters, nil)
			p.processLIPacketWithProvenance(correlationIntegrationRTP(invite.VoIPData.CallID, 1, at), nil, filters)
			p.processLIPacketWithProvenance(invite, filters, nil)
			awaitCorrelationBarrier(t, store.entered, "request-backed adoption did not enter held persistence")
			// A retained dialog still publishes while another dialog has passed
			// from response waiting into a physically blocked store reservation.
			p.processLIPacketWithProvenance(root, filters, nil)
			require.Equal(t, selected, responseWaitProduct(t, streams[0]).Header.CorrelationID)
			task, err := p.liManager.GetTaskDetails(xid)
			require.NoError(t, err)
			done := responseWaitBarrier(t, p, xid, invite, task.ActivationGeneration)
			store.unblock()
			awaitCorrelationBarrier(t, done, "storage outcome did not release waiting snapshots")
			liReorderBuffers.Range(func(_, value any) bool {
				value.(*delivery.ReorderBuffer).Stop()
				value.(*delivery.ReorderBuffer).Wait()
				return true
			})
			var chosen uint64
			for range 3 {
				product := responseWaitProduct(t, streams[0])
				if chosen == 0 {
					chosen = product.Header.CorrelationID
				}
				require.Equal(t, chosen, product.Header.CorrelationID, "response, INVITE and X3 retain one outcome-selected ID")
			}
			if outcome == securestore.NotCommitted {
				require.NotEqual(t, selected, chosen)
			} else {
				require.Equal(t, selected, chosen)
			}
		})
	}
}
