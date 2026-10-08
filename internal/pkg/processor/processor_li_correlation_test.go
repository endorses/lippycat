//go:build (processor || tap || all) && li && linux

package processor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func correlationIntegrationSIP(callID, from string, timestamp time.Time) *types.PacketDisplay {
	raw := fmt.Sprintf("INVITE %s SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-%s\r\nFrom: <%s>;tag=caller\r\nTo: <%s>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\nX-Test-Session: shared;complete=value\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nsecret", dirRemoteURI, callID, from, dirRemoteURI, callID)
	return &types.PacketDisplay{
		SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "5060", DstPort: "5060",
		Protocol: "SIP", Timestamp: timestamp, RawData: []byte(raw),
		VoIPData: &types.VoIPMetadata{RawSIP: []byte(raw), CallID: callID, Method: "INVITE", CSeqMethod: "INVITE", CSeqNumber: 1, ViaBranch: "z9hG4bK-" + callID, From: "<" + from + ">;tag=caller", FromTag: "caller", To: "<" + dirRemoteURI + ">"},
	}
}

func correlationIntegrationRTP(callID string, marker byte, timestamp time.Time) *types.PacketDisplay {
	packet := dirRTPPacket(uint32(42+marker), "192.0.2.1", "20000", "192.0.2.2", "30000")
	packet.Timestamp, packet.VoIPData.CallID = timestamp, callID
	packet.RawData[len(packet.RawData)-1] = marker
	return packet
}

func correlationMDF(t *testing.T) (int, <-chan *x2x3.PDU) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port, (&persistentProcessorFixture{address: address}).listenMDF(t)
}

func correlationProductKey(product *x2x3.PDU) string {
	return fmt.Sprintf("%s/%d/%x", product.Header.XID, product.Header.Type, product.Payload)
}

func correlationNormalizedProduct(t *testing.T, product *x2x3.PDU) []byte {
	t.Helper()
	normalized := *product
	normalized.Header.CorrelationID = 0
	normalized.Attributes = nil
	for _, attribute := range product.Attributes {
		if attribute.Type == x2x3.AttrSequenceNumber {
			attribute.Value = make([]byte, len(attribute.Value))
		}
		normalized.Attributes = append(normalized.Attributes, attribute)
	}
	raw, err := normalized.MarshalBinary()
	require.NoError(t, err)
	return raw
}

type correlationIntegrationResult struct {
	products [2]map[string]*x2x3.PDU
	stats    li.CallCorrelationStats
}

func runCorrelationDeliveryInvariant(t *testing.T, enabled bool, deliveryType li.DeliveryType) correlationIntegrationResult {
	t.Helper()
	var result correlationIntegrationResult
	var ports [2]int
	var products [2]<-chan *x2x3.PDU
	for index := range ports {
		ports[index], products[index] = correlationMDF(t)
		result.products[index] = make(map[string]*x2x3.PDU)
	}
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-delivery-invariant", "localhost:0", 1
	if enabled {
		config.LICallCorrelation = li.DefaultCallCorrelationConfig()
		config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
		// Exercise matching immediately after the configured startup blind period,
		// without changing the correlator's production clock or adding sleeps.
		config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	}
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	if enabled {
		require.NotNil(t, p.liStorage.correlation)
		require.False(t, p.liStorage.correlation.Stats().Blind)
	} else {
		require.Nil(t, p.liStorage.correlation, "all-disabled path allocates no correlator")
	}
	var dids []uuid.UUID
	for index, port := range ports {
		did := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("correlation-destination-%d", index)))
		dids = append(dids, did)
		require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true}))
	}
	var filters []string
	for index := range 2 {
		xid := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("correlation-task-%d", index)))
		require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: dids, DeliveryType: deliveryType}))
		filters = append(filters, "li-"+xid.String()+"-0")
	}
	timestamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for index, callID := range []string{"correlation-leg-a", "correlation-leg-b"} {
		p.processLIPacketWithProvenance(correlationIntegrationSIP(callID, dirTargetURI, timestamp.Add(time.Duration(index)*time.Millisecond)), filters, nil)
	}
	for index, callID := range []string{"correlation-leg-a", "correlation-leg-b"} {
		p.processLIPacketWithProvenance(correlationIntegrationRTP(callID, byte(index), timestamp.Add(time.Duration(2+index)*time.Millisecond)), nil, filters)
	}
	liReorderBuffers.Range(func(_, value any) bool {
		buffer := value.(*delivery.ReorderBuffer)
		buffer.Stop()
		buffer.Wait()
		return true
	})
	count := 4 // two independently admitted tasks, each with two legs
	if deliveryType == li.DeliveryX2andX3 {
		count *= 2
	}
	for index, stream := range products {
		for range count {
			select {
			case product := <-stream:
				key := correlationProductKey(product)
				require.NotContains(t, result.products[index], key, "one product per admitted task, destination and input packet")
				result.products[index][key] = product
			case <-time.After(5 * time.Second):
				t.Fatalf("authorized product did not reach TLS MDF: mode=%s correlation=%t encoders=%+v delivery=%+v", deliveryType, enabled, p.getLIEncodingStats(), liDeliveryClient.Stats())
			}
		}
	}
	before := p.getLIEncodingStats()
	p.processLIPacketWithProvenance(correlationIntegrationSIP("unauthorized-leg", dirTargetURI, timestamp), []string{"unknown-filter"}, nil)
	require.Equal(t, before, p.getLIEncodingStats(), "correlation cannot authorize an unmatched packet")
	if enabled {
		result.stats = p.liStorage.correlation.Stats()
	}
	require.NoError(t, p.Shutdown())
	return result
}

func TestProcessorCallCorrelationActualDeliveryInvariant(t *testing.T) {
	for _, mode := range []li.DeliveryType{li.DeliveryX2Only, li.DeliveryX3Only, li.DeliveryX2andX3} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			baseline := runCorrelationDeliveryInvariant(t, false, mode)
			grouped := runCorrelationDeliveryInvariant(t, true, mode)
			require.Equal(t, 2, grouped.stats.Records)
			require.EqualValues(t, 1, grouped.stats.Adopted["H"], "adoption is counted once across task and destination fan-out: %+v", grouped.stats)
			var standalone uint64
			for _, count := range grouped.stats.Standalone {
				standalone += count
			}
			require.EqualValues(t, 1, standalone, "first leg publication is counted once")
			var selected uint64
			baselineIDs := make(map[uint64]bool)
			for destination, expected := range baseline.products {
				require.Len(t, grouped.products[destination], len(expected))
				sequences := make(map[string][]uint32)
				for key, original := range expected {
					actual, found := grouped.products[destination][key]
					require.True(t, found, "same authorized task/destination/payload products")
					require.Equal(t, correlationNormalizedProduct(t, original), correlationNormalizedProduct(t, actual), "only Correlation ID and dependent Sequence Number may change")
					baselineIDs[original.Header.CorrelationID] = true
					if selected == 0 {
						selected = actual.Header.CorrelationID
					}
					require.Equal(t, selected, actual.Header.CorrelationID, "both legs use the packet-scoped group ID on X2 and X3")
					sequence := binary.BigEndian.Uint32(x2x3.FindAttribute(actual.Attributes, x2x3.AttrSequenceNumber).Value)
					originalSequence := binary.BigEndian.Uint32(x2x3.FindAttribute(original.Attributes, x2x3.AttrSequenceNumber).Value)
					require.Zero(t, originalSequence, "each disabled leg starts its own sequence context")
					context := fmt.Sprintf("%s/%d", actual.Header.XID, actual.Header.Type)
					sequences[context] = append(sequences[context], sequence)
				}
				for _, assigned := range sequences {
					require.ElementsMatch(t, []uint32{0, 1}, assigned, "group sequence scope preserves independent XIDs and X2/X3 interfaces")
				}
			}
			require.Len(t, baselineIDs, 2, "disabled path retains per-leg IDs")
		})
	}
}

func TestProcessorCallCorrelationPublicationAtX3JournalAdmission(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	f.config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	f.config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	filter := []string{"li-" + f.xid.String() + "-0"}
	timestamp := time.Now().UTC()
	for index, callID := range []string{"journal-leg-a", "journal-leg-b"} {
		p.processLIPacketWithProvenance(correlationIntegrationSIP(callID, f.target, timestamp.Add(time.Duration(index)*time.Millisecond)), filter, nil)
	}
	stats := p.liStorage.correlation.Stats()
	require.Empty(t, stats.Adopted, "X3-only signaling supplies evidence but publishes no product")
	require.Empty(t, stats.Standalone)
	for index, callID := range []string{"journal-leg-a", "journal-leg-b"} {
		p.processLIPacketWithProvenance(correlationIntegrationRTP(callID, byte(index), timestamp.Add(time.Duration(2+index)*time.Millisecond)), nil, filter)
	}
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 2, liDeliveryClient.X3JournalStats().Persisted, "MDF is offline; publication means accepted durable product, not successful transmission")
	stats = p.liStorage.correlation.Stats()
	require.EqualValues(t, 1, stats.Adopted["H"])
	var standalone uint64
	for _, count := range stats.Standalone {
		standalone += count
	}
	require.EqualValues(t, 1, standalone)
	incarnation := p.liManager.StateIncarnation()
	require.NoError(t, p.Shutdown())
	journal, err := delivery.OpenJournal(delivery.JournalConfig{Interface: delivery.PDUTypeX3, Dir: f.config.LIDeliveryX3SpoolDir,
		KeyFile: f.config.LIDeliveryX3SpoolKeyFile, KeyID: f.config.LIDeliveryX3SpoolKeyID,
		MaxBytes: f.config.LIDeliveryX3SpoolMaxBytes, MaxPending: 10000, MaxRecords: 2000000,
		StateIncarnation: incarnation, MaxAge: f.config.LIDeliveryX3MaxAge, PreserveSequences: true})
	require.NoError(t, err)
	var selected uint64
	count := 0
	require.NoError(t, journal.VisitHeld(func(record delivery.JournalRecord) error {
		product, err := x2x3.ReadPDU(bytes.NewReader(record.Data))
		if err != nil {
			return err
		}
		if count == 0 {
			selected = product.Header.CorrelationID
		}
		require.Equal(t, selected, product.Header.CorrelationID)
		require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
		require.Equal(t, f.xid, product.Header.XID)
		count++
		return nil
	}))
	require.Equal(t, 2, count)
	require.NoError(t, journal.Close())
}

func TestProcessorCallCorrelationRejectsIneligibleX3Publication(t *testing.T) {
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-ineligible-x3", "localhost:0", 1
	config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })

	xid, x2did, x3did := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: x2did, Address: "127.0.0.1", Port: 1, ProtocolType: "X2Only", X2Enabled: true}))
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: x3did, Address: "127.0.0.1", Port: 2, ProtocolType: "X3Only", X3Enabled: true}))
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{x2did, x3did}, DeliveryType: li.DeliveryX3Only}))

	// The eligible destination rejects reorder admission. The other destination
	// remains available, but cannot expose any X3 product: its capability is X2.
	rejecting := delivery.NewCallAwareReorderBuffer(func(delivery.ReorderEntry) {
		t.Error("stopped reorder buffer delivered a product")
	}, time.Millisecond)
	rejecting.Stop()
	rejecting.Wait()
	liReorderBuffers.Store(fmt.Sprintf("%s-%s", xid, x3did), rejecting)
	filters := []string{"li-" + xid.String() + "-0"}
	timestamp := time.Now().UTC()
	p.processLIPacketWithProvenance(correlationIntegrationSIP("ineligible-x3-leg", dirTargetURI, timestamp), filters, nil)
	p.processLIPacketWithProvenance(correlationIntegrationRTP("ineligible-x3-leg", 0, timestamp.Add(time.Millisecond)), nil, filters)

	stats := p.liStorage.correlation.Stats()
	require.Equal(t, 1, stats.Records, "encoding can retain a provisional decision")
	require.Empty(t, stats.Adopted)
	require.Empty(t, stats.Standalone, "neither destination admitted a deliverable X3 product")
	_, exists := liReorderBuffers.Load(fmt.Sprintf("%s-%s", xid, x2did))
	require.False(t, exists, "X2-only destinations must not create X3 reorder buffers")
}

func TestProcessorCallCorrelationInitialZeroCSeqThroughBatchDelivery(t *testing.T) {
	port, products := correlationMDF(t)
	config := storageKeyStartupConfig(t)
	config.ProcessorID, config.ListenAddr, config.MaxHunters = "correlation-zero-cseq", "localhost:0", 1
	config.LICallCorrelation = li.DefaultCallCorrelationConfig()
	config.LICallCorrelation.SessionHeaders = []string{"X-Test-Session"}
	config.LICallCorrelation.DecisionHorizon = time.Nanosecond
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true}))
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: []uuid.UUID{did}, DeliveryType: li.DeliveryX2andX3}))
	filters := []string{"li-" + xid.String() + "-0"}
	var selected uint64
	for index, callID := range []string{"zero-cseq-leg-a", "zero-cseq-leg-b"} {
		packet := correlationIntegrationSIP(callID, dirTargetURI, time.Now().UTC())
		raw := []byte(strings.Replace(string(packet.VoIPData.RawSIP), "CSeq: 1 INVITE", "CSeq: 0 INVITE", 1))
		frame := liTestSIPFrame(t, raw, false)
		captured := &data.CapturedPacket{
			TimestampNs: packet.Timestamp.UnixNano(), Data: frame,
			CaptureLength: uint32(len(frame)), OriginalLength: uint32(len(frame)), LinkType: uint32(layers.LinkTypeEthernet),
			MatchedFilterIds: filters, DirectMatchedFilterIds: filters,
			Metadata: &data.PacketMetadata{SrcIp: packet.SrcIP, DstIp: packet.DstIP, SrcPort: 5060, DstPort: 5060, Protocol: "SIP",
				Sip: &data.SIPMetadata{CallId: callID, Method: "INVITE", CseqMethod: "INVITE", CseqNumber: 0,
					ViaBranch: packet.VoIPData.ViaBranch, FromTag: "caller", FromUri: dirTargetURI, ToUri: dirRemoteURI}},
		}
		p.processBatch(source.FromProtoBatch(&data.PacketBatch{HunterId: "zero-cseq-fixture", Packets: []*data.CapturedPacket{captured}}))
		select {
		case product := <-products:
			require.Equal(t, x2x3.PDUTypeX2, product.Header.Type)
			require.Equal(t, xid, product.Header.XID)
			require.Equal(t, raw, product.Payload, "decoded transport framing preserves the initial CSeq zero request")
			if index == 0 {
				selected = product.Header.CorrelationID
			}
			require.Equal(t, selected, product.Header.CorrelationID, "valid CSeq zero initial requests can establish shared session evidence")
			require.EqualValues(t, index, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
		case <-time.After(5 * time.Second):
			t.Fatal("CSeq zero initial request did not reach the TLS MDF")
		}
	}
	stats := p.liStorage.correlation.Stats()
	require.Equal(t, 2, stats.Records)
	require.EqualValues(t, 1, stats.Adopted["H"])
}
