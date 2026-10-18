//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/stretchr/testify/require"
)

func TestProcessorCaptureSourceOrderingAndFanout(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprintf("persistent-%t", persistent), func(t *testing.T) {
			p, xid, filter, products := orderedLIProcessor(t, persistent)
			liX3Encoder.SetCaptureSourceMetadata(true)
			task, err := p.liManager.GetTaskDetails(xid)
			require.NoError(t, err)
			buffer := delivery.NewBudgetedCallAwareReorderBuffer(func(entry delivery.ReorderEntry) { p.emitOrderedX3(xid, task.ActivationGeneration, entry) }, time.Hour, liReorderBudget, recordBufferedX3Discard)
			require.NotNil(t, buffer)
			buffer.SetWorkerGroup(liReorderWorkers)
			liReorderBuffers.Store(liOrderedBufferKey(xid, task.ActivationGeneration), buffer)
			timestamp := time.Now().UTC().Truncate(time.Microsecond)
			for _, input := range []struct {
				sequence uint16
				node     string
				domain   uint32
			}{{10, "hunter-a", 0}, {12, "hunter-b", 42}, {11, "hunter-a", 0}} {
				packet := orderedRTP(input.sequence, 42, input.node)
				packet.Timestamp = timestamp.Add(time.Duration(input.sequence) * time.Microsecond)
				packet.ObservationDomain, packet.ObservationDomainKnown = input.domain, true
				p.processLIPacketWithProvenance(packet, nil, []string{filter})
				// Retained work must not reread mutable packet/source storage.
				packet.NodeID, packet.Interface, packet.ObservationDomain = "changed-after-encode", "changed", 99
			}
			var copies [2][][]byte
			for destination, stream := range products {
				for index, sequence := range []uint16{10, 11, 12} {
					product := receiveProduct(t, stream)
					require.Equal(t, sequence, binary.BigEndian.Uint16(product.Payload[2:]))
					require.EqualValues(t, index, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
					require.Equal(t, p.config.ProcessorID, string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
					source, available, err := x2x3.DecodeCaptureSource(product)
					require.NoError(t, err)
					require.True(t, available)
					expectedNode, expectedDomain := "hunter-a", uint32(0)
					if sequence == 12 {
						expectedNode, expectedDomain = "hunter-b", 42
					}
					require.Equal(t, expectedNode, source.NodeID())
					require.Equal(t, "capture0", source.Interface())
					domain, known := source.ObservationDomain()
					require.True(t, known)
					require.Equal(t, expectedDomain, domain)
					require.Equal(t, x2x3.NewAttributeBuilder().Timestamp(timestamp.Add(time.Duration(sequence)*time.Microsecond)).Value, x2x3.FindAttribute(product.Attributes, x2x3.AttrTimestamp).Value)
					wire, err := product.MarshalBinary()
					require.NoError(t, err)
					copies[destination] = append(copies[destination], wire)
				}
			}
			require.Equal(t, copies[0], copies[1])
		})
	}
}

func TestProcessorCaptureSourceSurvivesJournalRestart(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled-%t", enabled), func(t *testing.T) {
			f := newPersistentProcessorFixture(t)
			f.config.LIDeliveryCaptureSourceMetadata = enabled
			p := f.open(t)
			require.NoError(t, p.startLIManager())
			timestamp := time.Now().UTC().Truncate(time.Microsecond)
			for index, node := range []string{"hunter-a", "hunter-b"} {
				packet := orderedRTP(uint16(index+1), 42, node)
				packet.Timestamp = timestamp.Add(time.Duration(index) * time.Microsecond)
				packet.ObservationDomainKnown = true
				filter := []string{"li-" + f.xid.String() + "-0"}
				p.processLIPacketWithProvenance(packet, nil, filter)
			}
			result := p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete)
			require.True(t, result.Finalized)
			require.NoError(t, result.Err)
			require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
			require.Equal(t, 2, liDeliveryClient.X3JournalStats().Persisted)
			incarnation := p.liManager.StateIncarnation()
			require.NoError(t, p.Shutdown())
			journal, err := delivery.OpenJournal(delivery.JournalConfig{Interface: delivery.PDUTypeX3, Dir: f.config.LIDeliveryX3SpoolDir, KeyFile: f.config.LIDeliveryX3SpoolKeyFile, KeyID: f.config.LIDeliveryX3SpoolKeyID, MaxBytes: f.config.LIDeliveryX3SpoolMaxBytes, MaxPending: 10000, MaxRecords: 2_000_000, StateIncarnation: incarnation, MaxAge: f.config.LIDeliveryX3MaxAge, PreserveSequences: true})
			require.NoError(t, err)
			var originals [][]byte
			require.NoError(t, journal.VisitHeld(func(record delivery.JournalRecord) error {
				_, available, err := x2x3.DecodeProductCaptureSource(record.Data)
				require.NoError(t, err)
				require.Equal(t, enabled, available)
				originals = append(originals, append([]byte(nil), record.Data...))
				return nil
			}))
			require.NoError(t, journal.Close())
			require.Len(t, originals, 2)
			f.config.LIDeliveryCaptureSourceMetadata = !enabled
			restarted := f.open(t)
			path, manifest := exportProcessorX3Approval(t)
			require.Len(t, manifest.Records, 2)
			products := f.listenMDF(t)
			restarted.config.LIDeliveryX3SpoolReplayManifest = path
			require.NoError(t, restarted.startLIManager())
			// Recovery uses historical product bytes even if the new-output
			// setting changes. In particular, legacy records stay unavailable.
			for index := range 2 {
				product := receiveProduct(t, products)
				wire, err := product.MarshalBinary()
				require.NoError(t, err)
				require.Equal(t, originals[index], wire)
				source, available, err := x2x3.DecodeProductCaptureSource(wire)
				require.NoError(t, err)
				require.Equal(t, enabled, available)
				if available {
					require.Equal(t, []string{"hunter-a", "hunter-b"}[index], source.NodeID())
				}
			}
		})
	}
}

func TestProcessorSIPCaptureSourceSurvivesJournalRestart(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.taskDeliveryType, f.destinationDeliveryType = "X2andX3", "X2andX3"
	f.config.LIDeliveryCaptureSourceMetadata = true
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	timestamp := time.Now().UTC().Truncate(time.Microsecond)
	for index, node := range []string{"hunter-a", "hunter-b"} {
		packet := correlationIntegrationSIP("source-sip-call", f.target, timestamp.Add(time.Duration(index)*time.Microsecond))
		packet.NodeID, packet.Interface, packet.ObservationDomainKnown = node, "eth0", true
		p.processLIPacketWithProvenance(packet, []string{"li-" + f.xid.String() + "-0"}, nil)
	}
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 2, liDeliveryClient.JournalStats().Persisted)
	incarnation := p.liManager.StateIncarnation()
	require.NoError(t, p.Shutdown())
	journal, err := delivery.OpenJournal(delivery.JournalConfig{Interface: delivery.PDUTypeX2, StateIncarnation: incarnation, Dir: f.config.LIDeliveryX2SpoolDir, KeyFile: f.config.LIDeliveryX2SpoolKeyFile, KeyID: f.config.LIDeliveryX2SpoolKeyID, MaxBytes: f.config.LIDeliveryX2SpoolMaxBytes, MaxPending: 10000, MaxRecords: int(f.config.LIDeliveryX2SpoolMaxBytes / 4096), PreserveSequences: true})
	require.NoError(t, err)
	var originals [][]byte
	require.NoError(t, journal.VisitHeld(func(record delivery.JournalRecord) error {
		source, available, err := x2x3.DecodeProductCaptureSource(record.Data)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, []string{"hunter-a", "hunter-b"}[len(originals)], source.NodeID())
		originals = append(originals, append([]byte(nil), record.Data...))
		return nil
	}))
	require.NoError(t, journal.Close())
	require.Len(t, originals, 2)
	restarted := f.open(t)
	path := newTestFilterFile(t)
	require.NoError(t, liDeliveryClient.ExportHeldJournalManifest(path))
	products := f.listenMDF(t)
	restarted.config.LIDeliveryX2SpoolReplayManifest = path
	require.NoError(t, restarted.startLIManager())
	for index := range 2 {
		product := receiveProduct(t, products)
		wire, err := product.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, originals[index], wire)
		source, available, err := x2x3.DecodeProductCaptureSource(wire)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, []string{"hunter-a", "hunter-b"}[index], source.NodeID())
		require.Equal(t, p.config.ProcessorID, string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
		require.Equal(t, uint32(index), binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
	}
}
