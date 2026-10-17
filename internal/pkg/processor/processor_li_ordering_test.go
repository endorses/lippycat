//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func orderedLIProcessor(t *testing.T, persistent bool) (*Processor, uuid.UUID, string, [2]<-chan *x2x3.PDU) {
	t.Helper()
	var p *Processor
	var xid uuid.UUID
	var products [2]<-chan *x2x3.PDU
	var destinations []uuid.UUID
	if persistent {
		fixture := newPersistentProcessorFixture(t)
		products[0] = fixture.listenMDF(t)
		p = fixture.open(t)
		require.NoError(t, p.startLIManager())
		xid = fixture.xid
		destinations = append(destinations, fixture.did)
	} else {
		config := storageKeyStartupConfig(t)
		config.ProcessorID = "ordered-processor"
		config.ListenAddr = "localhost:0"
		config.MaxHunters = 1
		var err error
		p, err = newTestProcessor(t, config)
		require.NoError(t, err)
		p.ctx, p.cancel = context.WithCancel(context.Background())
		require.NoError(t, p.startLIManager())
		t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
		xid = uuid.New()
		port, stream := correlationMDF(t)
		products[0] = stream
		did := uuid.New()
		destinations = append(destinations, did)
		require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X3Enabled: true}))
		require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: xid, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: destinations, DeliveryType: li.DeliveryX3Only}))
	}
	port, stream := correlationMDF(t)
	products[1] = stream
	did := uuid.New()
	destinations = append(destinations, did)
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: port, X3Enabled: true}))
	require.NoError(t, p.liManager.ModifyTask(xid, &li.TaskModification{DestinationIDs: &destinations}))
	return p, xid, "li-" + xid.String() + "-0", products
}

func orderedRTP(sequence uint16, ssrc uint32, node string) *types.PacketDisplay {
	packet := dirRTPPacket(ssrc, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
	packet.Timestamp = time.Now().UTC()
	packet.NodeID = node
	packet.Interface = "capture0"
	packet.Transport = 17
	packet.VoIPData.SequenceNum = sequence
	packet.RawData[0] = 0x80
	packet.RawData[1] = 0
	binary.BigEndian.PutUint16(packet.RawData[2:], sequence)
	binary.BigEndian.PutUint32(packet.RawData[8:], ssrc)
	return packet
}

func receiveProduct(t *testing.T, stream <-chan *x2x3.PDU) *x2x3.PDU {
	t.Helper()
	select {
	case product := <-stream:
		return product
	case <-time.After(5 * time.Second):
		t.Fatal("authorized ordered product did not reach fixture destination")
		return nil
	}
}

func TestLISharedOrderingPrecedesSequenceForAllDestinations(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprintf("persistent-%t", persistent), func(t *testing.T) {
			p, xid, filter, products := orderedLIProcessor(t, persistent)
			task, err := p.liManager.GetTaskDetails(xid)
			require.NoError(t, err)
			// Give this deterministic fixture an explicit long reorder deadline;
			// production's bounded 60ms policy remains unchanged.
			buffer := delivery.NewBudgetedCallAwareReorderBuffer(func(entry delivery.ReorderEntry) { p.emitOrderedX3(xid, task.ActivationGeneration, entry) }, time.Hour, liReorderBudget, recordBufferedX3Discard)
			require.NotNil(t, buffer)
			buffer.SetWorkerGroup(liReorderWorkers)
			liReorderBuffers.Store(liOrderedBufferKey(xid, task.ActivationGeneration), buffer)
			for _, input := range []struct {
				sequence uint16
				ssrc     uint32
				node     string
			}{{10, 42, "hunter-a"}, {12, 42, "hunter-b"}, {20, 77, "hunter-b"}, {11, 42, "hunter-a"}} {
				packet := orderedRTP(input.sequence, input.ssrc, input.node)
				p.processLIPacketWithProvenance(packet, nil, []string{filter})
				require.Equal(t, input.node, packet.NodeID)
			}
			var encoded [2][][]byte
			for destination, stream := range products {
				for index, expected := range []uint16{10, 20, 11, 12} {
					product := receiveProduct(t, stream)
					require.Equal(t, expected, binary.BigEndian.Uint16(product.Payload[2:]))
					require.Equal(t, uint32(index), binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
					require.Equal(t, p.config.ProcessorID, string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
					data, err := product.MarshalBinary()
					require.NoError(t, err)
					encoded[destination] = append(encoded[destination], data)
				}
			}
			require.Equal(t, encoded[0], encoded[1], "all destination copies retain identical context, capture time and assigned sequence")
			admission, err := p.callLifecycle.Admit(dirCallID)
			require.NoError(t, err)
			require.Equal(t, persistent, buffer.HasAcceptedCall(dirCallID, admission.Generation(), admission.Incarnation()), "only persistent delivery retains a durable capture-drain frontier")
			admission.Release()
		})
	}
}

func dedupRTPObservation(t *testing.T, packet *types.PacketDisplay, node string) packetdedup.Observation {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Id: 123, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	udp := &layers.UDP{SrcPort: 20000, DstPort: 30000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, gopacket.Payload(packet.RawData)))
	return packetdedup.Observation{Source: node, Domain: "shared-domain", Flow: "udp/192.0.2.1:20000>192.0.2.2:30000", CapturedAt: packet.Timestamp, Packet: buffer.Bytes(), LinkType: layers.LinkTypeRaw}
}

func enableLIDedup(t *testing.T, p *Processor) {
	t.Helper()
	settings, err := (packetdedup.Settings{Enabled: true}).Normalize()
	require.NoError(t, err)
	p.config.PacketDedup = settings
	p.packetDuplicates, err = packetdedup.New(settings.Config())
	require.NoError(t, err)
}

func TestLIDedupKeepsIndependentTasksAndSameSourceRepeats(t *testing.T) {
	p, xid, filter, products := orderedLIProcessor(t, false)
	enableLIDedup(t, p)
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	second := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{XID: second, Targets: []li.TargetIdentity{dirTarget}, DestinationIDs: task.DestinationIDs, DeliveryType: li.DeliveryX3Only}))
	filters := []string{filter, "li-" + second.String() + "-0"}
	for _, node := range []string{"hunter-a", "hunter-b", "hunter-a"} {
		packet := orderedRTP(10, 42, node)
		observation := dedupRTPObservation(t, packet, node)
		p.processLIPacketWithAdmissionAndDedup(packet, nil, filters, nil, &observation)
	}
	require.EqualValues(t, 8, liDeliveryClient.Stats().X3Queued, "two tasks and two destinations each retain the first observation and same-source repeat")
	require.EqualValues(t, 2, p.packetDuplicates.Stats().Duplicates, "a copy accepted for one task cannot suppress the other task")
	for _, stream := range products {
		for range 4 {
			receiveProduct(t, stream)
		}
	}
}

func TestLIDedupAbortsRejectedFirstCopyAndAcceptsOtherSource(t *testing.T) {
	p, xid, filter, products := orderedLIProcessor(t, false)
	enableLIDedup(t, p)
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	key := liOrderedBufferKey(xid, task.ActivationGeneration)
	rejecting := delivery.NewCallAwareReorderBuffer(func(delivery.ReorderEntry) { t.Error("stopped ordering buffer emitted product") }, time.Hour)
	rejecting.Stop()
	liReorderBuffers.Store(key, rejecting)
	packet := orderedRTP(10, 42, "hunter-a")
	observation := dedupRTPObservation(t, packet, "hunter-a")
	p.processLIPacketWithAdmissionAndDedup(packet, nil, []string{filter}, nil, &observation)
	require.Zero(t, liDeliveryClient.Stats().X3Queued)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Aborts)
	liReorderBuffers.Delete(key)
	packet = orderedRTP(10, 42, "hunter-b")
	observation = dedupRTPObservation(t, packet, "hunter-b")
	p.processLIPacketWithAdmissionAndDedup(packet, nil, []string{filter}, nil, &observation)
	require.EqualValues(t, 2, liDeliveryClient.Stats().X3Queued)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Commits)
	for _, stream := range products {
		receiveProduct(t, stream)
	}
}

func TestLIDedupConcurrentCopiesWaitForActualAcceptance(t *testing.T) {
	p, xid, filter, products := orderedLIProcessor(t, false)
	enableLIDedup(t, p)
	task, err := p.liManager.GetTaskDetails(xid)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	buffer := delivery.NewBudgetedCallAwareReorderBuffer(func(entry delivery.ReorderEntry) {
		close(entered)
		<-release
		p.emitOrderedX3(xid, task.ActivationGeneration, entry)
	}, time.Hour, liReorderBudget, recordBufferedX3Discard)
	require.NotNil(t, buffer)
	buffer.SetWorkerGroup(liReorderWorkers)
	liReorderBuffers.Store(liOrderedBufferKey(xid, task.ActivationGeneration), buffer)
	first, second := orderedRTP(10, 42, "hunter-a"), orderedRTP(10, 42, "hunter-b")
	firstObservation, secondObservation := dedupRTPObservation(t, first, "hunter-a"), dedupRTPObservation(t, second, "hunter-b")
	done := make(chan struct{}, 2)
	go func() {
		p.processLIPacketWithAdmissionAndDedup(first, nil, []string{filter}, nil, &firstObservation)
		done <- struct{}{}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first LI observation did not reach ordered admission")
	}
	go func() {
		p.processLIPacketWithAdmissionAndDedup(second, nil, []string{filter}, nil, &secondObservation)
		done <- struct{}{}
	}()
	require.Eventually(t, func() bool { return p.packetDuplicates.Stats().InFlight > 0 }, time.Second, time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("LI duplicate claim owner did not settle")
		}
	}
	require.EqualValues(t, 2, liDeliveryClient.Stats().X3Queued)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Commits)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Duplicates)
	for _, stream := range products {
		receiveProduct(t, stream)
	}
}
