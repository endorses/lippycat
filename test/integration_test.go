package test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestIntegration_HunterProcessorBasicFlow tests basic packet flow from hunter to processor
func TestIntegration_HunterProcessorBasicFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50051"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err, "Failed to start processor")
	defer proc.Shutdown()

	// Wait for processor to be ready
	time.Sleep(500 * time.Millisecond)

	// Connect to processor as a hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to connect to processor")
	defer conn.Close()

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter
	regResp, err := mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId: "test-hunter-basic",
		Hostname: "test-host",
		Interfaces: []string{"mock0"},
		Version: "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:      []string{"bpf"},
			MaxBufferSize:    8192,
			GpuAcceleration:  false,
			AfXdp:           false,
		},
	})
	require.NoError(t, err, "Failed to register hunter")
	assert.True(t, regResp.Accepted, "Hunter registration rejected")

	// Stream packets
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(t, err, "Failed to create stream")

	// Send packet batch
	batch := &data.PacketBatch{
		HunterId:    "test-hunter-basic",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(10)),
		Stats: &data.BatchStats{
			TotalCaptured:   10,
			FilteredMatched: 0,
			Dropped:         0,
		},
	}

	err = stream.Send(batch)
	require.NoError(t, err, "Failed to send packet batch")

	// Receive acknowledgment
	resp, err := stream.Recv()
	require.NoError(t, err, "Failed to receive stream control")
	assert.NotNil(t, resp, "Stream control response is nil")

	// Verify processor received packets
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(10), "Processor should have received packets")

	t.Logf("✓ Basic flow test: Sent 10 packets, processor received %d", stats.TotalPacketsReceived)
}

// TestIntegration_HunterCrashRecovery tests hunter crash during packet send
func TestIntegration_HunterCrashRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50099"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err, "Failed to start processor")
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Connect first hunter
	conn1, stream1, err := connectHunter(ctx, processorAddr, "hunter-crash-1")
	require.NoError(t, err, "Failed to connect hunter 1")

	// Send some packets
	batch1 := createTestBatch("hunter-crash-1", 1, 5)
	err = stream1.Send(batch1)
	require.NoError(t, err, "Failed to send from hunter 1")

	// Simulate crash by closing connection abruptly
	conn1.Close()
	t.Log("✓ Simulated hunter crash")

	// Wait a bit for processor to detect disconnect
	time.Sleep(1 * time.Second)

	// Reconnect same hunter (recovery)
	conn2, stream2, err := connectHunter(ctx, processorAddr, "hunter-crash-1")
	require.NoError(t, err, "Failed to reconnect hunter after crash")
	defer conn2.Close()

	// Send more packets
	batch2 := createTestBatch("hunter-crash-1", 2, 5)
	err = stream2.Send(batch2)
	require.NoError(t, err, "Failed to send after recovery")

	// Wait for ACK from processor
	_, err = stream2.Recv()
	require.NoError(t, err, "Failed to receive ACK from processor")

	// Wait a bit for stats to be updated
	time.Sleep(100 * time.Millisecond)

	// Verify processor handled reconnection gracefully
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(5), "Processor should have received packets after recovery")

	t.Logf("✓ Hunter crash recovery test: Processor received %d packets across reconnection", stats.TotalPacketsReceived)
}

// TestIntegration_ProcessorRestartWithConnectedHunters tests processor restart scenario
func TestIntegration_ProcessorRestartWithConnectedHunters(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	processorAddr := "127.0.0.1:50053"

	// Start processor
	proc1Ctx, proc1Cancel := context.WithCancel(ctx)
	defer proc1Cancel()
	proc1, err := startTestProcessor(proc1Ctx, processorAddr)
	require.NoError(t, err, "Failed to start processor")
	defer proc1.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Connect multiple hunters
	conn1, stream1, err := connectHunter(ctx, processorAddr, "hunter-restart-1")
	require.NoError(t, err, "Failed to connect hunter 1")
	defer conn1.Close()

	conn2, stream2, err := connectHunter(ctx, processorAddr, "hunter-restart-2")
	require.NoError(t, err, "Failed to connect hunter 2")
	defer conn2.Close()

	// Send packets from both hunters
	batch1 := createTestBatch("hunter-restart-1", 1, 3)
	err = stream1.Send(batch1)
	require.NoError(t, err, "Failed to send from hunter 1")

	batch2 := createTestBatch("hunter-restart-2", 1, 3)
	err = stream2.Send(batch2)
	require.NoError(t, err, "Failed to send from hunter 2")

	stats1 := proc1.GetStats()
	t.Logf("Processor 1 stats before restart: %d packets", stats1.TotalPacketsReceived)

	// Shutdown processor
	proc1Cancel()
	t.Log("✓ Processor stopped")

	time.Sleep(1 * time.Second)

	// Restart processor on same address
	proc2Ctx, proc2Cancel := context.WithCancel(ctx)
	defer proc2Cancel()
	proc2, err := startTestProcessor(proc2Ctx, processorAddr)
	require.NoError(t, err, "Failed to restart processor")
	defer proc2.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Hunters should detect disconnect and reconnect
	// For this test, we'll manually reconnect
	conn3, stream3, err := connectHunter(ctx, processorAddr, "hunter-restart-1")
	require.NoError(t, err, "Failed to reconnect hunter 1 after processor restart")
	defer conn3.Close()

	conn4, stream4, err := connectHunter(ctx, processorAddr, "hunter-restart-2")
	require.NoError(t, err, "Failed to reconnect hunter 2 after processor restart")
	defer conn4.Close()

	// Send packets to new processor instance
	batch3 := createTestBatch("hunter-restart-1", 2, 3)
	err = stream3.Send(batch3)
	require.NoError(t, err, "Failed to send to new processor from hunter 1")

	batch4 := createTestBatch("hunter-restart-2", 2, 3)
	err = stream4.Send(batch4)
	require.NoError(t, err, "Failed to send to new processor from hunter 2")

	// Wait for ACKs from processor
	_, err = stream3.Recv()
	require.NoError(t, err, "Failed to receive ACK from processor")
	_, err = stream4.Recv()
	require.NoError(t, err, "Failed to receive ACK from processor")

	// Wait a bit for stats to be updated
	time.Sleep(100 * time.Millisecond)

	// Verify new processor received packets
	stats2 := proc2.GetStats()
	assert.GreaterOrEqual(t, stats2.TotalPacketsReceived, uint64(6), "New processor should have received packets")

	t.Logf("✓ Processor restart test: New processor received %d packets", stats2.TotalPacketsReceived)
}

// TestIntegration_NetworkPartition tests network partition between hunter and processor
func TestIntegration_NetworkPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr := "127.0.0.1:50054"

	// Start processor
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	defer proc.Shutdown()
	require.NoError(t, err, "Failed to start processor")

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, stream, err := connectHunter(ctx, processorAddr, "hunter-partition")
	require.NoError(t, err, "Failed to connect hunter")

	// Send initial packets
	batch1 := createTestBatch("hunter-partition", 1, 5)
	err = stream.Send(batch1)
	require.NoError(t, err, "Failed to send initial batch")

	// Simulate network partition by closing connection
	conn.Close()
	t.Log("✓ Simulated network partition")

	// Wait for processor to detect disconnection
	time.Sleep(2 * time.Second)

	// Reconnect after partition heals
	conn2, stream2, err := connectHunter(ctx, processorAddr, "hunter-partition")
	require.NoError(t, err, "Failed to reconnect after partition")
	defer conn2.Close()

	// Send packets after recovery
	batch2 := createTestBatch("hunter-partition", 2, 5)
	err = stream2.Send(batch2)
	require.NoError(t, err, "Failed to send after partition recovery")

	// Wait for ACK from processor
	_, err = stream2.Recv()
	require.NoError(t, err, "Failed to receive ACK from processor")

	// Wait a bit for stats to be updated
	time.Sleep(100 * time.Millisecond)

	// Verify processor recovered
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(5), "Processor should handle partition recovery")

	t.Logf("✓ Network partition test: Processor received %d packets", stats.TotalPacketsReceived)
}

// TestIntegration_HighVolume tests sustained high packet rates
func TestIntegration_HighVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	processorAddr := "127.0.0.1:50055"

	// Start processor
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	defer proc.Shutdown()
	require.NoError(t, err, "Failed to start processor")

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, stream, err := connectHunter(ctx, processorAddr, "hunter-highvol")
	require.NoError(t, err, "Failed to connect hunter")
	defer conn.Close()

	// Send 10,000 packets at high rate
	targetPackets := 10000
	batchSize := 100
	numBatches := targetPackets / batchSize

	start := time.Now()
	var totalSent uint64

	for i := 0; i < numBatches; i++ {
		batch := createTestBatch("hunter-highvol", uint64(i+1), batchSize)
		err := stream.Send(batch)
		require.NoError(t, err, "Failed to send high volume batch %d", i)

		atomic.AddUint64(&totalSent, uint64(batchSize))

		// Small delay to simulate realistic pacing (targeting ~10k packets/sec)
		time.Sleep(10 * time.Millisecond)
	}

	elapsed := time.Since(start)
	rate := float64(totalSent) / elapsed.Seconds()

	t.Logf("✓ High volume test: Sent %d packets in %.2fs (%.0f packets/sec)", totalSent, elapsed.Seconds(), rate)

	// Verify processor handled high volume
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(targetPackets*80/100),
		"Processor should receive at least 80%% of packets")

	// Check for reasonable packet rate
	assert.GreaterOrEqual(t, rate, 5000.0, "Should achieve at least 5k packets/sec")

	t.Logf("  Processor received: %d packets (%.1f%%)", stats.TotalPacketsReceived,
		float64(stats.TotalPacketsReceived)/float64(totalSent)*100)
}

// TestIntegration_MultipleHuntersSimultaneous tests multiple hunters sending simultaneously
func TestIntegration_MultipleHuntersSimultaneous(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	processorAddr := "127.0.0.1:50056"

	// Start processor
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	defer proc.Shutdown()
	require.NoError(t, err, "Failed to start processor")

	time.Sleep(500 * time.Millisecond)

	// Connect 5 hunters
	numHunters := 5
	var wg sync.WaitGroup
	var totalPackets atomic.Uint64

	for i := 0; i < numHunters; i++ {
		wg.Add(1)
		hunterID := fmt.Sprintf("hunter-multi-%d", i)

		go func(id string, index int) {
			defer wg.Done()

			conn, stream, err := connectHunter(ctx, processorAddr, id)
			if err != nil {
				t.Errorf("Hunter %s failed to connect: %v", id, err)
				return
			}
			defer conn.Close()

			// Each hunter sends 1000 packets
			for j := 0; j < 20; j++ {
				batch := createTestBatch(id, uint64(j+1), 50)
				err := stream.Send(batch)
				if err != nil {
					t.Errorf("Hunter %s failed to send batch %d: %v", id, j, err)
					return
				}
				totalPackets.Add(50)
				time.Sleep(10 * time.Millisecond)
			}
		}(hunterID, i)
	}

	wg.Wait()

	// Verify processor handled all hunters
	stats := proc.GetStats()
	expectedMin := totalPackets.Load() * 80 / 100
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, expectedMin,
		"Processor should receive at least 80%% of packets from all hunters")

	t.Logf("✓ Multiple hunters test: %d hunters sent %d packets, processor received %d",
		numHunters, totalPackets.Load(), stats.TotalPacketsReceived)
}

// TestIntegration_JumboFrames tests large packet payloads
func TestIntegration_JumboFrames(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	processorAddr := "127.0.0.1:50057"

	// Start processor with increased message size
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	defer proc.Shutdown()
	require.NoError(t, err, "Failed to start processor")

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, stream, err := connectHunter(ctx, processorAddr, "hunter-jumbo")
	require.NoError(t, err, "Failed to connect hunter")
	defer conn.Close()

	// Create jumbo frame packets (9000 bytes)
	jumboPackets := createJumboPackets(10, 9000)
	batch := &data.PacketBatch{
		HunterId:    "hunter-jumbo",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     jumboPackets,
		Stats: &data.BatchStats{
			TotalCaptured:   uint64(len(jumboPackets)),
			FilteredMatched: 0,
			Dropped:         0,
		},
	}

	err = stream.Send(batch)
	require.NoError(t, err, "Failed to send jumbo frames")

	// Wait for ACK from processor
	_, err = stream.Recv()
	require.NoError(t, err, "Failed to receive ACK from processor")

	// Wait a bit for stats to be updated
	time.Sleep(100 * time.Millisecond)

	// Verify processor handled jumbo frames
	stats := proc.GetStats()
	assert.GreaterOrEqual(t, stats.TotalPacketsReceived, uint64(10), "Processor should handle jumbo frames")

	t.Logf("✓ Jumbo frames test: Sent %d packets of 9000 bytes each", len(jumboPackets))
}

// Helper functions

func startTestProcessor(ctx context.Context, addr string) (*processor.Processor, error) {
	config := processor.Config{
		ProcessorID:     "test-processor-" + addr,
		ListenAddr:      addr,
		EnableDetection: false,
		MaxHunters:      100,
	}

	proc, err := processor.New(config)
	if err != nil {
		return nil, err
	}

	// Channel to receive startup errors
	errChan := make(chan error, 1)

	// Start processor in background
	go func() {
		if err := proc.Start(ctx); err != nil {
			// Send error to channel for debugging
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Wait a bit and check for startup errors
	select {
	case err := <-errChan:
		return nil, fmt.Errorf("processor failed to start: %w", err)
	case <-time.After(100 * time.Millisecond):
		// Processor started successfully
	}

	return proc, nil
}

func connectHunter(ctx context.Context, addr string, hunterID string) (*grpc.ClientConn, data.DataService_StreamPacketsClient, error) {
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, nil, err
	}

	// Register hunter
	mgmtClient := management.NewManagementServiceClient(conn)
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   hunterID,
		Hostname:   "test-host",
		Interfaces: []string{"mock0"},
		Version:    "test-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:          false,
		},
	})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Create stream
	dataClient := data.NewDataServiceClient(conn)
	stream, err := dataClient.StreamPackets(ctx)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return conn, stream, nil
}

func createTestBatch(hunterID string, sequence uint64, numPackets int) *data.PacketBatch {
	packets := make([]*data.CapturedPacket, numPackets)
	for i := 0; i < numPackets; i++ {
		packets[i] = &data.CapturedPacket{
			Data:           createTestPacketData(i),
			TimestampNs:    time.Now().UnixNano(),
			CaptureLength:  100,
			OriginalLength: 100,
			InterfaceIndex: 0,
			LinkType:       1, // Ethernet
		}
	}

	return &data.PacketBatch{
		HunterId:    hunterID,
		Sequence:    sequence,
		TimestampNs: time.Now().UnixNano(),
		Packets:     packets,
		Stats: &data.BatchStats{
			TotalCaptured:   uint64(numPackets),
			FilteredMatched: 0,
			Dropped:         0,
		},
	}
}

func createTestPackets(count int) []gopacket.Packet {
	packets := make([]gopacket.Packet, count)
	for i := 0; i < count; i++ {
		packets[i] = createSyntheticGoPacket(i)
	}
	return packets
}

func createSyntheticGoPacket(index int) gopacket.Packet {
	// Create a simple UDP packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, byte(index)},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, byte(index)},
		DstIP:    net.IP{192, 168, 1, 1},
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(10000 + index),
		DstPort: layers.UDPPort(5060),
	}
	udp.SetNetworkLayerForChecksum(ip)

	payload := []byte(fmt.Sprintf("Test packet %d", index))

	gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createTestPacketData(index int) []byte {
	return createSyntheticGoPacket(index).Data()
}

func createJumboPackets(count int, size int) []*data.CapturedPacket {
	packets := make([]*data.CapturedPacket, count)
	for i := 0; i < count; i++ {
		payload := make([]byte, size)
		// Fill with test pattern
		for j := 0; j < size; j++ {
			payload[j] = byte(j % 256)
		}

		packets[i] = &data.CapturedPacket{
			Data:           payload,
			TimestampNs:    time.Now().UnixNano(),
			CaptureLength:  uint32(size),
			OriginalLength: uint32(size),
			InterfaceIndex: 0,
			LinkType:       1,
		}
	}
	return packets
}

func convertToGrpcPackets(packets []gopacket.Packet) []*data.CapturedPacket {
	result := make([]*data.CapturedPacket, len(packets))
	for i, pkt := range packets {
		result[i] = &data.CapturedPacket{
			Data:           pkt.Data(),
			TimestampNs:    pkt.Metadata().Timestamp.UnixNano(),
			CaptureLength:  uint32(pkt.Metadata().CaptureLength),
			OriginalLength: uint32(pkt.Metadata().Length),
			InterfaceIndex: 0,
			LinkType:       1,
		}
	}
	return result
}

// MockPacketSource for testing
type MockPacketSource struct {
	packets []gopacket.Packet
	index   int
	mu      sync.Mutex
}

func (m *MockPacketSource) NextPacket() (gopacket.Packet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.index >= len(m.packets) {
		return nil, fmt.Errorf("no more packets")
	}

	pkt := m.packets[m.index]
	m.index++
	return pkt, nil
}

func (m *MockPacketSource) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.index = 0
}
