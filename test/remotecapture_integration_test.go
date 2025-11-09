package test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestIntegration_RemoteCapture_ConnectAndStream tests end-to-end packet streaming
func TestIntegration_RemoteCapture_ConnectAndStream(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Register a hunter to generate traffic
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "test-hunter-1",
		Hostname:   "test-host-1",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
	})
	require.NoError(t, err)

	// Create remotecapture client
	handler := &TestEventHandler{
		packetBatches: make([][]types.PacketDisplay, 0),
		hunterStatus:  make([][]types.HunterInfo, 0),
		disconnects:   make([]error, 0),
	}

	config := &remotecapture.ClientConfig{
		Address:    processorAddr,
		TLSEnabled: false,
	}

	client, err := remotecapture.NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify connection
	assert.NotNil(t, client)
	assert.Equal(t, processorAddr, client.GetAddr())
	assert.Equal(t, remotecapture.NodeTypeProcessor, client.GetNodeType())

	// Start streaming
	err = client.StreamPackets()
	require.NoError(t, err)

	// Subscribe to hunter status
	err = client.SubscribeHunterStatus()
	require.NoError(t, err)

	// Send some packets from hunter
	dataClient := data.NewDataServiceClient(conn)
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(t, err)

	batch := &data.PacketBatch{
		HunterId:    "test-hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(5)),
		Stats: &data.BatchStats{
			TotalCaptured:   5,
			FilteredMatched: 0,
			Dropped:         0,
		},
	}

	err = stream.Send(batch)
	require.NoError(t, err)

	// Wait for packets to be received (hunter status updates come every 2 seconds)
	time.Sleep(3 * time.Second)

	// Verify we received packets
	handler.mu.Lock()
	receivedPackets := len(handler.packetBatches) > 0
	receivedStatus := len(handler.hunterStatus) > 0
	noDisconnects := len(handler.disconnects) == 0
	handler.mu.Unlock()

	assert.True(t, receivedPackets, "should have received packet batches")
	assert.True(t, receivedStatus, "should have received hunter status updates")
	assert.True(t, noDisconnects, "should not have disconnected")
}

// TestIntegration_RemoteCapture_FilteredStream tests streaming with hunter filter
func TestIntegration_RemoteCapture_FilteredStream(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Register multiple hunters
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter-1
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "hunter-1",
		Hostname:   "host-1",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
	})
	require.NoError(t, err)

	// Register hunter-2
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "hunter-2",
		Hostname:   "host-2",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
	})
	require.NoError(t, err)

	// Create remotecapture client with filter
	handler := &TestEventHandler{
		packetBatches: make([][]types.PacketDisplay, 0),
		hunterStatus:  make([][]types.HunterInfo, 0),
		disconnects:   make([]error, 0),
	}

	config := &remotecapture.ClientConfig{
		Address:    processorAddr,
		TLSEnabled: false,
	}

	client, err := remotecapture.NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Start streaming with filter for hunter-1 only
	err = client.StreamPacketsWithFilter([]string{"hunter-1"})
	require.NoError(t, err)

	// Send packets from both hunters
	dataClient := data.NewDataServiceClient(conn)
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(t, err)

	// Send from hunter-1
	batch1 := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(3)),
		Stats:       &data.BatchStats{TotalCaptured: 3},
	}
	err = stream.Send(batch1)
	require.NoError(t, err)

	// Send from hunter-2 (should be filtered out)
	batch2 := &data.PacketBatch{
		HunterId:    "hunter-2",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(3)),
		Stats:       &data.BatchStats{TotalCaptured: 3},
	}
	err = stream.Send(batch2)
	require.NoError(t, err)

	// Wait for packets
	time.Sleep(1 * time.Second)

	// Verify only hunter-1 packets received
	handler.mu.Lock()
	defer handler.mu.Unlock()

	if len(handler.packetBatches) > 0 {
		for _, batch := range handler.packetBatches {
			for _, pkt := range batch {
				assert.Equal(t, "hunter-1", pkt.NodeID,
					"should only receive packets from hunter-1")
			}
		}
	}
}

// TestIntegration_RemoteCapture_HotSwapSubscription tests hot-swapping hunter filter
func TestIntegration_RemoteCapture_HotSwapSubscription(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Register hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "hunter-swap",
		Hostname:   "host-swap",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
	})
	require.NoError(t, err)

	// Create remotecapture client
	handler := &TestEventHandler{
		packetBatches: make([][]types.PacketDisplay, 0),
		hunterStatus:  make([][]types.HunterInfo, 0),
		disconnects:   make([]error, 0),
	}

	config := &remotecapture.ClientConfig{
		Address:    processorAddr,
		TLSEnabled: false,
	}

	client, err := remotecapture.NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Start with all hunters
	err = client.StreamPackets()
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Hot-swap to specific hunter
	err = client.UpdateSubscription([]string{"hunter-swap"})
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Hot-swap back to all hunters
	err = client.UpdateSubscription(nil)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	// Verify no disconnects during hot-swap
	handler.mu.Lock()
	noDisconnects := len(handler.disconnects) == 0
	handler.mu.Unlock()

	assert.True(t, noDisconnects, "hot-swap should not cause disconnect")
}

// TestIntegration_RemoteCapture_MultipleSubscribers tests multiple concurrent clients
func TestIntegration_RemoteCapture_MultipleSubscribers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Register hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "hunter-multi",
		Hostname:   "host-multi",
		Interfaces: []string{"eth0"},
		Version:    "test-1.0.0",
	})
	require.NoError(t, err)

	// Create multiple clients
	numClients := 3
	clients := make([]*remotecapture.Client, numClients)
	handlers := make([]*TestEventHandler, numClients)

	for i := 0; i < numClients; i++ {
		handlers[i] = &TestEventHandler{
			packetBatches: make([][]types.PacketDisplay, 0),
			hunterStatus:  make([][]types.HunterInfo, 0),
			disconnects:   make([]error, 0),
		}

		config := &remotecapture.ClientConfig{
			Address:    processorAddr,
			TLSEnabled: false,
		}

		client, err := remotecapture.NewClientWithConfig(config, handlers[i])
		require.NoError(t, err)
		clients[i] = client

		// Start streaming
		err = client.StreamPackets()
		require.NoError(t, err)
	}

	// Wait for all subscriptions to be established
	time.Sleep(500 * time.Millisecond)

	// Send packets
	dataClient := data.NewDataServiceClient(conn)
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(t, err)

	batch := &data.PacketBatch{
		HunterId:    "hunter-multi",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     convertToGrpcPackets(createTestPackets(5)),
		Stats:       &data.BatchStats{TotalCaptured: 5},
	}

	err = stream.Send(batch)
	require.NoError(t, err)

	// Wait for packets
	time.Sleep(1 * time.Second)

	// Close all clients
	for _, client := range clients {
		client.Close()
	}

	// Verify all clients received packets
	receivedCount := 0
	for _, handler := range handlers {
		handler.mu.Lock()
		if len(handler.packetBatches) > 0 {
			receivedCount++
		}
		handler.mu.Unlock()
	}

	assert.Equal(t, numClients, receivedCount,
		"all clients should have received packets")
}

// TestIntegration_RemoteCapture_GetTopology tests topology query
func TestIntegration_RemoteCapture_GetTopology(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start processor
	processorAddr, err := getFreePort()
	require.NoError(t, err)

	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(t, err)
	defer shutdownProcessorWithPortCleanup(proc)

	time.Sleep(500 * time.Millisecond)

	// Create remotecapture client
	handler := &TestEventHandler{
		packetBatches: make([][]types.PacketDisplay, 0),
		hunterStatus:  make([][]types.HunterInfo, 0),
		disconnects:   make([]error, 0),
	}

	config := &remotecapture.ClientConfig{
		Address:    processorAddr,
		TLSEnabled: false,
	}

	client, err := remotecapture.NewClientWithConfig(config, handler)
	require.NoError(t, err)
	defer client.Close()

	// Verify this is a processor
	assert.Equal(t, remotecapture.NodeTypeProcessor, client.GetNodeType())

	// Get topology
	topologyCtx, topologyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer topologyCancel()

	topology, err := client.GetTopology(topologyCtx)
	require.NoError(t, err)
	assert.NotNil(t, topology, "should return topology")

	// Verify topology has processor info
	assert.NotEmpty(t, topology.ProcessorId, "topology should have processor ID")
}

// TestEventHandler is a test implementation of types.EventHandler
type TestEventHandler struct {
	mu            sync.Mutex
	packetBatches [][]types.PacketDisplay
	hunterStatus  [][]types.HunterInfo
	disconnects   []error
}

func (h *TestEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.packetBatches = append(h.packetBatches, packets)
}

func (h *TestEventHandler) OnHunterStatus(hunters []types.HunterInfo, processorID string, processorStatus management.ProcessorStatus, processorAddr string, upstreamProcessor string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hunterStatus = append(h.hunterStatus, hunters)
}

func (h *TestEventHandler) OnCallUpdate(calls []types.CallInfo) {
	// Not tracked in these tests
}

func (h *TestEventHandler) OnCorrelatedCallUpdate(correlatedCalls []types.CorrelatedCallInfo) {
	// Not tracked in these tests
}

func (h *TestEventHandler) OnDisconnect(address string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disconnects = append(h.disconnects, err)
}

func (h *TestEventHandler) OnTopologyUpdate(update *management.TopologyUpdate, processorAddr string) {
	// Not tracked in these tests
}
