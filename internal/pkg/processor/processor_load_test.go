//go:build processor || tap || all

package processor

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// TestProcessor_HighPacketRate_10Kpps tests processor handling of high packet rate
func TestProcessor_HighPacketRate_10Kpps(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	cfg := Config{
		ProcessorID: "load-test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	}
	p, err := New(cfg)
	require.NoError(t, err)

	// Register a hunter
	ctx := context.Background()
	registerReq := &management.HunterRegistration{
		HunterId:   "high-rate-hunter",
		Hostname:   "loadtest",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	_, err = p.RegisterHunter(ctx, registerReq)
	require.NoError(t, err)

	// Create a subscriber to receive packets
	server := &mockSubscribePacketsServer{
		ctx:         metadata.NewIncomingContext(ctx, metadata.MD{}),
		sentBatches: []*data.PacketBatch{},
		sendErr:     nil,
	}

	// Subscribe in background
	done := make(chan error, 1)
	go func() {
		done <- p.SubscribePackets(&data.SubscribeRequest{
			ClientId:  "load-test-client",
			HunterIds: []string{"high-rate-hunter"},
		}, server)
	}()

	// Give subscription time to establish
	time.Sleep(50 * time.Millisecond)

	// Send packets as fast as possible without artificial throttling
	// This tests the processor's actual throughput capability
	targetPackets := 10000
	duration := 1 * time.Second

	start := time.Now()
	sent := 0

	timeout := time.After(duration)
	ticker := time.NewTicker(10 * time.Microsecond) // Very fast ticker to batch sends
	defer ticker.Stop()

sendLoop:
	for sent < targetPackets {
		select {
		case <-ticker.C:
			// Send in small bursts to avoid blocking
			for i := 0; i < 10 && sent < targetPackets; i++ {
				batch := &data.PacketBatch{
					HunterId:    "high-rate-hunter",
					Sequence:    uint64(sent + 1),
					TimestampNs: time.Now().UnixNano(),
					Packets:     []*data.CapturedPacket{createTestDataPacket()},
				}
				p.processBatch(source.FromProtoBatch(batch))
				sent++
			}

		case <-timeout:
			break sendLoop
		}
	}

	elapsed := time.Since(start)
	actualRate := float64(sent) / elapsed.Seconds()
	t.Logf("Sent %d packets in %v (%.0f packets/sec)", sent, elapsed, actualRate)

	// In CI with race detector, we may not reach 10k/sec, but we should process a reasonable amount
	// Target is at least 1000 packets/sec (very conservative for CI environments)
	minRate := 1000.0
	assert.Greater(t, actualRate, minRate, "Packet rate too low")

	// Give time for processing to complete
	time.Sleep(100 * time.Millisecond)

	// Check subscriber received packets
	server.mu.Lock()
	receivedBatches := len(server.sentBatches)
	server.mu.Unlock()

	t.Logf("Subscriber received %d batches", receivedBatches)
	assert.Greater(t, receivedBatches, 0, "Subscriber should have received packets")
}

// TestProcessor_ManyHunters_100Concurrent tests processor with 100 concurrent hunters
func TestProcessor_ManyHunters_100Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	cfg := Config{
		ProcessorID: "load-test-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  150, // Allow more than test count
	}
	p, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	hunterCount := 100
	var wg sync.WaitGroup

	start := time.Now()

	// Register hunters concurrently
	for i := 0; i < hunterCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			registerReq := &management.HunterRegistration{
				HunterId:   fmt.Sprintf("hunter-%d", id),
				Hostname:   fmt.Sprintf("host-%d", id),
				Interfaces: []string{"eth0"},
				Version:    "v1.0.0",
			}
			_, err := p.RegisterHunter(ctx, registerReq)
			if err != nil {
				t.Logf("Failed to register hunter-%d: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)
	t.Logf("Registered %d hunters in %v", hunterCount, elapsed)

	// Verify all hunters registered
	stats := p.GetStats()
	registeredCount := int(stats.TotalHunters)

	t.Logf("Successfully registered: %d/%d hunters", registeredCount, hunterCount)
	assert.Equal(t, hunterCount, registeredCount, "All hunters should be registered")

	// Send packets from all hunters concurrently
	packetsPerHunter := 10
	totalPackets := hunterCount * packetsPerHunter

	start = time.Now()
	for i := 0; i < hunterCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < packetsPerHunter; j++ {
				batch := &data.PacketBatch{
					HunterId:    fmt.Sprintf("hunter-%d", id),
					Sequence:    uint64(j + 1),
					TimestampNs: time.Now().UnixNano(),
					Packets:     []*data.CapturedPacket{createTestDataPacket()},
				}
				p.processBatch(source.FromProtoBatch(batch))
			}
		}(i)
	}

	wg.Wait()
	elapsed = time.Since(start)
	rate := float64(totalPackets) / elapsed.Seconds()
	t.Logf("Processed %d packets from %d hunters in %v (%.0f packets/sec)",
		totalPackets, hunterCount, elapsed, rate)

	// Verify stats
	stats = p.GetStats()
	assert.Equal(t, uint32(hunterCount), stats.TotalHunters, "Active hunter count mismatch")
}

// TestProcessor_ManySubscribers_100Concurrent tests processor with 100 TUI clients
func TestProcessor_ManySubscribers_100Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	cfg := Config{
		ProcessorID:    "load-test-processor",
		ListenAddr:     "localhost:0",
		MaxHunters:     10,
		MaxSubscribers: 150, // Allow more than test count
	}
	p, err := New(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Register a hunter
	registerReq := &management.HunterRegistration{
		HunterId:   "shared-hunter",
		Hostname:   "loadtest",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	_, err = p.RegisterHunter(ctx, registerReq)
	require.NoError(t, err)

	subscriberCount := 100
	var wg sync.WaitGroup

	// Create subscribers concurrently
	subscribers := make([]*mockSubscribePacketsServer, subscriberCount)
	contexts := make([]context.Context, subscriberCount)
	cancels := make([]context.CancelFunc, subscriberCount)

	for i := 0; i < subscriberCount; i++ {
		contexts[i], cancels[i] = context.WithCancel(metadata.NewIncomingContext(ctx, metadata.MD{}))
		subscribers[i] = &mockSubscribePacketsServer{
			ctx:         contexts[i],
			sentBatches: []*data.PacketBatch{},
			sendErr:     nil,
		}
	}

	start := time.Now()

	// Start all subscriptions
	for i := 0; i < subscriberCount; i++ {
		wg.Add(1)
		go func(id int, server *mockSubscribePacketsServer) {
			defer wg.Done()

			err := p.SubscribePackets(&data.SubscribeRequest{
				ClientId:  fmt.Sprintf("client-%d", id),
				HunterIds: []string{"shared-hunter"},
			}, server)
			if err != nil {
				t.Logf("Subscriber-%d error: %v", id, err)
			}
		}(i, subscribers[i])
	}

	// Give subscriptions time to establish
	time.Sleep(100 * time.Millisecond)

	// Verify all subscribed
	subCount := p.subscriberManager.Count()
	t.Logf("Active subscribers: %d/%d", subCount, subscriberCount)

	// Send some packets
	packetsToSend := 50
	for i := 0; i < packetsToSend; i++ {
		batch := &data.PacketBatch{
			HunterId:    "shared-hunter",
			Sequence:    uint64(i + 1),
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{createTestDataPacket()},
		}
		p.processBatch(source.FromProtoBatch(batch))
	}

	// Give time for broadcasts
	time.Sleep(200 * time.Millisecond)

	// Cancel all subscriptions by closing contexts
	for i := 0; i < subscriberCount; i++ {
		cancels[i]()
	}

	// Wait for subscriptions to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		t.Logf("All %d subscribers completed in %v", subscriberCount, elapsed)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for subscribers to complete")
	}

	// Count how many subscribers received packets
	receivedCount := 0
	for i := 0; i < subscriberCount; i++ {
		subscribers[i].mu.Lock()
		if len(subscribers[i].sentBatches) > 0 {
			receivedCount++
		}
		subscribers[i].mu.Unlock()
	}
	t.Logf("Subscribers that received packets: %d/%d", receivedCount, subscriberCount)
}

// TestProcessor_DeepTopology_5Levels tests 5-level processor hierarchy
func TestProcessor_DeepTopology_5Levels(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	t.Skip("Skipping topology test - requires processor hierarchy support")

	// This test would create a deep hierarchy but requires
	// processors to actually listen on ports and connect upstream
	// which is complex for a unit test
}

// BenchmarkProcessor_PacketProcessing benchmarks packet processing throughput
func BenchmarkProcessor_PacketProcessing(b *testing.B) {
	cfg := Config{
		ProcessorID: "bench-processor",
		ListenAddr:  "localhost:0",
		MaxHunters:  10,
	}
	p, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}

	// Register a hunter
	ctx := context.Background()
	registerReq := &management.HunterRegistration{
		HunterId:   "bench-hunter",
		Hostname:   "bench-host",
		Interfaces: []string{"eth0"},
		Version:    "v1.0.0",
	}
	_, err = p.RegisterHunter(ctx, registerReq)
	if err != nil {
		b.Fatal(err)
	}

	// Create packet batch
	batch := &data.PacketBatch{
		HunterId:    "bench-hunter",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{createTestDataPacket()},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p.processBatch(source.FromProtoBatch(batch))
	}

	b.StopTimer()

	// Report throughput
	elapsed := b.Elapsed()
	rate := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(rate, "packets/sec")
}

// BenchmarkProcessor_ManyHunters benchmarks with multiple concurrent hunters
func BenchmarkProcessor_ManyHunters(b *testing.B) {
	hunterCounts := []int{10, 50, 100}

	for _, hunterCount := range hunterCounts {
		b.Run(fmt.Sprintf("%d_hunters", hunterCount), func(b *testing.B) {
			cfg := Config{
				ProcessorID: "bench-processor",
				ListenAddr:  "localhost:0",
				MaxHunters:  hunterCount + 10,
			}
			p, err := New(cfg)
			if err != nil {
				b.Fatal(err)
			}

			ctx := context.Background()

			// Register hunters
			for i := 0; i < hunterCount; i++ {
				registerReq := &management.HunterRegistration{
					HunterId:   fmt.Sprintf("hunter-%d", i),
					Hostname:   fmt.Sprintf("host-%d", i),
					Interfaces: []string{"eth0"},
					Version:    "v1.0.0",
				}
				_, err := p.RegisterHunter(ctx, registerReq)
				if err != nil {
					b.Fatal(err)
				}
			}

			// Create batches for each hunter
			batches := make([]*data.PacketBatch, hunterCount)
			for i := 0; i < hunterCount; i++ {
				batches[i] = &data.PacketBatch{
					HunterId:    fmt.Sprintf("hunter-%d", i),
					Sequence:    1,
					TimestampNs: time.Now().UnixNano(),
					Packets:     []*data.CapturedPacket{createTestDataPacket()},
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Round-robin through hunters
				p.processBatch(source.FromProtoBatch(batches[i%hunterCount]))
			}

			b.StopTimer()

			elapsed := b.Elapsed()
			rate := float64(b.N) / elapsed.Seconds()
			b.ReportMetric(rate, "packets/sec")
		})
	}
}

// Helper to create test packet
func createTestDataPacket() *data.CapturedPacket {
	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		Data:           []byte("test packet data"),
		CaptureLength:  16,
		OriginalLength: 16,
		Metadata: &data.PacketMetadata{
			Protocol: "UDP",
			SrcIp:    "192.168.1.1",
			DstIp:    "192.168.1.2",
			SrcPort:  5060,
			DstPort:  5060,
		},
	}
}
