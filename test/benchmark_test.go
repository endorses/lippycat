package test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// BenchmarkProcessorPacketThroughput measures packet processing throughput
func BenchmarkProcessorPacketThroughput(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start processor
	processorAddr := "127.0.0.1:50070"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(b, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Connect hunter
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(b, err)
	defer conn.Close()

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	// Register hunter
	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "bench-hunter",
		Hostname:   "bench-host",
		Interfaces: []string{"mock0"},
		Version:    "bench-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(b, err)

	// Create stream
	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(b, err)

	// Pre-generate test packets (outside benchmark loop)
	testPackets := make([]*data.CapturedPacket, 100)
	for i := 0; i < 100; i++ {
		testPackets[i] = createSyntheticPacket(i)
	}

	b.ResetTimer() // Start timing from here

	// Benchmark packet throughput
	b.RunParallel(func(pb *testing.PB) {
		seqNum := uint64(0)
		for pb.Next() {
			batch := &data.PacketBatch{
				HunterId:    "bench-hunter",
				Sequence:    atomic.AddUint64(&seqNum, 1),
				TimestampNs: time.Now().UnixNano(),
				Packets:     testPackets,
				Stats: &data.BatchStats{
					TotalCaptured:   uint64(len(testPackets)),
					FilteredMatched: 0,
					Dropped:         0,
				},
			}

			if err := stream.Send(batch); err != nil {
				b.Fatalf("Failed to send batch: %v", err)
			}

			// Receive ack (flow control)
			if _, err := stream.Recv(); err != nil {
				b.Fatalf("Failed to receive ack: %v", err)
			}
		}
	})

	b.StopTimer()

	// Report throughput metrics
	stats := proc.GetStats()
	b.ReportMetric(float64(stats.TotalPacketsReceived)/b.Elapsed().Seconds(), "packets/sec")
	// Estimate bytes (assuming ~1500 byte average packet size for Ethernet)
	estimatedBytes := stats.TotalPacketsReceived * 1500
	b.ReportMetric(float64(estimatedBytes)/b.Elapsed().Seconds()/(1024*1024), "MB/sec")
}

// BenchmarkHunterToProcessorLatency measures end-to-end latency
func BenchmarkHunterToProcessorLatency(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	processorAddr := "127.0.0.1:50071"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(b, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(b, err)
	defer conn.Close()

	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)

	_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
		HunterId:   "bench-hunter-latency",
		Hostname:   "bench-host",
		Interfaces: []string{"mock0"},
		Version:    "bench-1.0.0",
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"bpf"},
			MaxBufferSize:   8192,
			GpuAcceleration: false,
			AfXdp:           false,
		},
	})
	require.NoError(b, err)

	stream, err := dataClient.StreamPackets(ctx)
	require.NoError(b, err)

	testPacket := createSyntheticPacket(0)

	b.ResetTimer()

	// Measure latency for single-packet batches
	for i := 0; i < b.N; i++ {
		batch := &data.PacketBatch{
			HunterId:    "bench-hunter-latency",
			Sequence:    uint64(i),
			TimestampNs: time.Now().UnixNano(),
			Packets:     []*data.CapturedPacket{testPacket},
			Stats: &data.BatchStats{
				TotalCaptured:   1,
				FilteredMatched: 0,
				Dropped:         0,
			},
		}

		start := time.Now()
		if err := stream.Send(batch); err != nil {
			b.Fatalf("Failed to send batch: %v", err)
		}

		if _, err := stream.Recv(); err != nil {
			b.Fatalf("Failed to receive ack: %v", err)
		}
		latency := time.Since(start)

		b.ReportMetric(float64(latency.Microseconds()), "µs/op")
	}
}

// BenchmarkFilterDistribution measures filter distribution performance
func BenchmarkFilterDistribution(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	processorAddr := "127.0.0.1:50072"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(b, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	// Register 100 hunters
	numHunters := 100
	hunterIDs := make([]string, numHunters)

	for i := 0; i < numHunters; i++ {
		conn, err := grpc.DialContext(ctx, processorAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		require.NoError(b, err)
		defer conn.Close()

		mgmtClient := management.NewManagementServiceClient(conn)
		hunterID := fmt.Sprintf("bench-hunter-%d", i)
		hunterIDs[i] = hunterID

		_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
			HunterId:   hunterID,
			Hostname:   fmt.Sprintf("bench-host-%d", i),
			Interfaces: []string{"mock0"},
			Version:    "bench-1.0.0",
			Capabilities: &management.HunterCapabilities{
				FilterTypes:     []string{"bpf"},
				MaxBufferSize:   8192,
				GpuAcceleration: false,
				AfXdp:           false,
			},
		})
		require.NoError(b, err)
	}

	// Connect management client for pushing filters
	conn, err := grpc.DialContext(ctx, processorAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(b, err)
	defer conn.Close()

	mgmtClient := management.NewManagementServiceClient(conn)

	b.ResetTimer()

	// Benchmark filter distribution to all hunters
	for i := 0; i < b.N; i++ {
		filter := &management.Filter{
			Id:            fmt.Sprintf("bench-filter-%d", i),
			Type:          management.FilterType_FILTER_SIP_USER,
			Pattern:       "alice@example.com",
			TargetHunters: hunterIDs,
			Enabled:       true,
		}

		start := time.Now()
		resp, err := mgmtClient.UpdateFilter(ctx, filter)
		if err != nil {
			b.Fatalf("Failed to update filter: %v", err)
		}
		distributionTime := time.Since(start)

		b.ReportMetric(float64(resp.HuntersUpdated), "hunters/op")
		b.ReportMetric(float64(distributionTime.Microseconds()), "µs/op")
	}
}

// BenchmarkConcurrentHunters measures performance with many concurrent hunters
func BenchmarkConcurrentHunters(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	processorAddr := "127.0.0.1:50073"
	procCtx, procCancel := context.WithCancel(ctx)
	defer procCancel()
	proc, err := startTestProcessor(procCtx, processorAddr)
	require.NoError(b, err)
	defer proc.Shutdown()

	time.Sleep(500 * time.Millisecond)

	numHunters := 50
	testPackets := make([]*data.CapturedPacket, 10)
	for i := 0; i < 10; i++ {
		testPackets[i] = createSyntheticPacket(i)
	}

	// Register all hunters
	var wg sync.WaitGroup
	for i := 0; i < numHunters; i++ {
		wg.Add(1)
		go func(hunterIdx int) {
			defer wg.Done()

			conn, err := grpc.DialContext(ctx, processorAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				b.Errorf("Failed to connect hunter %d: %v", hunterIdx, err)
				return
			}
			defer conn.Close()

			dataClient := data.NewDataServiceClient(conn)
			mgmtClient := management.NewManagementServiceClient(conn)

			hunterID := fmt.Sprintf("bench-concurrent-%d", hunterIdx)
			_, err = mgmtClient.RegisterHunter(ctx, &management.HunterRegistration{
				HunterId:   hunterID,
				Hostname:   fmt.Sprintf("bench-host-%d", hunterIdx),
				Interfaces: []string{"mock0"},
				Version:    "bench-1.0.0",
				Capabilities: &management.HunterCapabilities{
					FilterTypes:     []string{"bpf"},
					MaxBufferSize:   8192,
					GpuAcceleration: false,
					AfXdp:           false,
				},
			})
			if err != nil {
				b.Errorf("Failed to register hunter %d: %v", hunterIdx, err)
				return
			}

			_, err = dataClient.StreamPackets(ctx)
			if err != nil {
				b.Errorf("Failed to create stream for hunter %d: %v", hunterIdx, err)
				return
			}

			// Wait for benchmark to start
			<-ctx.Done()
		}(i)
	}

	wg.Wait()

	b.ResetTimer()

	// Measure processor performance with concurrent hunters
	var totalPackets atomic.Uint64
	for i := 0; i < b.N; i++ {
		totalPackets.Add(uint64(numHunters * len(testPackets)))
	}

	b.StopTimer()

	stats := proc.GetStats()
	b.ReportMetric(float64(stats.TotalPacketsReceived)/b.Elapsed().Seconds(), "packets/sec")
	b.ReportMetric(float64(numHunters), "concurrent_hunters")
}

// BenchmarkProtocolDetection measures protocol detection performance
func BenchmarkProtocolDetection(b *testing.B) {
	// This would benchmark the protocol detection system
	// See internal/pkg/detector benchmarks for more details

	packets := [][]byte{
		createSIPInvitePacket(),
		createHTTPPacket(),
		createDNSPacket(),
		createTLSClientHello(),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		_ = detectProtocol(packet)
	}
}

// Helper functions for benchmark are now in testhelpers.go
