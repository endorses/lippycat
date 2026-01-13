//go:build cli || all

package voip

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BenchmarkCaptureEngine_XDP benchmarks XDP packet capture
func BenchmarkCaptureEngine_XDP(b *testing.B) {
	if !IsXDPSupported() {
		b.Skip("XDP not supported on this system")
	}

	config := DefaultCaptureConfig("lo")
	config.UseXDP = true
	config.BufferSize = 10000
	config.BatchSize = 64

	engine, err := NewCaptureEngine(config)
	if err != nil {
		b.Skip("Could not create XDP capture engine:", err)
	}
	defer engine.Close()

	if !engine.IsUsingXDP() {
		b.Skip("XDP not available, using standard capture")
	}

	b.ResetTimer()
	b.ReportAllocs()

	var processed atomic.Uint64
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		for {
			select {
			case pkt := <-engine.Packets():
				if pkt != nil {
					processed.Add(1)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := engine.Start(); err != nil {
		b.Fatal(err)
	}

	<-ctx.Done()
	engine.Stop()

	b.StopTimer()
	stats := engine.GetStats()
	b.ReportMetric(float64(stats.PacketsReceived.Load()), "packets_rx")
	b.ReportMetric(float64(stats.PacketsDropped.Load()), "packets_dropped")
	b.ReportMetric(float64(processed.Load()), "packets_processed")
}

// BenchmarkCaptureEngine_Standard benchmarks standard packet capture
func BenchmarkCaptureEngine_Standard(b *testing.B) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = false
	config.BufferSize = 10000

	engine, err := NewCaptureEngine(config)
	if err != nil {
		b.Skip("Could not create standard capture engine:", err)
	}
	defer engine.Close()

	b.ResetTimer()
	b.ReportAllocs()

	var processed atomic.Uint64
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		for {
			select {
			case pkt := <-engine.Packets():
				if pkt != nil {
					processed.Add(1)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := engine.Start(); err != nil {
		b.Fatal(err)
	}

	<-ctx.Done()
	engine.Stop()

	b.StopTimer()
	stats := engine.GetStats()
	b.ReportMetric(float64(stats.PacketsReceived.Load()), "packets_rx")
	b.ReportMetric(float64(processed.Load()), "packets_processed")
}

// BenchmarkXDPSocket_ReceiveBatch benchmarks batch packet reception
func BenchmarkXDPSocket_ReceiveBatch(b *testing.B) {
	if !IsXDPSupported() {
		b.Skip("XDP not supported")
	}

	config := DefaultXDPConfig("lo")
	socket, err := NewXDPSocket(config)
	if err != nil {
		b.Skip("Could not create XDP socket:", err)
	}
	defer socket.Close()

	batchSizes := []int{1, 8, 16, 32, 64, 128}

	for _, batchSize := range batchSizes {
		b.Run(b.Name()+"_batch_"+string(rune(batchSize)), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			totalPackets := 0
			for i := 0; i < b.N; i++ {
				packets, _ := socket.ReceiveBatch(batchSize)
				totalPackets += len(packets)
			}

			b.StopTimer()
			b.ReportMetric(float64(totalPackets)/float64(b.N), "pkts/batch")
		})
	}
}

// BenchmarkUMEM_FrameOperations benchmarks UMEM frame allocation
func BenchmarkUMEM_FrameOperations(b *testing.B) {
	size := 4 * 1024 * 1024
	frameSize := 2048
	numFrames := size / frameSize

	umem, err := newUMEM(size, frameSize, numFrames)
	if err != nil {
		b.Skip("UMEM allocation failed:", err)
	}

	b.Run("AllocFrame", func(b *testing.B) {
		b.ReportAllocs()

		// Pre-allocate to ensure frames available
		allocated := make([]uint64, 0, b.N)
		for i := 0; i < b.N && i < numFrames; i++ {
			idx, ok := umem.AllocFrame()
			if ok {
				allocated = append(allocated, idx)
			}
		}

		// Free all
		for _, idx := range allocated {
			umem.FreeFrame(idx)
		}

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			idx, ok := umem.AllocFrame()
			if ok {
				umem.FreeFrame(idx)
			}
		}
	})

	b.Run("GetFrame", func(b *testing.B) {
		idx, _ := umem.AllocFrame()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = umem.GetFrame(idx)
		}
	})
}

// BenchmarkCaptureEngine_EndToEnd benchmarks full capture pipeline
func BenchmarkCaptureEngine_EndToEnd(b *testing.B) {
	config := DefaultCaptureConfig("lo")
	config.BufferSize = 10000
	config.BatchSize = 64

	engine, err := NewCaptureEngine(config)
	if err != nil {
		b.Skip("Could not create capture engine:", err)
	}
	defer engine.Close()

	// Create mock packet processor
	processor := func(pkt []byte) {
		// Simulate packet processing overhead
		_ = len(pkt)
	}

	b.ResetTimer()
	b.ReportAllocs()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		for {
			select {
			case pkt := <-engine.Packets():
				if pkt != nil {
					processor(pkt)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := engine.Start(); err != nil {
		b.Fatal(err)
	}

	<-ctx.Done()
	engine.Stop()

	b.StopTimer()
	stats := engine.GetStats()
	b.ReportMetric(float64(stats.PacketsProcessed.Load()), "packets")
	b.ReportMetric(float64(stats.BytesReceived.Load())/1024/1024, "MB")

	if stats.PacketsReceived.Load() > 0 {
		dropRate := float64(stats.PacketsDropped.Load()) / float64(stats.PacketsReceived.Load()) * 100
		b.ReportMetric(dropRate, "drop_rate_%")
	}
}

// BenchmarkXDP_vs_MmapWriter benchmarks capture + write pipeline
func BenchmarkXDP_vs_MmapWriter(b *testing.B) {
	tempDir := b.TempDir()

	b.Run("XDP_to_MmapV2", func(b *testing.B) {
		if !IsXDPSupported() {
			b.Skip("XDP not supported")
		}

		// Setup capture
		captureConfig := DefaultCaptureConfig("lo")
		captureConfig.UseXDP = true
		captureConfig.BufferSize = 10000

		engine, err := NewCaptureEngine(captureConfig)
		if err != nil {
			b.Skip("Could not create XDP engine:", err)
		}
		defer engine.Close()

		if !engine.IsUsingXDP() {
			b.Skip("XDP not available")
		}

		// Setup writer
		writerConfig := DefaultMmapV2Config()
		writerConfig.PreallocSize = 100 * 1024 * 1024

		writer, err := NewMmapWriterV2(
			tempDir+"/xdp_capture.pcap",
			layers.LinkTypeEthernet,
			writerConfig,
		)
		if err != nil {
			b.Fatal(err)
		}
		defer writer.Close()

		b.ResetTimer()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		go func() {
			for {
				select {
				case pkt := <-engine.Packets():
					if pkt != nil {
						ci := gopacket.CaptureInfo{
							Timestamp:     time.Now(),
							CaptureLength: len(pkt),
							Length:        len(pkt),
						}
						writer.WritePacket(ci, pkt)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		engine.Start()
		<-ctx.Done()
		engine.Stop()

		b.StopTimer()
		metrics := writer.GetMetrics()
		b.ReportMetric(float64(metrics.PacketsWritten), "packets_written")
		b.ReportMetric(float64(metrics.BytesWritten)/1024/1024, "MB_written")
	})

	b.Run("Standard_to_MmapV2", func(b *testing.B) {
		// Setup capture
		captureConfig := DefaultCaptureConfig("lo")
		captureConfig.UseXDP = false
		captureConfig.BufferSize = 10000

		engine, err := NewCaptureEngine(captureConfig)
		if err != nil {
			b.Skip("Could not create standard engine:", err)
		}
		defer engine.Close()

		// Setup writer
		writerConfig := DefaultMmapV2Config()
		writerConfig.PreallocSize = 100 * 1024 * 1024

		writer, err := NewMmapWriterV2(
			tempDir+"/standard_capture.pcap",
			layers.LinkTypeEthernet,
			writerConfig,
		)
		if err != nil {
			b.Fatal(err)
		}
		defer writer.Close()

		b.ResetTimer()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		go func() {
			for {
				select {
				case pkt := <-engine.Packets():
					if pkt != nil {
						ci := gopacket.CaptureInfo{
							Timestamp:     time.Now(),
							CaptureLength: len(pkt),
							Length:        len(pkt),
						}
						writer.WritePacket(ci, pkt)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		engine.Start()
		<-ctx.Done()
		engine.Stop()

		b.StopTimer()
		metrics := writer.GetMetrics()
		b.ReportMetric(float64(metrics.PacketsWritten), "packets_written")
		b.ReportMetric(float64(metrics.BytesWritten)/1024/1024, "MB_written")
	})
}

// BenchmarkCaptureMode_Switch benchmarks mode switching
func BenchmarkCaptureMode_Switch(b *testing.B) {
	config := DefaultCaptureConfig("lo")
	config.UseXDP = true

	engine, err := NewCaptureEngine(config)
	if err != nil {
		b.Skip("Could not create capture engine:", err)
	}
	defer engine.Close()

	initialMode := engine.GetMode()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		targetMode := CaptureModeStandard
		if i%2 == 0 {
			targetMode = CaptureModeXDP
		}

		// Only switch if different
		if engine.GetMode() != targetMode {
			engine.SwitchMode(targetMode)
		}
	}

	b.StopTimer()
	b.Logf("Initial mode: %s, Final mode: %s", initialMode, engine.GetMode())
}
