package x2x3

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// BenchmarkX3Encoder_EncodeCC_PayloadSizes benchmarks X3 CC encoding for various payload sizes.
func BenchmarkX3Encoder_EncodeCC_PayloadSizes(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Test various RTP payload sizes.
	payloadSizes := []int{
		160,  // G.711 20ms
		320,  // G.711 40ms
		80,   // G.729 10ms
		33,   // GSM-FR
		1200, // Video frame fragment
	}

	for _, size := range payloadSizes {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			payload := make([]byte, size)
			rand.Read(payload)

			pkt := &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.200",
				SrcPort:   "10000",
				DstPort:   "20000",
				Protocol:  "RTP",
				RawData:   payload,
				VoIPData: &types.VoIPMetadata{
					IsRTP:       true,
					SSRC:        0x12345678,
					SequenceNum: 1000,
					Timestamp:   160000,
					PayloadType: 0, // PCMU
					CallID:      "test-call@192.168.1.100",
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encoder.EncodeCC(pkt, xid)
				if err != nil {
					b.Fatalf("EncodeCC failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkX3Encoder_EncodeCC_Parallel benchmarks X3 CC encoding under concurrent load.
// This simulates multiple calls being intercepted simultaneously.
func BenchmarkX3Encoder_EncodeCC_Parallel(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// G.711 20ms payload.
	payload := make([]byte, 160)
	rand.Read(payload)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   payload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "test-call@192.168.1.100",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encoder.EncodeCC(pkt, xid)
			if err != nil {
				b.Fatalf("EncodeCC failed: %v", err)
			}
		}
	})
}

// BenchmarkX3Encoder_EncodeAndSerialize benchmarks the full encode + serialize path.
func BenchmarkX3Encoder_EncodeAndSerialize(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// G.711 20ms payload.
	payload := make([]byte, 160)
	rand.Read(payload)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   payload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "test-call@192.168.1.100",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	var totalBytes int64
	for i := 0; i < b.N; i++ {
		pdu, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeCC failed: %v", err)
		}

		data, err := pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
		totalBytes += int64(len(data))
	}

	b.ReportMetric(float64(totalBytes)/float64(b.N), "bytes/op")
}

// BenchmarkX3Encoder_EncodeAndSerialize_Parallel benchmarks concurrent encode + serialize.
func BenchmarkX3Encoder_EncodeAndSerialize_Parallel(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// G.711 20ms payload.
	payload := make([]byte, 160)
	rand.Read(payload)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   payload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "test-call@192.168.1.100",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pdu, err := encoder.EncodeCC(pkt, xid)
			if err != nil {
				b.Fatalf("EncodeCC failed: %v", err)
			}

			_, err = pdu.MarshalBinary()
			if err != nil {
				b.Fatalf("MarshalBinary failed: %v", err)
			}
		}
	})
}

// BenchmarkX3Encoder_HighVolumeThroughput measures throughput in packets per second.
// This simulates high-volume RTP interception (e.g., many concurrent calls).
func BenchmarkX3Encoder_HighVolumeThroughput(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// G.711 20ms at 8kHz = 50 packets/second per call.
	// With 100 concurrent calls, that's 5000 packets/second.
	payload := make([]byte, 160)
	rand.Read(payload)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   payload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "test-call@192.168.1.100",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		pdu, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeCC failed: %v", err)
		}
		_, err = pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
	}
	elapsed := time.Since(start)

	packetsPerSecond := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(packetsPerSecond, "pkt/s")

	// Also report in terms of concurrent G.711 calls (50 pkt/s each).
	concurrentCalls := packetsPerSecond / 50.0
	b.ReportMetric(concurrentCalls, "calls@G.711")
}

// BenchmarkX3Encoder_EncodeCCBatch_BatchSizes benchmarks batch encoding of RTP packets.
func BenchmarkX3Encoder_EncodeCCBatch_BatchSizes(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	batchSizes := []int{10, 50, 100, 500}

	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			// Create batch of RTP packets.
			packets := make([]*types.PacketDisplay, batchSize)
			for i := 0; i < batchSize; i++ {
				payload := make([]byte, 160)
				rand.Read(payload)

				packets[i] = &types.PacketDisplay{
					Timestamp: time.Now(),
					SrcIP:     "192.168.1.100",
					DstIP:     "192.168.1.200",
					SrcPort:   fmt.Sprintf("%d", 10000+i),
					DstPort:   fmt.Sprintf("%d", 20000+i),
					Protocol:  "RTP",
					RawData:   payload,
					VoIPData: &types.VoIPMetadata{
						IsRTP:       true,
						SSRC:        uint32(0x12345678 + i),
						SequenceNum: uint16(1000 + i),
						Timestamp:   uint32(160000 + i*160),
						PayloadType: 0,
						CallID:      fmt.Sprintf("call-%d@192.168.1.100", i),
					},
				}
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				pdus, errs := encoder.EncodeCCBatch(packets, xid)
				if len(errs) > 0 {
					b.Fatalf("EncodeCCBatch errors: %v", errs)
				}
				if len(pdus) != batchSize {
					b.Fatalf("Expected %d PDUs, got %d", batchSize, len(pdus))
				}
			}

			// Report per-packet cost.
			b.ReportMetric(float64(b.N*batchSize), "packets_total")
		})
	}
}

// BenchmarkX3Encoder_VaryingSSRCs benchmarks encoding with many different SSRCs.
// This tests the correlation ID generation with varying stream identifiers.
func BenchmarkX3Encoder_VaryingSSRCs(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Pre-generate packets with different SSRCs (different RTP streams).
	numStreams := 1000
	packets := make([]*types.PacketDisplay, numStreams)
	for i := 0; i < numStreams; i++ {
		payload := make([]byte, 160)
		rand.Read(payload)

		packets[i] = &types.PacketDisplay{
			Timestamp: time.Now(),
			SrcIP:     fmt.Sprintf("192.168.%d.%d", i/256, i%256),
			DstIP:     "192.168.100.1",
			SrcPort:   fmt.Sprintf("%d", 10000+(i%1000)),
			DstPort:   "20000",
			Protocol:  "RTP",
			RawData:   payload,
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        uint32(i + 1),
				SequenceNum: uint16(1000 + i),
				Timestamp:   uint32(160000),
				PayloadType: 0,
				CallID:      fmt.Sprintf("call-%d@192.168.1.100", i),
			},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pkt := packets[i%numStreams]
		_, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeCC failed: %v", err)
		}
	}
}

// BenchmarkX3Encoder_IPv6 benchmarks X3 encoding with IPv6 addresses.
func BenchmarkX3Encoder_IPv6(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	payload := make([]byte, 160)
	rand.Read(payload)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "2001:db8::1",
		DstIP:     "2001:db8::2",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   payload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1000,
			Timestamp:   160000,
			PayloadType: 0,
			CallID:      "ipv6-call@example.com",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pdu, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeCC failed: %v", err)
		}
		_, err = pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
	}
}

// BenchmarkX3Encoder_LargeVideoPayload benchmarks encoding with video-sized payloads.
func BenchmarkX3Encoder_LargeVideoPayload(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	payloadSizes := []int{
		1400,  // Near MTU video fragment
		5000,  // Jumbo frame
		10000, // Large frame
	}

	for _, size := range payloadSizes {
		b.Run(fmt.Sprintf("video_%d", size), func(b *testing.B) {
			payload := make([]byte, size)
			rand.Read(payload)

			pkt := &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.200",
				SrcPort:   "10000",
				DstPort:   "20000",
				Protocol:  "RTP",
				RawData:   payload,
				VoIPData: &types.VoIPMetadata{
					IsRTP:       true,
					SSRC:        0x12345678,
					SequenceNum: 1000,
					Timestamp:   90000,
					PayloadType: 96, // Dynamic (H.264)
					CallID:      "video-call@192.168.1.100",
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			var totalBytes int64
			for i := 0; i < b.N; i++ {
				pdu, err := encoder.EncodeCC(pkt, xid)
				if err != nil {
					b.Fatalf("EncodeCC failed: %v", err)
				}

				data, err := pdu.MarshalBinary()
				if err != nil {
					b.Fatalf("MarshalBinary failed: %v", err)
				}
				totalBytes += int64(len(data))
			}

			b.ReportMetric(float64(totalBytes)/float64(b.N), "bytes/op")
		})
	}
}

// BenchmarkX3Encoder_SimulateCallLoad simulates realistic call load.
// Each G.711 call generates 50 packets/second (20ms interval).
func BenchmarkX3Encoder_SimulateCallLoad(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Simulate 100 concurrent G.711 calls.
	numCalls := 100
	packetsPerCall := 50 // 50 pkt/s

	// Pre-generate packets for all calls.
	allPackets := make([]*types.PacketDisplay, numCalls*packetsPerCall)
	for call := 0; call < numCalls; call++ {
		for pkt := 0; pkt < packetsPerCall; pkt++ {
			payload := make([]byte, 160)
			rand.Read(payload)

			idx := call*packetsPerCall + pkt
			allPackets[idx] = &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     fmt.Sprintf("192.168.%d.%d", call/256, call%256),
				DstIP:     "192.168.100.1",
				SrcPort:   fmt.Sprintf("%d", 10000+call),
				DstPort:   "20000",
				Protocol:  "RTP",
				RawData:   payload,
				VoIPData: &types.VoIPMetadata{
					IsRTP:       true,
					SSRC:        uint32(call + 1),
					SequenceNum: uint16(1000 + pkt),
					Timestamp:   uint32(160 * pkt),
					PayloadType: 0,
					CallID:      fmt.Sprintf("call-%d@192.168.1.100", call),
				},
			}
		}
	}

	totalPackets := len(allPackets)

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		pkt := allPackets[i%totalPackets]
		pdu, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeCC failed: %v", err)
		}
		_, err = pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
	}
	elapsed := time.Since(start)

	packetsPerSecond := float64(b.N) / elapsed.Seconds()
	concurrentCalls := packetsPerSecond / 50.0

	b.ReportMetric(packetsPerSecond, "pkt/s")
	b.ReportMetric(concurrentCalls, "concurrent_calls")
}
