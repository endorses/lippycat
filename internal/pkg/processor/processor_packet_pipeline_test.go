//go:build processor || tap || all

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessBatch_BasicFlow tests the basic packet processing flow
// This complements the existing TestProcessBatch in streaming_test.go
func TestProcessBatch_BasicFlow(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Register a hunter
	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create test packet batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet counter was updated
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_MultiplePackets tests processing a batch with many packets
func TestProcessBatch_MultiplePackets(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with 100 packets
	const packetCount = 100
	packets := make([]*data.CapturedPacket, packetCount)
	for i := 0; i < packetCount; i++ {
		packets[i] = &data.CapturedPacket{
			TimestampNs:    time.Now().UnixNano(),
			Data:           make([]byte, 64),
			CaptureLength:  64,
			OriginalLength: 64,
		}
	}

	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     packets,
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify all packets were counted
	assert.Equal(t, uint64(packetCount), processor.packetsReceived.Load())
}

// TestProcessBatch_ConcurrentProcessing tests concurrent batch processing from multiple hunters
func TestProcessBatch_ConcurrentProcessing(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Register multiple hunters
	for i := 0; i < 5; i++ {
		hunterID := "hunter-" + string(rune('1'+i))
		_, _, err := processor.hunterManager.Register(hunterID, "host"+string(rune('1'+i)), []string{"eth0"}, nil)
		require.NoError(t, err)
	}

	// Process batches concurrently from multiple hunters
	const batchesPerHunter = 10
	const packetsPerBatch = 10

	done := make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		hunterID := "hunter-" + string(rune('1'+i))
		go func(hid string) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < batchesPerHunter; j++ {
				packets := make([]*data.CapturedPacket, packetsPerBatch)
				for k := 0; k < packetsPerBatch; k++ {
					packets[k] = &data.CapturedPacket{
						TimestampNs:    time.Now().UnixNano(),
						Data:           make([]byte, 64),
						CaptureLength:  64,
						OriginalLength: 64,
					}
				}

				batch := &data.PacketBatch{
					HunterId:    hid,
					Sequence:    uint64(j + 1),
					TimestampNs: time.Now().UnixNano(),
					Packets:     packets,
				}

				processor.processBatch(source.FromProtoBatch(batch))
			}
		}(hunterID)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}

	// Verify total packet count
	expectedPackets := uint64(5 * batchesPerHunter * packetsPerBatch)
	assert.Equal(t, expectedPackets, processor.packetsReceived.Load())
}

// TestProcessBatch_WithVoIPMetadata tests VoIP packet processing with SIP metadata
func TestProcessBatch_WithVoIPMetadata(t *testing.T) {
	processor, err := New(Config{
		ProcessorID:     "test-processor",
		ListenAddr:      "localhost:50051",
		MaxHunters:      10,
		EnableDetection: true,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create packet with SIP metadata
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
				Metadata: &data.PacketMetadata{
					SrcIp:    "192.168.1.1",
					DstIp:    "192.168.1.2",
					Protocol: "UDP",
					Sip: &data.SIPMetadata{
						CallId:   "test-call-1@example.com",
						FromUser: "alice",
						ToUser:   "bob",
						Method:   "INVITE",
					},
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was processed
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())

	// Verify call was aggregated
	calls := processor.callAggregator.GetCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "test-call-1@example.com", calls[0].CallID)
	assert.Contains(t, calls[0].Hunters, "hunter-1")
}

// TestProcessBatch_WithBroadcast tests subscriber broadcasting
func TestProcessBatch_WithBroadcast(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create subscriber using Add() method
	subChan := processor.subscriberManager.Add("test-subscriber-1")
	require.NotNil(t, subChan)

	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify subscriber received the batch
	select {
	case received := <-subChan:
		assert.Equal(t, batch.HunterId, received.HunterId)
		assert.Equal(t, batch.Sequence, received.Sequence)
	case <-time.After(1 * time.Second):
		t.Fatal("subscriber did not receive batch")
	}
}

// TestProcessBatch_LargePackets tests processing large packets (64KB)
func TestProcessBatch_LargePackets(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with large packets (64KB each)
	const packetSize = 64 * 1024
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, packetSize),
				CaptureLength:  packetSize,
				OriginalLength: packetSize,
			},
		},
	}

	// Should handle large packets
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_HighSequenceNumber tests processing with high sequence numbers
func TestProcessBatch_HighSequenceNumber(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with very high sequence number
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    uint64(1<<63 - 1), // Near max uint64
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Should handle high sequence numbers
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_UnregisteredHunter tests processing batch from unknown hunter
func TestProcessBatch_UnregisteredHunter(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Process batch from unregistered hunter (should not panic)
	batch := &data.PacketBatch{
		HunterId:    "unknown-hunter",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Should not panic
	processor.processBatch(source.FromProtoBatch(batch))

	// Packet should still be counted
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithRTPMetadata tests RTP packet processing
func TestProcessBatch_WithRTPMetadata(t *testing.T) {
	processor, err := New(Config{
		ProcessorID:     "test-processor",
		ListenAddr:      "localhost:50051",
		MaxHunters:      10,
		EnableDetection: true,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create packet with RTP metadata
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
				Metadata: &data.PacketMetadata{
					SrcIp:    "192.168.1.1",
					DstIp:    "192.168.1.2",
					Protocol: "UDP",
					Rtp: &data.RTPMetadata{
						Ssrc:        12345,
						PayloadType: 0,
						Sequence:    100,
						Timestamp:   1000,
					},
					Sip: &data.SIPMetadata{
						CallId: "rtp-call@example.com",
					},
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was processed
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithUpstreamForwarding tests packet forwarding to upstream processor
func TestProcessBatch_WithUpstreamForwarding(t *testing.T) {
	// Create processor with upstream address (enables upstream forwarding)
	processor, err := New(Config{
		ProcessorID:  "test-processor",
		ListenAddr:   "localhost:50051",
		MaxHunters:   10,
		UpstreamAddr: "upstream:50051", // Enables upstream manager
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create test batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Process the batch (should forward to upstream)
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was processed
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithAutoRotatePcapWriter tests non-VoIP packet writing to auto-rotate PCAP
func TestProcessBatch_WithAutoRotatePcapWriter(t *testing.T) {
	tempDir := t.TempDir()

	// Create processor with auto-rotate PCAP writer
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
		AutoRotateConfig: &AutoRotateConfig{
			Enabled:      true,
			OutputDir:    tempDir,
			FilePattern:  "{timestamp}.pcap",
			MaxFileSize:  1024 * 1024, // 1MB
			MaxDuration:  60 * time.Second,
			MaxIdleTime:  30 * time.Second,
			MinDuration:  1 * time.Second,
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with non-VoIP packets (no SIP/RTP metadata)
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
				Metadata: &data.PacketMetadata{
					SrcIp:    "192.168.1.1",
					DstIp:    "192.168.1.2",
					Protocol: "TCP", // Non-VoIP traffic
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was counted
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithPerCallPcapWriter tests VoIP packet writing to per-call PCAP files
func TestProcessBatch_WithPerCallPcapWriter(t *testing.T) {
	tempDir := t.TempDir()

	// Create processor with per-call PCAP writer
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
		PcapWriterConfig: &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    tempDir,
			FilePattern:  "{callid}.pcap",
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with SIP packets
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 200),
				CaptureLength:  200,
				OriginalLength: 200,
				Metadata: &data.PacketMetadata{
					SrcIp:    "192.168.1.1",
					DstIp:    "192.168.1.2",
					Protocol: "UDP",
					Sip: &data.SIPMetadata{
						CallId:   "test-call@example.com",
						FromUser: "alice",
						ToUser:   "bob",
						Method:   "INVITE",
					},
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was counted
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithPerCallPcapWriter_RTPPacket tests RTP packet writing to per-call PCAP
func TestProcessBatch_WithPerCallPcapWriter_RTPPacket(t *testing.T) {
	tempDir := t.TempDir()

	// Create processor with per-call PCAP writer
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
		PcapWriterConfig: &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    tempDir,
			FilePattern:  "{callid}.pcap",
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with RTP packets (has both SIP and RTP metadata)
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 172), // RTP packet with headers
				CaptureLength:  172,
				OriginalLength: 172,
				Metadata: &data.PacketMetadata{
					SrcIp:    "192.168.1.1",
					DstIp:    "192.168.1.2",
					Protocol: "UDP",
					Sip: &data.SIPMetadata{
						CallId: "rtp-call@example.com",
					},
					Rtp: &data.RTPMetadata{
						Ssrc:        12345,
						PayloadType: 0,
						Sequence:    100,
						Timestamp:   1000,
					},
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify packet was counted
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_MixedVoIPAndNonVoIP tests processing mixed traffic types
func TestProcessBatch_MixedVoIPAndNonVoIP(t *testing.T) {
	tempDir := t.TempDir()

	// Create processor with both per-call and auto-rotate PCAP writers
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
		PcapWriterConfig: &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    tempDir + "/percall",
			FilePattern:  "{callid}.pcap",
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
		AutoRotateConfig: &AutoRotateConfig{
			Enabled:      true,
			OutputDir:    tempDir + "/autorotate",
			FilePattern:  "{timestamp}.pcap",
			MaxFileSize:  1024 * 1024,
			MaxDuration:  60 * time.Second,
			MaxIdleTime:  30 * time.Second,
			MinDuration:  1 * time.Second,
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		},
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with mixed packets
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			// SIP packet
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 200),
				CaptureLength:  200,
				OriginalLength: 200,
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   "call1@test.com",
						FromUser: "alice",
						ToUser:   "bob",
						Method:   "INVITE",
					},
				},
			},
			// Non-VoIP TCP packet
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
				Metadata: &data.PacketMetadata{
					Protocol: "TCP",
				},
			},
			// RTP packet
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 172),
				CaptureLength:  172,
				OriginalLength: 172,
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId: "call1@test.com",
					},
					Rtp: &data.RTPMetadata{
						Ssrc: 12345,
					},
				},
			},
		},
	}

	// Process the batch
	processor.processBatch(source.FromProtoBatch(batch))

	// Verify all packets were counted
	assert.Equal(t, uint64(3), processor.packetsReceived.Load())
}

// TestProcessBatch_EmptyPacketData tests handling of packets with empty data
func TestProcessBatch_EmptyPacketData(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with empty packet data
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           []byte{}, // Empty data
				CaptureLength:  0,
				OriginalLength: 0,
			},
		},
	}

	// Should not panic
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_NilMetadata tests handling of packets with nil metadata
func TestProcessBatch_NilMetadata(t *testing.T) {
	processor, err := New(Config{
		ProcessorID:     "test-processor",
		ListenAddr:      "localhost:50051",
		MaxHunters:      10,
		EnableDetection: true,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with nil metadata
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
				Metadata:       nil, // Nil metadata
			},
		},
	}

	// Should not panic
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithEnricher tests protocol detection enrichment
func TestProcessBatch_WithEnricher(t *testing.T) {
	processor, err := New(Config{
		ProcessorID:     "test-processor",
		ListenAddr:      "localhost:50051",
		MaxHunters:      10,
		EnableDetection: true, // Enables enricher
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 100),
				CaptureLength:  100,
				OriginalLength: 100,
			},
		},
	}

	// Process the batch (enricher should process)
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessBatch_WithCallCorrelator tests B2BUA call correlation
func TestProcessBatch_WithCallCorrelator(t *testing.T) {
	// Call correlator is always enabled (initialized in New)
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Verify call correlator is initialized
	require.NotNil(t, processor.callCorrelator)

	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Create batch with SIP packets for correlation
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				TimestampNs:    time.Now().UnixNano(),
				Data:           make([]byte, 200),
				CaptureLength:  200,
				OriginalLength: 200,
				Metadata: &data.PacketMetadata{
					Sip: &data.SIPMetadata{
						CallId:   "leg1@b2bua.com",
						FromUser: "alice",
						ToUser:   "bob",
						FromTag:  "tag-alice",
						ToTag:    "tag-bob",
						Method:   "INVITE",
					},
				},
			},
		},
	}

	// Process the batch (call correlator should process)
	processor.processBatch(source.FromProtoBatch(batch))

	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}

// TestProcessor_GetStats tests retrieving processor statistics
func TestProcessor_GetStats(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)
	defer processor.Shutdown()

	// Get stats (just verify it doesn't panic)
	stats := processor.GetStats()
	assert.NotNil(t, stats)
}
