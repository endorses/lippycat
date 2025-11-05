package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

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

				processor.processBatch(batch)
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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

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
	processor.processBatch(batch)

	// Verify packet was processed
	assert.Equal(t, uint64(1), processor.packetsReceived.Load())
}
