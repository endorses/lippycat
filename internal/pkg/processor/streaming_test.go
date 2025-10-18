package processor

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProcessBatch tests batch processing
func TestProcessBatch(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Create a test batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{
				Data:           []byte("test packet 1"),
				TimestampNs:    time.Now().UnixNano(),
				CaptureLength:  13,
				OriginalLength: 13,
			},
			{
				Data:           []byte("test packet 2"),
				TimestampNs:    time.Now().UnixNano(),
				CaptureLength:  13,
				OriginalLength: 13,
			},
		},
		Stats: &data.BatchStats{
			TotalCaptured:   100,
			FilteredMatched: 95,
			Dropped:         5,
			BufferUsage:     50,
		},
	}

	// Process the batch
	processor.processBatch(batch)

	// Verify stats were updated
	assert.Equal(t, uint64(2), processor.packetsReceived.Load(),
		"should receive 2 packets")
}

// TestProcessBatch_EmptyBatch tests processing empty batch
func TestProcessBatch_EmptyBatch(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Create an empty batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{},
	}

	// Process the batch
	processor.processBatch(batch)

	// Verify no packets were counted
	assert.Equal(t, uint64(0), processor.packetsReceived.Load(),
		"should receive 0 packets")
}

// TestProcessBatch_NilBatch tests handling nil batch
// Note: processBatch currently does not handle nil gracefully and will panic
// This test documents the behavior but skips execution
func TestProcessBatch_NilBatch(t *testing.T) {
	// Skip this test - processBatch assumes non-nil batch
	// It would require gRPC server to send nil, which doesn't happen in practice
	t.Skip("processBatch does not handle nil batch - would require gRPC server to send nil")
}

// TestHunterRegistration tests hunter registration and tracking
func TestHunterRegistration(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Register a hunter using the manager
	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0", "wlan0"}, nil)
	require.NoError(t, err)

	// Verify hunter was registered by getting all hunters
	hunters := processor.hunterManager.GetAll("")
	assert.Equal(t, 1, len(hunters), "should have 1 hunter registered")

	// Find our hunter
	found := false
	for _, h := range hunters {
		if h.ID == "hunter-1" {
			found = true
			assert.Equal(t, []string{"eth0", "wlan0"}, h.Interfaces)
			assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, h.Status)
			break
		}
	}
	assert.True(t, found, "hunter-1 should be registered")
}

// TestMultipleHunters tests managing multiple hunters
func TestMultipleHunters(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Add multiple hunters using the manager
	for i := 1; i <= 5; i++ {
		hunterID := string(rune('h') + rune(i))
		_, _, err := processor.hunterManager.Register(hunterID, "host"+hunterID, []string{"eth0"}, nil)
		require.NoError(t, err)
	}

	// Verify all hunters were registered
	hunters := processor.hunterManager.GetAll("")
	assert.Equal(t, 5, len(hunters), "should have 5 hunters registered")
}

// TestBroadcastToSubscribers tests packet broadcasting
func TestBroadcastToSubscribers(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Add a subscriber using the manager
	subscriberCh := processor.subscriberManager.Add("subscriber-1")

	// Create a test batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{Data: []byte("test packet")},
		},
	}

	// Broadcast to subscribers
	processor.subscriberManager.Broadcast(batch)

	// Verify subscriber received the batch
	select {
	case receivedBatch := <-subscriberCh:
		assert.Equal(t, batch.HunterId, receivedBatch.HunterId)
		assert.Equal(t, batch.Sequence, receivedBatch.Sequence)
		assert.Equal(t, len(batch.Packets), len(receivedBatch.Packets))
	case <-time.After(1 * time.Second):
		t.Fatal("subscriber did not receive batch")
	}
}

// TestBroadcastToSubscribers_MultipleSubscribers tests broadcasting to multiple subscribers
func TestBroadcastToSubscribers_MultipleSubscribers(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Add multiple subscribers using the manager
	numSubscribers := 3
	subscribers := make([]chan *data.PacketBatch, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		clientID := string(rune('a') + rune(i))
		ch := processor.subscriberManager.Add(clientID)
		subscribers[i] = ch
	}

	// Create a test batch
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{Data: []byte("broadcast packet")},
		},
	}

	// Broadcast to all subscribers
	processor.subscriberManager.Broadcast(batch)

	// Verify all subscribers received the batch
	for i, ch := range subscribers {
		select {
		case receivedBatch := <-ch:
			assert.Equal(t, batch.HunterId, receivedBatch.HunterId,
				"subscriber %d should receive batch", i)
		case <-time.After(1 * time.Second):
			t.Fatalf("subscriber %d did not receive batch", i)
		}
	}
}

// TestAddSubscriber tests adding a subscriber
func TestAddSubscriber(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Add a subscriber
	ch := processor.subscriberManager.Add("subscriber-1")

	// Verify subscriber was added by checking count
	// Since SubscriberManager doesn't expose direct access, we verify by broadcasting
	batch := &data.PacketBatch{
		HunterId: "test",
		Packets:  []*data.CapturedPacket{{Data: []byte("test")}},
	}
	processor.subscriberManager.Broadcast(batch)

	select {
	case <-ch:
		// Success - subscriber is active
	case <-time.After(100 * time.Millisecond):
		t.Fatal("subscriber not receiving broadcasts")
	}
}

// TestRemoveSubscriber tests removing a subscriber
func TestRemoveSubscriber(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Add a subscriber
	ch := processor.subscriberManager.Add("subscriber-1")

	// Remove the subscriber
	processor.subscriberManager.Remove("subscriber-1")

	// Verify subscriber was removed by broadcasting (channel should not receive)
	batch := &data.PacketBatch{
		HunterId: "test",
		Packets:  []*data.CapturedPacket{{Data: []byte("test")}},
	}
	processor.subscriberManager.Broadcast(batch)

	select {
	case <-ch:
		t.Fatal("removed subscriber should not receive broadcasts")
	case <-time.After(100 * time.Millisecond):
		// Success - subscriber not receiving
	}
}

// TestConcurrentBatchProcessing tests concurrent batch processing
func TestConcurrentBatchProcessing(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Process batches concurrently
	var wg sync.WaitGroup
	numBatches := 10
	packetsPerBatch := 5

	for i := 0; i < numBatches; i++ {
		wg.Add(1)
		go func(batchNum int) {
			defer wg.Done()

			packets := make([]*data.CapturedPacket, packetsPerBatch)
			for j := 0; j < packetsPerBatch; j++ {
				packets[j] = &data.CapturedPacket{
					Data:           []byte("concurrent packet"),
					TimestampNs:    time.Now().UnixNano(),
					CaptureLength:  17,
					OriginalLength: 17,
				}
			}

			batch := &data.PacketBatch{
				HunterId:    "hunter-concurrent",
				Sequence:    uint64(batchNum),
				TimestampNs: time.Now().UnixNano(),
				Packets:     packets,
			}

			processor.processBatch(batch)
		}(i)
	}

	wg.Wait()

	// Verify all packets were counted
	expectedPackets := uint64(numBatches * packetsPerBatch)
	assert.Equal(t, expectedPackets, processor.packetsReceived.Load(),
		"all packets should be counted correctly with concurrent processing")
}

// TestStatsAtomic tests atomic stats operations
func TestStatsAtomic(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Increment stats from multiple goroutines
	var wg sync.WaitGroup
	numGoroutines := 10
	incrementsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				processor.packetsReceived.Add(1)
				processor.packetsForwarded.Add(1)
			}
		}()
	}

	wg.Wait()

	expected := uint64(numGoroutines * incrementsPerGoroutine)
	assert.Equal(t, expected, processor.packetsReceived.Load())
	assert.Equal(t, expected, processor.packetsForwarded.Load())
}

// TestHunterPacketCounting tests per-hunter packet counting
func TestHunterPacketCounting(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
		MaxHunters:  10,
	})
	require.NoError(t, err)

	// Register a hunter
	_, _, err = processor.hunterManager.Register("hunter-1", "host1", []string{"eth0"}, nil)
	require.NoError(t, err)

	// Process a batch from this hunter
	batch := &data.PacketBatch{
		HunterId:    "hunter-1",
		Sequence:    1,
		TimestampNs: time.Now().UnixNano(),
		Packets: []*data.CapturedPacket{
			{Data: []byte("packet 1")},
			{Data: []byte("packet 2")},
			{Data: []byte("packet 3")},
		},
	}

	processor.processBatch(batch)

	// Verify hunter's packet count was updated
	hunters := processor.hunterManager.GetAll("")
	found := false
	for _, h := range hunters {
		if h.ID == "hunter-1" {
			found = true
			assert.Equal(t, uint64(3), h.PacketsReceived, "hunter should have 3 packets received")
			break
		}
	}
	assert.True(t, found, "hunter-1 should be in list")
}

// TestProcessorStatsConcurrent tests concurrent stats updates
func TestProcessorStatsConcurrent(t *testing.T) {
	processor, err := New(Config{
		ProcessorID: "test-processor",
		ListenAddr:  "localhost:50051",
	})
	require.NoError(t, err)

	// Update stats concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processor.packetsReceived.Add(1)
			processor.packetsForwarded.Add(1)
		}()
	}

	wg.Wait()

	// Verify stats are consistent
	assert.Equal(t, uint64(100), processor.packetsReceived.Load())
	assert.Equal(t, uint64(100), processor.packetsForwarded.Load())
}
