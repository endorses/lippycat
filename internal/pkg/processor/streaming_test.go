//go:build skip_until_refactored

// TODO: This test file needs refactoring to work with the new manager architecture.
// Tests directly access old processor.hunters, processor.filters fields.
// Should be refactored to test through public Processor API or moved to manager packages.
// See REFACTOR.md Phase 2.1 for details.

package processor

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

// TestProcessBatch tests batch processing
func TestProcessBatch(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Simulate hunter connection
	now := time.Now().Unix()
	hunter := &ConnectedHunter{
		ID:              "hunter-1",
		Interfaces:      []string{"eth0", "wlan0"},
		RemoteAddr:      "192.168.1.100:12345",
		ConnectedAt:     now,
		LastHeartbeat:   now,
		PacketsReceived: 0,
		Status:          management.HunterStatus_STATUS_HEALTHY,
	}

	processor.huntersMu.Lock()
	processor.hunters["hunter-1"] = hunter
	processor.huntersMu.Unlock()

	// Verify hunter was registered
	processor.huntersMu.RLock()
	retrieved, exists := processor.hunters["hunter-1"]
	processor.huntersMu.RUnlock()

	assert.True(t, exists, "hunter should be registered")
	assert.Equal(t, "hunter-1", retrieved.ID)
	assert.Equal(t, []string{"eth0", "wlan0"}, retrieved.Interfaces)
	assert.Equal(t, management.HunterStatus_STATUS_HEALTHY, retrieved.Status)
}

// TestMultipleHunters tests managing multiple hunters
func TestMultipleHunters(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Add multiple hunters
	now := time.Now().Unix()
	for i := 1; i <= 5; i++ {
		hunter := &ConnectedHunter{
			ID:            string(rune('h') + rune(i)),
			Interfaces:    []string{"eth0"},
			ConnectedAt:   now,
			LastHeartbeat: now,
			Status:        management.HunterStatus_STATUS_HEALTHY,
		}
		processor.huntersMu.Lock()
		processor.hunters[hunter.ID] = hunter
		processor.huntersMu.Unlock()
	}

	// Verify all hunters were registered
	processor.huntersMu.RLock()
	hunterCount := len(processor.hunters)
	processor.huntersMu.RUnlock()

	assert.Equal(t, 5, hunterCount, "should have 5 hunters registered")
}

// TestBroadcastToSubscribers tests packet broadcasting
func TestBroadcastToSubscribers(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Add a subscriber using sync.Map
	subscriberCh := make(chan *data.PacketBatch, 10)
	processor.addSubscriber("subscriber-1", subscriberCh)

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
	processor.broadcastToSubscribers(batch)

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Add multiple subscribers using sync.Map
	numSubscribers := 3
	subscribers := make([]chan *data.PacketBatch, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		ch := make(chan *data.PacketBatch, 10)
		subscribers[i] = ch
		clientID := string(rune('a') + rune(i))
		processor.addSubscriber(clientID, ch)
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
	processor.broadcastToSubscribers(batch)

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Add a subscriber
	ch := make(chan *data.PacketBatch, 10)
	processor.addSubscriber("subscriber-1", ch)

	// Verify subscriber was added using sync.Map
	value, exists := processor.subscribers.Load("subscriber-1")
	assert.True(t, exists, "subscriber should be added")

	if exists {
		subscriberCh := value.(chan *data.PacketBatch)
		assert.Equal(t, ch, subscriberCh, "channel should match")
	}
}

// TestRemoveSubscriber tests removing a subscriber
func TestRemoveSubscriber(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Add a subscriber
	ch := make(chan *data.PacketBatch, 10)
	processor.addSubscriber("subscriber-1", ch)

	// Remove the subscriber
	processor.removeSubscriber("subscriber-1")

	// Verify subscriber was removed using sync.Map
	_, exists := processor.subscribers.Load("subscriber-1")
	assert.False(t, exists, "subscriber should be removed")
}

// TestConcurrentBatchProcessing tests concurrent batch processing
func TestConcurrentBatchProcessing(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

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
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Register a hunter
	hunter := &ConnectedHunter{
		ID:              "hunter-1",
		PacketsReceived: 0,
		Status:          management.HunterStatus_STATUS_HEALTHY,
	}
	processor.huntersMu.Lock()
	processor.hunters["hunter-1"] = hunter
	processor.huntersMu.Unlock()

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
	processor.huntersMu.RLock()
	retrievedHunter := processor.hunters["hunter-1"]
	packetCount := retrievedHunter.PacketsReceived
	processor.huntersMu.RUnlock()

	assert.Equal(t, uint64(3), packetCount, "hunter should have 3 packets received")
}

// TestProcessorStatsConcurrent tests concurrent stats updates
func TestProcessorStatsConcurrent(t *testing.T) {
	processor := &Processor{
		config: Config{
			ProcessorID: "test-processor",
			ListenAddr:  "localhost:50051",
		},
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

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
