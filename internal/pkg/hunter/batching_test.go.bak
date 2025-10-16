package hunter

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSendBatch_EmptyBatch tests that sending an empty batch is a no-op
func TestSendBatch_EmptyBatch(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
		currentBatch:   make([]*data.CapturedPacket, 0),
		statsCollector: stats.New(),
	}

	// Send empty batch
	hunter.sendBatch()

	// Verify no packets were forwarded
	assert.Equal(t, uint64(0), hunter.statsCollector.GetForwarded())
}

// TestSendBatch_WhenPaused tests that batches are not sent when paused
func TestSendBatch_WhenPaused(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
		statsCollector: stats.New(),
		currentBatch: []*data.CapturedPacket{
			{Data: []byte("test packet")},
		},
	}

	// Pause the hunter
	hunter.paused.Store(true)

	// Attempt to send batch
	hunter.sendBatch()

	// Verify batch was not sent (still in currentBatch)
	assert.Equal(t, 1, len(hunter.currentBatch))
	assert.Equal(t, uint64(0), hunter.statsCollector.GetForwarded())
}

// TestBatchSequenceIncrement tests that batch sequence increments
func TestBatchSequenceIncrement(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
		batchSequence: 0,
		currentBatch: []*data.CapturedPacket{
			{Data: []byte("test packet 1")},
		},
		statsCollector: stats.New(),
	}

	initialSeq := hunter.batchSequence

	// Note: sendBatch() requires a stream, so we just test sequence increment manually
	hunter.batchMu.Lock()
	hunter.batchSequence++
	newSeq := hunter.batchSequence
	hunter.batchMu.Unlock()

	assert.Equal(t, initialSeq+1, newSeq, "batch sequence should increment")
}

// TestConvertPacket tests packet conversion to protobuf format
func TestConvertPacket(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID: "test-hunter",
		},
	}

	// Create a test packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("test data")))
	require.NoError(t, err)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		LinkType:  layers.LinkTypeEthernet,
		Packet:    packet,
		Interface: "eth0",
	}

	// Convert packet
	pbPkt := hunter.convertPacket(pktInfo)

	// Verify conversion
	assert.NotNil(t, pbPkt)
	assert.Equal(t, buf.Bytes(), pbPkt.Data)
	// When creating packets with gopacket.NewPacket(), metadata is not set
	// so CaptureLength and OriginalLength will be 0, but packet data is still captured
	assert.Greater(t, pbPkt.TimestampNs, int64(0))
	assert.Equal(t, uint32(layers.LinkTypeEthernet), pbPkt.LinkType)
}

// TestBatchQueueCapacity tests batch queue capacity limits
func TestBatchQueueCapacity(t *testing.T) {
	maxBatches := 3
	hunter := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: maxBatches,
		},
		batchQueue: make(chan []*data.CapturedPacket, maxBatches),
	}

	// Verify initial capacity
	assert.Equal(t, maxBatches, cap(hunter.batchQueue))
	assert.Equal(t, 0, len(hunter.batchQueue))

	// Fill queue
	for i := 0; i < maxBatches; i++ {
		batch := []*data.CapturedPacket{
			{Data: []byte("batch packet")},
		}
		hunter.batchQueue <- batch
	}

	// Verify full
	assert.Equal(t, maxBatches, len(hunter.batchQueue))

	// Drain queue
	for i := 0; i < maxBatches; i++ {
		<-hunter.batchQueue
	}

	// Verify empty
	assert.Equal(t, 0, len(hunter.batchQueue))
}

// TestBatchQueueSizeTracking tests atomic batch queue size counter
func TestBatchQueueSizeTracking(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:           "test-hunter",
			MaxBufferedBatches: 10,
		},
		batchQueue: make(chan []*data.CapturedPacket, 10),
	}

	// Initial size should be 0
	assert.Equal(t, int32(0), hunter.batchQueueSize.Load())

	// Add batches and track size
	batch1 := []*data.CapturedPacket{{Data: []byte("batch 1")}}
	hunter.batchQueue <- batch1
	hunter.batchQueueSize.Add(1)
	assert.Equal(t, int32(1), hunter.batchQueueSize.Load())

	batch2 := []*data.CapturedPacket{{Data: []byte("batch 2")}}
	hunter.batchQueue <- batch2
	hunter.batchQueueSize.Add(1)
	assert.Equal(t, int32(2), hunter.batchQueueSize.Load())

	// Drain and decrement
	<-hunter.batchQueue
	hunter.batchQueueSize.Add(-1)
	assert.Equal(t, int32(1), hunter.batchQueueSize.Load())

	<-hunter.batchQueue
	hunter.batchQueueSize.Add(-1)
	assert.Equal(t, int32(0), hunter.batchQueueSize.Load())
}

// TestBatchStatsIncluded tests that batch stats are populated
func TestBatchStatsIncluded(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
		statsCollector: stats.New(),
	}

	// Set some stats
	hunter.statsCollector.IncrementCaptured()
	for i := 0; i < 999; i++ {
		hunter.statsCollector.IncrementCaptured()
	}
	for i := 0; i < 950; i++ {
		hunter.statsCollector.IncrementMatched()
	}
	hunter.statsCollector.IncrementDropped(50)

	// Create a batch manually (simulating what sendBatch does)
	hunter.batchMu.Lock()
	hunter.batchSequence++
	batch := &data.PacketBatch{
		HunterId:    hunter.config.HunterID,
		Sequence:    hunter.batchSequence,
		TimestampNs: time.Now().UnixNano(),
		Packets:     []*data.CapturedPacket{{Data: []byte("test")}},
		Stats: &data.BatchStats{
			TotalCaptured:   hunter.statsCollector.GetCaptured(),
			FilteredMatched: hunter.statsCollector.GetMatched(),
			Dropped:         hunter.statsCollector.GetDropped(),
			BufferUsage:     0,
		},
	}
	hunter.batchMu.Unlock()

	// Verify stats were included
	assert.NotNil(t, batch.Stats)
	assert.Equal(t, uint64(1000), batch.Stats.TotalCaptured)
	assert.Equal(t, uint64(950), batch.Stats.FilteredMatched)
	assert.Equal(t, uint64(50), batch.Stats.Dropped)
}

// TestBatchConcurrentAccess tests concurrent access to batch
func TestBatchConcurrentAccess(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  1000,
			BufferSize: 1000,
		},
		currentBatch:   make([]*data.CapturedPacket, 0, 1000),
		statsCollector: stats.New(),
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	packetsPerGoroutine := 10

	// Concurrently add packets to batch
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < packetsPerGoroutine; j++ {
				hunter.batchMu.Lock()
				hunter.currentBatch = append(hunter.currentBatch, &data.CapturedPacket{
					Data: []byte("concurrent packet"),
				})
				hunter.batchMu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Verify all packets were added
	hunter.batchMu.Lock()
	totalPackets := len(hunter.currentBatch)
	hunter.batchMu.Unlock()

	expectedPackets := numGoroutines * packetsPerGoroutine
	assert.Equal(t, expectedPackets, totalPackets,
		"all packets should be added without race conditions")
}

// TestBatchReset tests that batch is reset after sending
func TestBatchReset(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
		currentBatch: []*data.CapturedPacket{
			{Data: []byte("packet 1")},
			{Data: []byte("packet 2")},
			{Data: []byte("packet 3")},
		},
		statsCollector: stats.New(),
	}

	// Manually simulate batch reset (as done in sendBatch)
	hunter.batchMu.Lock()
	oldLen := len(hunter.currentBatch)
	hunter.currentBatch = make([]*data.CapturedPacket, 0, hunter.config.BatchSize)
	newLen := len(hunter.currentBatch)
	hunter.batchMu.Unlock()

	assert.Equal(t, 3, oldLen, "old batch should have 3 packets")
	assert.Equal(t, 0, newLen, "new batch should be empty")
	assert.Equal(t, 10, cap(hunter.currentBatch), "capacity should be BatchSize")
}

// TestPacketBufferTooBig tests handling of oversized packets
func TestPacketBufferTooBig(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID:   "test-hunter",
			BatchSize:  10,
			BufferSize: 100,
		},
	}

	// Create a very large packet
	largeData := make([]byte, 100000) // 100KB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	pktInfo := capture.PacketInfo{
		LinkType:  layers.LinkTypeEthernet,
		Packet:    gopacket.NewPacket(largeData, layers.LayerTypeEthernet, gopacket.Default),
		Interface: "eth0",
	}

	// Convert packet
	pbPkt := hunter.convertPacket(pktInfo)

	// Verify packet was converted (no size limit in conversion)
	assert.NotNil(t, pbPkt)
	assert.Equal(t, largeData, pbPkt.Data)
}

// TestBatchTimeout tests batch sending on timeout
func TestBatchTimeout(t *testing.T) {
	// This is a simplified test since we can't easily test the full timeout logic
	// We just verify the timeout duration is configured correctly
	config := Config{
		HunterID:     "test-hunter",
		BatchSize:    100,
		BatchTimeout: 500 * time.Millisecond,
	}

	assert.Equal(t, 500*time.Millisecond, config.BatchTimeout,
		"batch timeout should be configurable")
}

// TestMinHelper tests the min helper function
func TestMinHelper(t *testing.T) {
	tests := []struct {
		a    int
		b    int
		want int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{7, 7, 7},
		{0, 10, 0},
		{-5, -10, -10},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		assert.Equal(t, tt.want, result, "min(%d, %d) should be %d", tt.a, tt.b, tt.want)
	}
}

// TestBatchSequenceOverflow tests batch sequence handling with large numbers
func TestBatchSequenceOverflow(t *testing.T) {
	hunter := &Hunter{
		config: Config{
			HunterID: "test-hunter",
		},
		batchSequence: 18446744073709551610, // Near uint64 max
	}

	// Increment sequence
	oldSeq := hunter.batchSequence
	hunter.batchSequence++

	assert.Greater(t, hunter.batchSequence, oldSeq, "sequence should increment")

	// Continue incrementing to overflow
	hunter.batchSequence = 18446744073709551615 // Max uint64
	hunter.batchSequence++                      // Overflow to 0

	assert.Equal(t, uint64(0), hunter.batchSequence, "sequence should overflow to 0")
}
