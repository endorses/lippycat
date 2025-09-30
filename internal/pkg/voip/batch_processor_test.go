package voip

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultBatchConfig(t *testing.T) {
	config := DefaultBatchConfig()

	assert.Equal(t, 64, config.BatchSize)
	assert.Equal(t, 4, config.NumWorkers)
	assert.Equal(t, 100*time.Millisecond, config.FlushInterval)
	assert.True(t, config.EnablePrefetch)
	assert.True(t, config.WorkerAffinity)
}

func TestNewBatchProcessor(t *testing.T) {
	config := DefaultBatchConfig()
	config.NumWorkers = 2
	config.WorkerAffinity = false // Disable affinity in tests

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)
	defer bp.Stop()

	assert.Equal(t, config.NumWorkers, len(bp.workers))
	assert.NotNil(t, bp.inputQueue)
	assert.NotNil(t, bp.resultQueue)
}

func TestBatchProcessor_SubmitBatch(t *testing.T) {
	config := DefaultBatchConfig()
	config.NumWorkers = 2
	config.WorkerAffinity = false

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)
	defer bp.Stop()

	// Create a test batch
	batch := &PacketBatch{
		Packets:  make([]*PacketBuffer, 2),
		Metadata: make([]PacketMetadata, 2),
		Count:    2,
	}

	// Fill with test packets
	for i := 0; i < 2; i++ {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte("test packet data")
		batch.Packets[i] = pkt
		batch.Metadata[i] = PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(pkt.Data),
				Length:        len(pkt.Data),
			},
			Index: i,
		}
	}

	// Submit batch
	err := bp.SubmitBatch(batch)
	assert.NoError(t, err)

	// Wait briefly for processing
	time.Sleep(50 * time.Millisecond)

	// Check stats
	stats := bp.GetStats()
	assert.Greater(t, stats.TotalBatches.Get(), uint64(0))
}

func TestBatchProcessor_Stop(t *testing.T) {
	config := DefaultBatchConfig()
	config.NumWorkers = 2
	config.WorkerAffinity = false

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)

	assert.True(t, bp.running.Load())

	bp.Stop()

	assert.False(t, bp.running.Load())

	// Submitting after stop should fail
	batch := &PacketBatch{Count: 0}
	err := bp.SubmitBatch(batch)
	assert.Error(t, err)
}

func TestBatchProcessor_GetWorkerStats(t *testing.T) {
	config := DefaultBatchConfig()
	config.NumWorkers = 2
	config.WorkerAffinity = false

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)
	defer bp.Stop()

	// Get stats for each worker
	for i := 0; i < config.NumWorkers; i++ {
		stats := bp.GetWorkerStats(i)
		assert.NotNil(t, stats)
	}

	// Invalid worker ID
	stats := bp.GetWorkerStats(999)
	assert.Nil(t, stats)
}

func TestVectorizedCallIDExtractor(t *testing.T) {
	ve := NewVectorizedCallIDExtractor(4)

	tests := []struct {
		name     string
		packets  [][]byte
		expected int
	}{
		{
			name: "empty packets",
			packets: [][]byte{
				[]byte("test without call-id"),
			},
			expected: 0,
		},
		{
			name: "packets with Call-ID",
			packets: [][]byte{
				[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123\r\n"),
				[]byte("200 OK\r\nCall-ID: xyz789\r\n"),
			},
			expected: 2,
		},
		{
			name: "short form Call-ID",
			packets: [][]byte{
				[]byte("INVITE sip:bob@example.com SIP/2.0\r\ni: shortform123\r\n"),
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callIDs := ve.ExtractCallIDs(tt.packets)
			assert.Equal(t, tt.expected, len(callIDs))
		})
	}
}

func TestExtractCallIDFast(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "standard Call-ID",
			data:     []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123@host\r\n"),
			expected: "abc123@host",
		},
		{
			name:     "short form",
			data:     []byte("INVITE sip:bob@example.com SIP/2.0\r\ni: xyz789\r\n"),
			expected: "xyz789",
		},
		{
			name:     "with whitespace",
			data:     []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID:   padded123  \r\n"),
			expected: "padded123",
		},
		{
			name:     "no Call-ID",
			data:     []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: alice\r\n"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCallIDFast(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBatchCollector(t *testing.T) {
	config := DefaultBatchConfig()
	config.BatchSize = 4
	config.FlushInterval = 500 * time.Millisecond
	config.WorkerAffinity = false

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)
	defer bp.Stop()

	bc := NewBatchCollector(config, bp)
	require.NotNil(t, bc)

	// Add packets
	for i := 0; i < 3; i++ {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte("test packet")

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(pkt.Data),
			Length:        len(pkt.Data),
		}

		bc.Add(pkt, ci, uint32(i))
	}

	// Should not have flushed yet (batch size = 4)
	assert.Equal(t, 3, bc.currentBatch.Count)

	// Add one more to trigger flush
	pkt := GetPacketPool().Get()
	pkt.Data = []byte("test packet")
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}
	bc.Add(pkt, ci, 999)

	// Should have flushed
	assert.Equal(t, 0, bc.currentBatch.Count)
}

func TestBatchCollector_FlushTimer(t *testing.T) {
	config := DefaultBatchConfig()
	config.BatchSize = 100
	config.FlushInterval = 100 * time.Millisecond
	config.WorkerAffinity = false

	bp := NewBatchProcessor(config)
	require.NotNil(t, bp)
	defer bp.Stop()

	bc := NewBatchCollector(config, bp)
	require.NotNil(t, bc)

	// Add a few packets (less than batch size)
	for i := 0; i < 3; i++ {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte("test packet")

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(pkt.Data),
			Length:        len(pkt.Data),
		}

		bc.Add(pkt, ci, uint32(i))
	}

	// Should have packets waiting
	assert.Equal(t, 3, bc.currentBatch.Count)

	// Wait for flush timer
	time.Sleep(200 * time.Millisecond)

	// Should have flushed by timer
	assert.Equal(t, 0, bc.currentBatch.Count)
}

// Benchmarks

func BenchmarkBatchProcessor_SubmitBatch(b *testing.B) {
	config := DefaultBatchConfig()
	config.WorkerAffinity = false
	bp := NewBatchProcessor(config)
	defer bp.Stop()

	// Consume results in background to prevent queue blocking
	go func() {
		for range bp.GetResults() {
			// Discard results
		}
	}()

	// Create a single test batch to reuse
	batch := &PacketBatch{
		Packets:  make([]*PacketBuffer, config.BatchSize),
		Metadata: make([]PacketMetadata, config.BatchSize),
		Count:    config.BatchSize,
	}

	for i := 0; i < config.BatchSize; i++ {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte("test packet data for benchmarking")
		batch.Packets[i] = pkt
		batch.Metadata[i] = PacketMetadata{
			CaptureInfo: gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(pkt.Data),
				Length:        len(pkt.Data),
			},
			Index: i,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		bp.SubmitBatch(batch)
	}
}

func BenchmarkVectorizedCallIDExtractor(b *testing.B) {
	ve := NewVectorizedCallIDExtractor(8)

	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123@host.example.com\r\nFrom: alice\r\n")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ve.ExtractCallIDs(packets)
	}
}

func BenchmarkExtractCallIDFast(b *testing.B) {
	data := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123@host.example.com\r\nFrom: alice\r\n")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractCallIDFast(data)
	}
}

func BenchmarkBatchCollector_Add(b *testing.B) {
	config := DefaultBatchConfig()
	config.WorkerAffinity = false
	bp := NewBatchProcessor(config)
	defer bp.Stop()

	bc := NewBatchCollector(config, bp)

	pkt := GetPacketPool().Get()
	pkt.Data = []byte("test packet")

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data),
		Length:        len(pkt.Data),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		bc.Add(pkt, ci, uint32(i))
	}
}

func BenchmarkBatchProcessing_EndToEnd(b *testing.B) {
	config := DefaultBatchConfig()
	config.BatchSize = 64
	config.WorkerAffinity = false
	bp := NewBatchProcessor(config)
	defer bp.Stop()

	// Consume results in background
	go func() {
		for range bp.GetResults() {
			// Discard results
		}
	}()

	bc := NewBatchCollector(config, bp)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: bench123\r\n")

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(pkt.Data),
			Length:        len(pkt.Data),
		}

		bc.Add(pkt, ci, uint32(i))
	}
}