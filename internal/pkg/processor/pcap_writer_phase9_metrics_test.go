//go:build processor || tap || all

package processor

import (
	"container/heap"
	"github.com/endorses/lippycat/api/gen/management"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPhase9RotatedSIPAndRTPFilesAreValidAndCallbacksOrdered(t *testing.T) {
	var eventsMu sync.Mutex
	var events []string
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.MaxFileSize = 1
		config.OnFileClose = func(path string) {
			eventsMu.Lock()
			events = append(events, filepath.Base(path))
			eventsMu.Unlock()
		}
		config.OnCallComplete = func(CallMetadata) {
			eventsMu.Lock()
			events = append(events, "complete")
			eventsMu.Unlock()
		}
	})
	const callID = "rotation-validity"
	for _, name := range []string{
		callID + "_sip.pcap", callID + "_sip_1.pcap",
		callID + "_rtp.pcap", callID + "_rtp_1.pcap",
	} {
		writeTestPCAP(t, filepath.Join(manager.config.OutputDir, name), []byte("prior-generation"))
	}
	for _, isRTP := range []bool{false, true} {
		require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, isRTP))
		require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte{2}, layers.LinkTypeEthernet, isRTP))
	}
	_, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(manager.config.OutputDir, callID+"_*.pcap"))
	require.NoError(t, err)
	require.Len(t, files, 8)
	for _, path := range files {
		file, openErr := os.Open(path)
		require.NoError(t, openErr)
		reader, readErr := pcapgo.NewReader(file)
		require.NoError(t, readErr)
		_, _, readErr = reader.ReadPacketData()
		require.NoError(t, readErr)
		_, _, readErr = reader.ReadPacketData()
		assert.ErrorIs(t, readErr, io.EOF)
		require.NoError(t, file.Close())
	}
	eventsMu.Lock()
	require.Len(t, events, 5)
	assert.Equal(t, "complete", events[len(events)-1])
	assert.Contains(t, events[0], "_sip")
	assert.Contains(t, events[1], "_rtp")
	eventsMu.Unlock()
	assert.GreaterOrEqual(t, manager.Telemetry().FilenameCollisions, uint64(4))
}

func TestPhase9TelemetryAccountsForLifecyclePressure(t *testing.T) {
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.MaxWriters = 1
		config.OnCallComplete = func(CallMetadata) { panic("completion failure") }
	})
	manager.tombstoneLimit = 2
	assert.Equal(t, uint64(0), manager.Telemetry().ActiveWriters)
	require.NoError(t, manager.WritePacket("capacity", "a", "b", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))
	assert.Equal(t, uint64(1), manager.Telemetry().ActiveWriters)
	require.NoError(t, manager.WritePacket("protocol", "c", "d", time.Now(), []byte{2}, layers.LinkTypeEthernet, false))
	_, err := manager.FinalizeCall("protocol", CallFinalizationProtocolComplete)
	require.NoError(t, err)

	// Reuse an expired Call-ID to exercise collision-safe admission telemetry.
	manager.mu.Lock()
	manager.tombstoneTTL = time.Nanosecond
	manager.mu.Unlock()
	time.Sleep(time.Nanosecond)
	require.NoError(t, manager.WritePacket("protocol", "e", "f", time.Now(), []byte{3}, layers.LinkTypeEthernet, false))
	manager.mu.Lock()
	manager.tombstoneTTL = completedCallTombstoneTTL
	manager.mu.Unlock()
	_, err = manager.FinalizeCall("protocol", CallFinalizationManual)
	require.NoError(t, err)
	require.NoError(t, manager.WritePacket("idle", "g", "h", time.Now(), []byte{4}, layers.LinkTypeEthernet, false))
	manager.mu.RLock()
	idleWriter := manager.writers["idle"]
	manager.mu.RUnlock()
	idleWriter.mu.Lock()
	idleWriter.lastWrite = time.Now().Add(-time.Hour)
	idleWriter.mu.Unlock()
	require.Equal(t, 1, manager.SweepIdle(time.Minute))
	assert.True(t, IsCallFinalized(manager.WritePacket("idle", "g", "h", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)))

	got := manager.Telemetry()
	assert.Equal(t, uint64(1), got.ActiveWriters)
	assert.LessOrEqual(t, got.Tombstones, uint64(2))
	assert.Equal(t, uint64(1), got.ProtocolFinalizations)
	assert.Zero(t, got.CapacityFinalizations)
	assert.Equal(t, uint64(1), got.ManualFinalizations)
	assert.Equal(t, uint64(1), got.IdleFinalizations)
	assert.Equal(t, uint64(1), got.SuppressedLatePackets)
	assert.GreaterOrEqual(t, got.FilenameCollisions, uint64(1))
	assert.Equal(t, uint64(2), got.CallbackFailures)
	assert.Zero(t, got.TombstoneCapacityEvictions)
}

func TestPhase9ProcessorHeartbeatTelemetryMappingAndSerialization(t *testing.T) {
	writer := newPhase8Manager(t, nil)
	require.NoError(t, writer.WritePacket("active", "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false))
	processor := &Processor{sessionOutputManager: newSessionOutputManager(writer, nil)}
	heartbeat := &management.ProcessorHeartbeat{PcapWriter: processor.pcapWriterTelemetryProto()}
	wire, err := proto.Marshal(heartbeat)
	require.NoError(t, err)
	var decoded management.ProcessorHeartbeat
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.NotNil(t, decoded.PcapWriter)
	assert.Equal(t, uint64(1), decoded.PcapWriter.ActiveWriters)
}

func TestPhase9TombstoneLookupAllocationsAreCardinalityIndependent(t *testing.T) {
	for _, size := range []int{10, 1_000, 100_000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			manager := newTombstoneTestManager(size)
			seedTombstones(manager, size, time.Now())
			allocs := testing.AllocsPerRun(100, func() { _ = manager.IsFinalized("absent") })
			assert.Zero(t, allocs)
		})
	}
}

func TestPhase9FinalizeErrorsKeepContextAndTerminalState(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	const callID = "close-error-context"
	require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false))

	manager.mu.RLock()
	writer := manager.writers[callID]
	manager.mu.RUnlock()
	writer.mu.Lock()
	path := writer.sipFilePath
	require.NoError(t, writer.sipFile.Close())
	writer.mu.Unlock()

	result, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	require.Error(t, err)
	assert.True(t, result.Finalized)
	assert.True(t, manager.IsFinalized(callID))
	assert.Contains(t, err.Error(), callID)
	assert.Contains(t, err.Error(), path)
	lateErr := manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
	assert.True(t, IsCallFinalized(lateErr))
}

func TestPhase9CreateAndCleanupFailuresPreserveTerminalBookkeeping(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "output")
	manager, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled: true, OutputDir: dir, FilePattern: "{callid}.pcap", SyncInterval: time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, os.Rename(dir, dir+"-moved"))
	require.NoError(t, os.WriteFile(dir, []byte("not a directory"), 0o600))
	err = manager.WritePacket("blocked", "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
	assert.Contains(t, err.Error(), "create SIP PCAP")

	manager.SetBeforeFinalize(func(string, CallFinalizationReason) { panic("endpoint cleanup failure") })
	result, err := manager.FinalizeCall("blocked", CallFinalizationProtocolComplete)
	require.NoError(t, err)
	assert.True(t, result.Finalized)
	assert.True(t, manager.IsFinalized("blocked"))
	assert.Equal(t, uint64(1), manager.Telemetry().CallbackFailures)
	assert.True(t, IsCallFinalized(manager.WritePacket("blocked", "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)))
	require.NoError(t, manager.Close())
}

func TestPhase9ConcurrentWriteFinalizeCreateAndSweep(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	const callID = "all-lifecycle-operations"
	require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("initial"), layers.LinkTypeEthernet, false))

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 50 {
				err := manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false)
				if err != nil && !IsCallFinalized(err) {
					assert.NoError(t, err)
				}
			}
		}()
	}
	wg.Add(2)
	go func() { defer wg.Done(); <-start; manager.SweepIdle(time.Nanosecond) }()
	go func() {
		defer wg.Done()
		<-start
		_, _ = manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	}()
	close(start)
	wg.Wait()
	assert.True(t, manager.IsFinalized(callID))
	assert.True(t, IsCallFinalized(manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)))
}

func TestPhase9LatePacketAndGetOrCreateDuringFinalizationAreSuppressed(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	const callID = "late-during-finalization"
	require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("initial"), layers.LinkTypeEthernet, false))
	started := make(chan struct{})
	release := make(chan struct{})
	manager.SetBeforeFinalize(func(string, CallFinalizationReason) {
		close(started)
		<-release
	})
	done := make(chan error, 1)
	go func() {
		_, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
		done <- err
	}()
	<-started

	_, err := manager.GetOrCreateWriter(callID, "alice", "bob")
	assert.True(t, IsCallFinalized(err))
	err = manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
	assert.True(t, IsCallFinalized(err))
	close(release)
	require.NoError(t, <-done)
}

func BenchmarkPcapWriterTombstoneLookup(b *testing.B) {
	for _, size := range []int{10, 1_000, 100_000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			manager := benchmarkPcapManager(b)
			manager.tombstoneLimit = 100_000
			manager.mu.Lock()
			seedTombstonesLocked(manager, size, time.Now())
			manager.mu.Unlock()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = manager.IsFinalized("absent-call")
			}
		})
	}
}

func BenchmarkPcapWriterTombstonePruning(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			manager := newTombstoneTestManager(size)
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				manager.mu.Lock()
				clear(manager.tombstones)
				clear(manager.tombstoneIndex)
				manager.tombstoneQueue = manager.tombstoneQueue[:0]
				seedTombstonesLocked(manager, size, time.Unix(0, 0))
				manager.mu.Unlock()
				b.StartTimer()
				manager.mu.Lock()
				manager.pruneTombstonesLocked(time.Now(), tombstonePruneBatch)
				manager.mu.Unlock()
				b.StopTimer()
			}
		})
	}
}

func BenchmarkPcapWriterTelemetryAtTombstoneCardinality(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			manager := newTombstoneTestManager(size)
			seedTombstones(manager, size, time.Now())
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = manager.Telemetry()
			}
		})
	}
}

func newTombstoneTestManager(size int) *PcapWriterManager {
	return &PcapWriterManager{
		tombstones:     make(map[string]time.Time, size),
		tombstoneIndex: make(map[string]*callTombstone, size),
		tombstoneLimit: size + 1,
		tombstoneTTL:   time.Hour,
	}
}

func seedTombstones(manager *PcapWriterManager, size int, finalizedAt time.Time) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	seedTombstonesLocked(manager, size, finalizedAt)
}

func seedTombstonesLocked(manager *PcapWriterManager, size int, finalizedAt time.Time) {
	for i := range size {
		callID := strings.Repeat("x", 8) + strconv.Itoa(i)
		entry := &callTombstone{callID: callID, finalizedAt: finalizedAt.Add(time.Duration(i))}
		manager.tombstones[callID] = entry.finalizedAt
		manager.tombstoneIndex[callID] = entry
		heap.Push(&manager.tombstoneQueue, entry)
	}
}

func BenchmarkPcapWriterFinalizationPause(b *testing.B) {
	manager := benchmarkPcapManager(b)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		callID := strconv.Itoa(i)
		if err := manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if _, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkPcapWriterConcurrentWrites(b *testing.B) {
	manager := benchmarkPcapManager(b)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := manager.WritePacket("benchmark", "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkPcapManager(b *testing.B) *PcapWriterManager {
	b.Helper()
	manager, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled: true, OutputDir: b.TempDir(), FilePattern: "{callid}.pcap", SyncInterval: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = manager.Close() })
	return manager
}
