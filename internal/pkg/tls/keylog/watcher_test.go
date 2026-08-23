//go:build cli || hunter || processor || tap || all

package keylog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyLogContent = `# TLS 1.2 session
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
`

const additionalKeyLogContent = `CLIENT_RANDOM fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
`

func TestWatcherReadExisting(t *testing.T) {
	// Create temp file with existing content
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	// Wait for initial read
	time.Sleep(100 * time.Millisecond)

	// Check that existing entry was loaded
	assert.Equal(t, 1, store.Size())
	stats := watcher.Stats()
	assert.Equal(t, uint64(1), stats.EntriesAdded)
}

func TestWatcherNewEntries(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 50 * time.Millisecond // Fast polling for test
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	// Wait for initial read
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.Size())

	// Append new content
	f, err := os.OpenFile(keylogPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.WriteString(additionalKeyLogContent)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Wait for watcher to detect change
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 2, store.Size())
	stats := watcher.Stats()
	assert.Equal(t, uint64(2), stats.EntriesAdded)
}

func TestWatcherNonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "nonexistent.log")

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 50 * time.Millisecond
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	// Start watcher - should not error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	// File doesn't exist yet
	assert.Equal(t, 0, store.Size())

	// Create file
	err = os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	// Wait for watcher to detect file
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 1, store.Size())
}

func TestWatcherFileTruncation(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	// Create initial file
	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 50 * time.Millisecond
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.Size())

	// Truncate and rewrite
	err = os.WriteFile(keylogPath, []byte(additionalKeyLogContent), 0600)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	// Should have 2 entries now (original + new)
	assert.Equal(t, 2, store.Size())
}

func TestWatcherNamedPipe(t *testing.T) {
	// Skip on systems that don't support named pipes
	tmpDir := t.TempDir()
	pipePath := filepath.Join(tmpDir, "keys.pipe")

	// Create named pipe
	err := syscall.Mkfifo(pipePath, 0600)
	if err != nil {
		t.Skip("named pipes not supported on this system")
	}

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 100 * time.Millisecond // Fast retry for test
	watcher := NewWatcher(pipePath, store, watcherConfig)

	// Start watcher with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// Open the pipe for writing and keep it open until the watcher consumes data.
	writerReady := make(chan *os.File, 1)
	writeErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(pipePath, os.O_WRONLY, 0600)
		if err != nil {
			writeErr <- err
			return
		}
		writerReady <- f

		_, err = f.WriteString(testKeyLogContent)
		writeErr <- err
	}()

	var writer *os.File
	select {
	case writer = <-writerReady:
	case err := <-writeErr:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for pipe writer")
	}
	defer func() {
		if writer != nil {
			require.NoError(t, writer.Close())
		}
	}()

	select {
	case err := <-writeErr:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for pipe write")
	}

	waitForStoreSize(t, store, 1, time.Second)

	// Stop watcher (this should not block since ctx has timeout)
	stopDone := make(chan struct{})
	go func() {
		if err := watcher.Stop(); err != nil {
			t.Logf("watcher stop error: %v", err)
		}
		close(stopDone)
	}()

	select {
	case <-stopDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for watcher to stop")
	}

	assert.Equal(t, 1, store.Size())
}

func TestWatcherNamedPipeStopWithIdleWriter(t *testing.T) {
	tmpDir := t.TempDir()
	pipePath := filepath.Join(tmpDir, "keys.pipe")

	err := syscall.Mkfifo(pipePath, 0600)
	if err != nil {
		t.Skip("named pipes not supported on this system")
	}

	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 10 * time.Millisecond
	watcher := NewWatcher(pipePath, store, watcherConfig)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, watcher.Start(ctx))

	writerReady := make(chan *os.File, 1)
	writerErr := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(pipePath, os.O_WRONLY, 0600)
		if err != nil {
			writerErr <- err
			return
		}
		writerReady <- f
	}()

	var writer *os.File
	select {
	case writer = <-writerReady:
	case err := <-writerErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for pipe writer")
	}
	defer func() {
		if writer != nil {
			_ = writer.Close()
		}
	}()

	waitForActivePipe(t, watcher, time.Second)

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- watcher.Stop()
	}()

	select {
	case err := <-stopDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for watcher to stop")
	}
}

func TestWatcherStatsRaceFree(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	require.NoError(t, os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600))

	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcherConfig.PollInterval = 10 * time.Millisecond
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, watcher.Start(ctx))
	defer func() {
		require.NoError(t, watcher.Stop())
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.After(200 * time.Millisecond)
			for {
				select {
				case <-deadline:
					return
				default:
					_ = watcher.Stats()
				}
			}
		}()
	}

	f, err := os.OpenFile(keylogPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		_, err := fmt.Fprintf(f, "INVALID_LINE_%d\n", i)
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}
	require.NoError(t, f.Close())

	wg.Wait()
	stats := watcher.Stats()
	assert.Greater(t, stats.LinesRead, uint64(0))
}

func TestWatcherStats(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	// Create store and watcher
	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	stats := watcher.Stats()
	assert.Equal(t, keylogPath, stats.Path)
	assert.True(t, stats.Running)
	assert.Equal(t, uint64(1), stats.EntriesAdded)
	assert.Greater(t, stats.Offset, int64(0))
}

func TestWatcherDoubleStart(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := watcher.Stop(); err != nil {
			t.Errorf("failed to stop watcher: %v", err)
		}
	}()

	// Second start should error
	err = watcher.Start(ctx)
	assert.Error(t, err)
}

func TestWatcherStopIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	keylogPath := filepath.Join(tmpDir, "keys.log")

	err := os.WriteFile(keylogPath, []byte(testKeyLogContent), 0600)
	require.NoError(t, err)

	storeConfig := DefaultStoreConfig()
	storeConfig.CleanupInterval = 1 * time.Hour
	store := NewStore(storeConfig)
	defer store.Stop()

	watcherConfig := DefaultWatcherConfig()
	watcher := NewWatcher(keylogPath, store, watcherConfig)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = watcher.Start(ctx)
	require.NoError(t, err)

	// First stop
	err = watcher.Stop()
	assert.NoError(t, err)

	// Second stop should be no-op
	err = watcher.Stop()
	assert.NoError(t, err)
}

func waitForStoreSize(t *testing.T, store *Store, expected int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if store.Size() >= expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.GreaterOrEqual(t, store.Size(), expected)
}

func waitForActivePipe(t *testing.T, watcher *Watcher, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		watcher.mu.Lock()
		active := watcher.file != nil
		watcher.mu.Unlock()
		if active {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout waiting for active pipe")
}
