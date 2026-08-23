//go:build cli || hunter || processor || tap || tui || all

package keylog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

// WatcherConfig configures the key log file watcher.
type WatcherConfig struct {
	// PollInterval is the fallback polling interval when fsnotify is unavailable.
	// Default: 1 second
	PollInterval time.Duration

	// ReadBufferSize is the buffer size for reading key log data.
	// Default: 64KB
	ReadBufferSize int

	// MaxLineLength is the maximum length of a single key log line.
	// Default: 4KB
	MaxLineLength int

	// StrictMode rejects entries with unknown labels.
	// Default: false (unknown labels are silently ignored)
	StrictMode bool
}

// DefaultWatcherConfig returns the default watcher configuration.
func DefaultWatcherConfig() WatcherConfig {
	return WatcherConfig{
		PollInterval:   1 * time.Second,
		ReadBufferSize: 64 * 1024,
		MaxLineLength:  4 * 1024,
		StrictMode:     false,
	}
}

// Watcher watches a key log file for new entries and adds them to a store.
type Watcher struct {
	config    WatcherConfig
	store     *Store
	parser    *Parser
	path      string
	file      *os.File
	offset    int64
	fsWatcher *fsnotify.Watcher
	mu        sync.Mutex
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool

	// Stats
	linesRead    atomic.Uint64
	entriesAdded atomic.Uint64
	errors       atomic.Uint64
}

// NewWatcher creates a new key log file watcher.
func NewWatcher(path string, store *Store, config WatcherConfig) *Watcher {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultWatcherConfig().PollInterval
	}
	if config.ReadBufferSize <= 0 {
		config.ReadBufferSize = DefaultWatcherConfig().ReadBufferSize
	}
	if config.MaxLineLength <= 0 {
		config.MaxLineLength = DefaultWatcherConfig().MaxLineLength
	}

	parser := NewParser()
	parser.StrictMode = config.StrictMode

	return &Watcher{
		config:   config,
		store:    store,
		parser:   parser,
		path:     path,
		stopChan: make(chan struct{}),
	}
}

// Start begins watching the key log file.
// It first reads any existing content, then watches for new entries.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("watcher already running")
	}
	w.running = true
	w.mu.Unlock()

	// Check if path is a named pipe (FIFO)
	info, err := os.Stat(w.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	isPipe := info != nil && (info.Mode()&os.ModeNamedPipe != 0)

	if isPipe {
		// Named pipe: use continuous reader
		return w.startPipeReader(ctx)
	}

	// Regular file: use fsnotify or polling
	return w.startFileWatcher(ctx)
}

// startFileWatcher watches a regular file for changes.
func (w *Watcher) startFileWatcher(ctx context.Context) error {
	// Try to use fsnotify
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Warn("fsnotify unavailable, falling back to polling",
			"error", err)
		return w.startPolling(ctx)
	}
	w.fsWatcher = fsWatcher

	// Read existing content first (if file exists)
	if err := w.readExisting(); err != nil {
		logger.Warn("failed to read existing key log",
			"path", w.path,
			"error", err)
	}

	// Start watching
	if err := w.fsWatcher.Add(w.path); err != nil {
		// File might not exist yet - watch the parent directory for CREATE events
		dir := filepath.Dir(w.path)
		if dirErr := w.fsWatcher.Add(dir); dirErr != nil {
			logger.Warn("failed to watch directory, falling back to polling",
				"path", w.path,
				"dir", dir,
				"error", dirErr)
			if cerr := w.fsWatcher.Close(); cerr != nil {
				logger.Error("failed to close fsnotify watcher", "error", cerr)
			}
			w.fsWatcher = nil
			return w.startPolling(ctx)
		}
		logger.Debug("file not found, watching directory for creation",
			"path", w.path,
			"dir", dir)
	}

	w.wg.Add(1)
	go w.fsWatchLoop(ctx)

	logger.Info("started key log file watcher",
		"path", w.path,
		"mode", "fsnotify")

	return nil
}

// startPolling watches using periodic polling.
func (w *Watcher) startPolling(ctx context.Context) error {
	// Read existing content first (if file exists)
	if err := w.readExisting(); err != nil {
		logger.Warn("failed to read existing key log",
			"path", w.path,
			"error", err)
	}

	w.wg.Add(1)
	go w.pollLoop(ctx)

	logger.Info("started key log file watcher",
		"path", w.path,
		"mode", "polling",
		"interval", w.config.PollInterval)

	return nil
}

// startPipeReader reads from a named pipe (FIFO).
func (w *Watcher) startPipeReader(ctx context.Context) error {
	w.wg.Add(1)
	go w.pipeReadLoop(ctx)

	logger.Info("started key log pipe reader",
		"path", w.path,
		"mode", "pipe")

	return nil
}

// readExisting reads any existing content from the file.
func (w *Watcher) readExisting() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	file, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet - that's fine
			return nil
		}
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			logger.Error("failed to close key log file", "error", cerr)
		}
	}()

	// Read and parse existing content
	entries, errs := w.parser.Parse(file)
	for _, err := range errs {
		logger.Warn("key log parse error", "error", err)
		w.errors.Add(1)
	}

	// Add entries to store
	for _, entry := range entries {
		w.store.Add(entry)
		w.entriesAdded.Add(1)
	}
	w.linesRead.Add(uint64(len(entries)))

	// Get file size for offset tracking
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	w.offset = info.Size()

	if len(entries) > 0 {
		logger.Info("loaded existing key log entries",
			"path", w.path,
			"entries", len(entries))
	}

	return nil
}

// fsWatchLoop watches for file changes using fsnotify.
func (w *Watcher) fsWatchLoop(ctx context.Context) {
	defer w.wg.Done()

	targetPath, _ := filepath.Abs(w.path)

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}

			// Normalize the event name for comparison
			eventPath, _ := filepath.Abs(event.Name)

			// If watching directory, only react to our target file
			if eventPath != targetPath {
				continue
			}

			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// If file was just created, start watching it directly
				if event.Op&fsnotify.Create != 0 {
					// Try to add the file directly to the watch list
					if err := w.fsWatcher.Add(w.path); err == nil {
						logger.Debug("key log file created, now watching directly",
							"path", w.path)
					}
				}
				if err := w.readNew(); err != nil {
					logger.Warn("failed to read new key log entries",
						"error", err)
				}
			}
			if event.Op&fsnotify.Remove != 0 {
				// File was removed - reset offset
				w.mu.Lock()
				w.offset = 0
				w.mu.Unlock()
				logger.Debug("key log file removed, resetting offset")
			}
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			logger.Warn("fsnotify error", "error", err)
			w.errors.Add(1)
		}
	}
}

// pollLoop watches for file changes using periodic polling.
func (w *Watcher) pollLoop(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	var lastModTime time.Time
	var lastSize int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		case <-ticker.C:
			info, err := os.Stat(w.path)
			if err != nil {
				if !os.IsNotExist(err) {
					logger.Warn("failed to stat key log file",
						"path", w.path,
						"error", err)
				}
				continue
			}

			// Check if file was modified or recreated
			modTime := info.ModTime()
			size := info.Size()

			if modTime.After(lastModTime) || size > lastSize {
				if size < lastSize {
					// File was truncated or recreated - reset offset
					w.mu.Lock()
					w.offset = 0
					w.mu.Unlock()
					logger.Debug("key log file truncated, resetting offset")
				}

				if err := w.readNew(); err != nil {
					logger.Warn("failed to read new key log entries",
						"error", err)
				}

				lastModTime = modTime
				lastSize = size
			}
		}
	}
}

// pipeReadLoop continuously reads from a named pipe.
func (w *Watcher) pipeReadLoop(ctx context.Context) {
	defer w.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		default:
		}

		// Open pipe with non-blocking mode to avoid blocking on open
		// This allows us to check ctx/stopChan while waiting for a writer
		file, err := os.OpenFile(w.path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			// ENXIO means no writer is connected yet - this is expected
			if !errors.Is(err, syscall.ENXIO) {
				logger.Warn("failed to open key log pipe",
					"path", w.path,
					"error", err)
			}
			// Wait before retrying
			select {
			case <-time.After(w.config.PollInterval):
			case <-ctx.Done():
				return
			case <-w.stopChan:
				return
			}
			continue
		}

		if w.isStopped() {
			if err := file.Close(); err != nil {
				logger.Error("failed to close key log pipe", "error", err)
			}
			return
		}

		w.mu.Lock()
		if !w.running {
			w.mu.Unlock()
			if err := file.Close(); err != nil {
				logger.Error("failed to close key log pipe", "error", err)
			}
			return
		}
		w.file = file
		w.mu.Unlock()

		// Keep the pipe non-blocking so shutdown can be observed without relying
		// on cross-goroutine Close behavior to interrupt a blocked read.
		w.readPipe(ctx, file)

		w.closeActivePipe(file)

		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		case <-time.After(w.config.PollInterval):
		}
	}
}

// readPipe reads entries from an open pipe.
func (w *Watcher) readPipe(ctx context.Context, file *os.File) {
	reader := bufio.NewReaderSize(file, w.config.ReadBufferSize)
	pending := make([]byte, 0, w.config.MaxLineLength)

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopChan:
			return
		default:
		}

		chunk, err := reader.ReadBytes('\n')
		if len(chunk) > 0 {
			pending = append(pending, chunk...)
			if len(pending) > w.config.MaxLineLength {
				logger.Debug("key log parse error",
					"error", fmt.Errorf("line exceeds maximum length"),
					"line", string(pending[:w.config.MaxLineLength]))
				w.errors.Add(1)
				pending = pending[:0]
			} else if pending[len(pending)-1] == '\n' {
				w.processPipeLine(strings.TrimRight(string(pending), "\r\n"))
				pending = pending[:0]
			}
		}

		if err == nil {
			continue
		}

		if errors.Is(err, io.EOF) {
			if len(pending) > 0 {
				w.processPipeLine(strings.TrimRight(string(pending), "\r\n"))
			}
			return
		}

		if isWouldBlock(err) {
			select {
			case <-ctx.Done():
				return
			case <-w.stopChan:
				return
			case <-time.After(w.config.PollInterval):
				continue
			}
		}

		if !w.isStopped() {
			logger.Warn("key log pipe read error", "error", err)
			w.errors.Add(1)
		}
		return
	}
}

func (w *Watcher) processPipeLine(line string) {
	w.linesRead.Add(1)
	entry, err := w.parser.ParseLine(line)
	if err != nil {
		logger.Debug("key log parse error",
			"error", err,
			"line", line)
		w.errors.Add(1)
		return
	}
	if entry != nil {
		w.store.Add(entry)
		w.entriesAdded.Add(1)
		logger.Debug("added key from pipe",
			"label", entry.Label.String(),
			"client_random", entry.ClientRandomHex()[:16]+"...")
	}
}

// readNew reads new entries from the file (from current offset).
func (w *Watcher) readNew() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	file, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			logger.Error("failed to close key log file", "error", cerr)
		}
	}()

	// Check if file was truncated
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() < w.offset {
		// File was truncated - read from beginning
		w.offset = 0
		logger.Debug("key log file truncated, reading from beginning")
	}

	// Seek to offset
	if w.offset > 0 {
		if _, err := file.Seek(w.offset, io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek: %w", err)
		}
	}

	// Read new content
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, w.config.ReadBufferSize), w.config.MaxLineLength)

	newEntries := 0
	for scanner.Scan() {
		w.linesRead.Add(1)
		entry, err := w.parser.ParseLine(scanner.Text())
		if err != nil {
			logger.Debug("key log parse error",
				"error", err,
				"line", scanner.Text())
			w.errors.Add(1)
			continue
		}
		if entry != nil {
			w.store.Add(entry)
			w.entriesAdded.Add(1)
			newEntries++
			logger.Debug("added new key",
				"label", entry.Label.String(),
				"client_random", entry.ClientRandomHex()[:16]+"...")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read error: %w", err)
	}

	// Update offset
	newOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get offset: %w", err)
	}
	w.offset = newOffset

	if newEntries > 0 {
		logger.Debug("read new key log entries",
			"count", newEntries,
			"offset", w.offset)
	}

	return nil
}

// Stop stops the watcher.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopChan)

	w.mu.Lock()
	file := w.file
	w.file = nil
	w.mu.Unlock()
	if file != nil {
		if err := file.Close(); err != nil {
			logger.Error("failed to close key log pipe", "error", err)
		}
	}

	if w.fsWatcher != nil {
		if err := w.fsWatcher.Close(); err != nil {
			logger.Error("failed to close fsnotify watcher", "error", err)
		}
	}

	w.wg.Wait()

	logger.Info("stopped key log watcher",
		"path", w.path,
		"entries_added", w.entriesAdded.Load())

	return nil
}

// Stats returns watcher statistics.
func (w *Watcher) Stats() WatcherStats {
	w.mu.Lock()
	defer w.mu.Unlock()

	return WatcherStats{
		Path:         w.path,
		Offset:       w.offset,
		LinesRead:    w.linesRead.Load(),
		EntriesAdded: w.entriesAdded.Load(),
		Errors:       w.errors.Load(),
		Running:      w.running,
	}
}

func (w *Watcher) isStopped() bool {
	select {
	case <-w.stopChan:
		return true
	default:
		return false
	}
}

func isWouldBlock(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

func (w *Watcher) closeActivePipe(file *os.File) {
	w.mu.Lock()
	shouldClose := w.file == file
	if shouldClose {
		w.file = nil
	}
	w.mu.Unlock()

	if shouldClose {
		if err := file.Close(); err != nil && !w.isStopped() {
			logger.Error("failed to close key log pipe", "error", err)
		}
	}
}

// WatcherStats contains watcher statistics.
type WatcherStats struct {
	Path         string
	Offset       int64
	LinesRead    uint64
	EntriesAdded uint64
	Errors       uint64
	Running      bool
}
