package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// LogEntry represents a single log entry for the dev console
type LogEntry struct {
	Time    time.Time
	Level   slog.Level
	Message string
	Attrs   string // Formatted key=value pairs
}

// ConsoleBuffer is a ring buffer for log entries
type ConsoleBuffer struct {
	entries []LogEntry
	size    int
	head    int
	count   int
	mu      sync.RWMutex
}

// NewConsoleBuffer creates a new ring buffer with the given capacity
func NewConsoleBuffer(capacity int) *ConsoleBuffer {
	return &ConsoleBuffer{
		entries: make([]LogEntry, capacity),
		size:    capacity,
	}
}

// Add adds a log entry to the buffer
func (b *ConsoleBuffer) Add(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.size
	if b.count < b.size {
		b.count++
	}
}

// GetAll returns all entries in chronological order (oldest first)
func (b *ConsoleBuffer) GetAll() []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]LogEntry, b.count)
	if b.count == 0 {
		return result
	}

	start := 0
	if b.count == b.size {
		start = b.head // head points to oldest when full
	}

	for i := 0; i < b.count; i++ {
		idx := (start + i) % b.size
		result[i] = b.entries[idx]
	}

	return result
}

// GetRecent returns the N most recent entries (newest first for display)
func (b *ConsoleBuffer) GetRecent(n int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if n > b.count {
		n = b.count
	}
	if n == 0 {
		return nil
	}

	result := make([]LogEntry, n)
	// Head points to next write position, so head-1 is most recent
	for i := 0; i < n; i++ {
		idx := (b.head - 1 - i + b.size) % b.size
		result[i] = b.entries[idx]
	}

	return result
}

// Clear empties the buffer
func (b *ConsoleBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.head = 0
	b.count = 0
}

// Count returns the number of entries in the buffer
func (b *ConsoleBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// ConsoleHandler is a slog handler that writes to both another handler and a ring buffer
type ConsoleHandler struct {
	buffer *ConsoleBuffer
	level  slog.Level
	attrs  []slog.Attr
	group  string
}

// NewConsoleHandler creates a handler that captures logs to the buffer
func NewConsoleHandler(buffer *ConsoleBuffer, level slog.Level) *ConsoleHandler {
	return &ConsoleHandler{
		buffer: buffer,
		level:  level,
	}
}

// Enabled reports whether the handler handles records at the given level
func (h *ConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle handles the log record
func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	// Format attributes
	var attrs string
	r.Attrs(func(a slog.Attr) bool {
		if attrs != "" {
			attrs += " "
		}
		attrs += fmt.Sprintf("%s=%v", a.Key, a.Value.Any())
		return true
	})

	// Add handler's pre-set attrs
	for _, a := range h.attrs {
		if attrs != "" {
			attrs += " "
		}
		attrs += fmt.Sprintf("%s=%v", a.Key, a.Value.Any())
	}

	entry := LogEntry{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		Attrs:   attrs,
	}

	h.buffer.Add(entry)
	return nil
}

// WithAttrs returns a new handler with the given attributes
func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newH := &ConsoleHandler{
		buffer: h.buffer,
		level:  h.level,
		attrs:  make([]slog.Attr, len(h.attrs)+len(attrs)),
		group:  h.group,
	}
	copy(newH.attrs, h.attrs)
	copy(newH.attrs[len(h.attrs):], attrs)
	return newH
}

// WithGroup returns a new handler with the given group name
func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	return &ConsoleHandler{
		buffer: h.buffer,
		level:  h.level,
		attrs:  h.attrs,
		group:  name,
	}
}

// Global console buffer (only initialized when LOG_LEVEL=DEBUG)
var (
	consoleBuffer     *ConsoleBuffer
	consoleBufferOnce sync.Once
	debugEnabled      bool
)

// InitConsole initializes the dev console buffer if LOG_LEVEL=DEBUG
// Returns true if debug mode is enabled
func InitConsole() bool {
	consoleBufferOnce.Do(func() {
		if os.Getenv("LOG_LEVEL") == "DEBUG" {
			debugEnabled = true
			consoleBuffer = NewConsoleBuffer(1000) // Keep last 1000 messages
		}
	})
	return debugEnabled
}

// IsDebugEnabled returns true if LOG_LEVEL=DEBUG
func IsDebugEnabled() bool {
	return debugEnabled
}

// GetConsoleBuffer returns the console buffer (nil if debug not enabled)
func GetConsoleBuffer() *ConsoleBuffer {
	return consoleBuffer
}

// EnableConsoleCapture configures the logger to capture to the console buffer
// Call this after InitConsole() returns true
func EnableConsoleCapture() {
	if consoleBuffer == nil {
		return
	}

	disabledMux.Lock()
	defer disabledMux.Unlock()

	// Create a multi-handler that writes to both console buffer and original destination
	consoleHandler := NewConsoleHandler(consoleBuffer, slog.LevelDebug)
	defaultLogger = slog.New(consoleHandler)
}

// FormatLevel returns a short string for the log level
func FormatLevel(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "DBG"
	case slog.LevelInfo:
		return "INF"
	case slog.LevelWarn:
		return "WRN"
	case slog.LevelError:
		return "ERR"
	default:
		return "???"
	}
}
