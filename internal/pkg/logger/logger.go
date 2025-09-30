package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

var (
	defaultLogger *slog.Logger
	once          sync.Once
	disabled      bool
	disabledMux   sync.RWMutex
)

// Initialize sets up the structured logger
func Initialize() {
	once.Do(func() {
		// Create a JSON handler for production use
		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: false,
		})
		defaultLogger = slog.New(handler)
	})
}

// Disable disables logging output (useful for TUI mode)
func Disable() {
	disabledMux.Lock()
	defer disabledMux.Unlock()
	disabled = true
	// Redirect to discard
	handler := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	defaultLogger = slog.New(handler)
}

// Enable re-enables logging output
func Enable() {
	disabledMux.Lock()
	defer disabledMux.Unlock()
	disabled = false
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	})
	defaultLogger = slog.New(handler)
}

// IsDisabled returns whether logging is disabled
func IsDisabled() bool {
	disabledMux.RLock()
	defer disabledMux.RUnlock()
	return disabled
}

// Get returns the default structured logger
func Get() *slog.Logger {
	Initialize() // Always call Initialize, sync.Once ensures it only runs once
	return defaultLogger
}

// Info logs an info level message
func Info(msg string, args ...any) {
	Get().Info(msg, args...)
}

// InfoContext logs an info level message with context
func InfoContext(ctx context.Context, msg string, args ...any) {
	Get().InfoContext(ctx, msg, args...)
}

// Warn logs a warning level message
func Warn(msg string, args ...any) {
	Get().Warn(msg, args...)
}

// WarnContext logs a warning level message with context
func WarnContext(ctx context.Context, msg string, args ...any) {
	Get().WarnContext(ctx, msg, args...)
}

// Error logs an error level message
func Error(msg string, args ...any) {
	Get().Error(msg, args...)
}

// ErrorContext logs an error level message with context
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Get().ErrorContext(ctx, msg, args...)
}

// Debug logs a debug level message
func Debug(msg string, args ...any) {
	Get().Debug(msg, args...)
}

// DebugContext logs a debug level message with context
func DebugContext(ctx context.Context, msg string, args ...any) {
	Get().DebugContext(ctx, msg, args...)
}

// With returns a logger with the given attributes
func With(args ...any) *slog.Logger {
	return Get().With(args...)
}

// WithGroup returns a logger with the given group name
func WithGroup(name string) *slog.Logger {
	return Get().WithGroup(name)
}
