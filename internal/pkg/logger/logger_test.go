package logger

import (
	"context"
	"testing"
)

func TestLogger(t *testing.T) {
	// Test that logger functions don't panic
	ctx := context.Background()

	// Initialize logger first
	Initialize()

	// Test all logger functions - we can't easily capture output
	// but we can verify they don't panic
	t.Run("InfoContext", func(t *testing.T) {
		InfoContext(ctx, "Test info message", "key", "value", "number", 42)
	})

	t.Run("Info", func(t *testing.T) {
		Info("Test info message", "component", "test")
	})

	t.Run("Warn", func(t *testing.T) {
		Warn("Test warning message", "component", "test")
	})

	t.Run("WarnContext", func(t *testing.T) {
		WarnContext(ctx, "Test warning message", "component", "test")
	})

	t.Run("Error", func(t *testing.T) {
		Error("Test error message", "error", "sample error", "severity", "test")
	})

	t.Run("ErrorContext", func(t *testing.T) {
		ErrorContext(ctx, "Test error message", "error", "sample error")
	})

	t.Run("Debug", func(t *testing.T) {
		Debug("Test debug message", "debug", true)
	})

	t.Run("DebugContext", func(t *testing.T) {
		DebugContext(ctx, "Test debug message", "debug", true)
	})
}

func TestLoggerInitialization(t *testing.T) {
	// Test that Get() returns a logger
	logger := Get()
	if logger == nil {
		t.Error("Expected logger to be initialized")
	}

	// Test that multiple calls return same logger
	logger2 := Get()
	if logger != logger2 {
		t.Error("Expected same logger instance on multiple calls")
	}
}

func TestWithMethods(t *testing.T) {
	// Ensure logger is initialized
	logger := Get()
	if logger == nil {
		t.Fatal("Expected logger to be initialized")
	}

	// Test With method
	withLogger := With("service", "test")
	if withLogger == nil {
		t.Error("Expected With to return logger")
	}

	// Test WithGroup method
	groupLogger := WithGroup("test_group")
	if groupLogger == nil {
		t.Error("Expected WithGroup to return logger")
	}
}
