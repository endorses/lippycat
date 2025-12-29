//go:build tui || all
// +build tui all

package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
)

// SetCurrentProgram sets the global program reference used by event handlers.
// This must be called before starting packet capture to enable message sending.
// Thread-safe via CaptureState synchronization.
func SetCurrentProgram(p *tea.Program) {
	globalCaptureState.SetProgram(p)
}

// SetCaptureHandle sets up capture cancellation and completion signaling.
// The done channel should be closed when the capture goroutine exits.
// Thread-safe via CaptureState synchronization.
func SetCaptureHandle(cancel context.CancelFunc, done chan struct{}) {
	globalCaptureState.SetHandle(cancel, done)
}

// ClearCaptureHandle clears the current capture handle.
// This should be called when capture is stopped externally.
// Thread-safe via CaptureState synchronization.
func ClearCaptureHandle() {
	globalCaptureState.ClearHandle()
}
