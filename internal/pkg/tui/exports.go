//go:build tui || all

package tui

import (
	"context"
	"sync"

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

// ClearCurrentProgram clears the global program reference.
// This should be called during shutdown to prevent goroutines from
// sending messages to a terminated program.
// Thread-safe via CaptureState synchronization.
func ClearCurrentProgram() {
	globalCaptureState.SetProgram(nil)
}

// SignalTUIReady signals that the TUI is fully initialized and ready to receive messages.
// This should be called after the first WindowSizeMsg is processed.
// Thread-safe via CaptureState synchronization.
func SignalTUIReady() {
	globalCaptureState.SignalReady()
}

// WaitForTUIReady blocks until the TUI is ready to receive messages.
// This should be called by capture goroutines before sending messages.
// Thread-safe via CaptureState synchronization.
func WaitForTUIReady() {
	globalCaptureState.WaitForReady()
}

// ResetTUIReady resets the ready state. This is used in tests to ensure
// each test starts with a fresh ready state.
// Thread-safe via CaptureState synchronization.
func ResetTUIReady() {
	globalCaptureState.mu.Lock()
	globalCaptureState.ready = make(chan struct{})
	globalCaptureState.readyOnce = sync.Once{}
	globalCaptureState.mu.Unlock()
}

// SendCaptureCompleteMsg sends a CaptureCompleteMsg to the TUI if the program is still valid.
// This is safe to call even if the program has been shut down.
// Thread-safe via CaptureState synchronization.
func SendCaptureCompleteMsg(packetsReceived int64) {
	globalCaptureState.SendMessage(CaptureCompleteMsg{
		PacketsReceived: packetsReceived,
	})
}
