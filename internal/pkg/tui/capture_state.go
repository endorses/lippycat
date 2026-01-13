//go:build tui || all

package tui

import (
	"context"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// CaptureState manages capture lifecycle state with proper synchronization.
// This replaces the previous global variables to ensure thread-safe access
// from goroutines that need to send messages back to the TUI.
type CaptureState struct {
	mu      sync.RWMutex
	handle  *captureHandle
	program *tea.Program
}

// globalCaptureState is the package-level synchronized capture state.
// While still a singleton, it provides thread-safe access via accessor methods.
var globalCaptureState = &CaptureState{}

// SetProgram sets the tea.Program reference used by event handlers.
// This must be called before starting packet capture to enable message sending.
// The program reference is typically set once at startup and not changed.
func (cs *CaptureState) SetProgram(p *tea.Program) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.program = p
}

// GetProgram returns the tea.Program reference for sending messages.
// Returns nil if no program has been set.
func (cs *CaptureState) GetProgram() *tea.Program {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.program
}

// SetHandle sets up capture cancellation and completion signaling.
// The done channel should be closed when the capture goroutine exits.
func (cs *CaptureState) SetHandle(cancel context.CancelFunc, done chan struct{}) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.handle = &captureHandle{cancel: cancel, done: done}
}

// ClearHandle clears the current capture handle.
// This should be called when capture is stopped externally.
func (cs *CaptureState) ClearHandle() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.handle = nil
}

// StopCapture cancels the current capture and waits for completion.
// Returns true if there was an active capture that was stopped.
// This is safe to call even if no capture is active.
func (cs *CaptureState) StopCapture() bool {
	cs.mu.Lock()
	handle := cs.handle
	cs.handle = nil // Clear immediately to prevent double-cancellation
	cs.mu.Unlock()

	if handle == nil {
		return false
	}

	handle.cancel()
	// Wait for capture goroutine to finish (deterministic, no race conditions)
	<-handle.done
	return true
}

// HasActiveCapture returns true if there is an active capture session.
func (cs *CaptureState) HasActiveCapture() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.handle != nil
}

// SendMessage sends a message to the TUI program if one is set.
// This is safe to call from goroutines.
// Returns false if no program is set.
func (cs *CaptureState) SendMessage(msg tea.Msg) bool {
	p := cs.GetProgram()
	if p == nil {
		return false
	}
	p.Send(msg)
	return true
}
