//go:build tui || all

package tui

import (
	"sync"
	"time"
)

// PauseSignal provides a channel-based pause/resume mechanism for goroutines.
// When paused, the channel is closed (signals pause). On resume, a new open
// channel is created. Goroutines can use C() in select statements or call
// Wait() to block until resumed.
type PauseSignal struct {
	mu     sync.RWMutex
	ch     chan struct{}
	paused bool
}

// NewPauseSignal creates a new pause signal in the running (not paused) state.
func NewPauseSignal() *PauseSignal {
	return &PauseSignal{ch: make(chan struct{})}
}

// Pause signals all waiting goroutines to pause. Safe to call multiple times.
func (p *PauseSignal) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.paused {
		close(p.ch)
		p.paused = true
	}
}

// Resume signals all waiting goroutines to continue. Safe to call multiple times.
func (p *PauseSignal) Resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.paused {
		p.ch = make(chan struct{})
		p.paused = false
	}
}

// IsPaused returns whether the signal is in paused state.
func (p *PauseSignal) IsPaused() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.paused
}

// C returns the pause channel for use in select statements.
// The channel is closed when paused (will return immediately),
// and open when running (will block).
func (p *PauseSignal) C() <-chan struct{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ch
}

// Wait blocks until the signal is resumed. Returns immediately if not paused.
func (p *PauseSignal) Wait() {
	for {
		p.mu.RLock()
		paused := p.paused
		p.mu.RUnlock()

		if !paused {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
