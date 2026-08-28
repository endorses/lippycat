package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

var ErrReassemblyClosed = errors.New("reassembly engine is closed")

// StreamFactory owns every stream and worker created for TCP reassembly.
type StreamFactory interface {
	reassembly.StreamFactory
	Shutdown() error
}

// Clock supplies wall time for live stream aging and deterministic tests.
type Clock interface {
	Now() time.Time
	NewTicker(time.Duration) Ticker
}

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type systemClock struct{}
type systemTicker struct{ *time.Ticker }

func (systemClock) Now() time.Time                   { return time.Now() }
func (systemClock) NewTicker(d time.Duration) Ticker { return systemTicker{time.NewTicker(d)} }
func (t systemTicker) C() <-chan time.Time           { return t.Ticker.C }

type ReassemblyConfig struct {
	FlushInterval                 time.Duration
	IdleTimeout                   time.Duration
	MaxBufferedPagesPerConnection int
	MaxBufferedPagesTotal         int
	Clock                         Clock
}

func DefaultReassemblyConfig() ReassemblyConfig {
	return ReassemblyConfig{
		FlushInterval:                 30 * time.Second,
		IdleTimeout:                   2 * time.Minute,
		MaxBufferedPagesPerConnection: capture.DefaultMaxBufferedPagesPerConnection,
		MaxBufferedPagesTotal:         capture.DefaultMaxBufferedPagesTotal,
		Clock:                         systemClock{},
	}
}

// ReassemblyEngine owns an assembler, its periodic flush loop, and its factory.
type ReassemblyEngine struct {
	factory StreamFactory
	asm     *capture.TCPAssembler
	cfg     ReassemblyConfig

	stateMu           sync.RWMutex
	closed            bool
	latestCaptureTime time.Time
	captureTimeAging  bool

	runOnce   sync.Once
	closeOnce sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
	closeErr  error
}

func NewReassemblyEngine(factory StreamFactory, cfg ReassemblyConfig) *ReassemblyEngine {
	defaults := DefaultReassemblyConfig()
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaults.FlushInterval
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	return &ReassemblyEngine{
		factory: factory,
		asm:     capture.NewTCPAssemblerWithLimits(factory, cfg.MaxBufferedPagesPerConnection, cfg.MaxBufferedPagesTotal),
		cfg:     cfg,
		done:    make(chan struct{}),
	}
}

// Run performs periodic aging until ctx is cancelled or Close is called.
func (e *ReassemblyEngine) Run(ctx context.Context) error {
	started := false
	e.stateMu.Lock()
	if e.closed {
		e.stateMu.Unlock()
		return nil
	}
	e.runOnce.Do(func() {
		started = true
		var runCtx context.Context
		runCtx, e.cancel = context.WithCancel(ctx)
		go e.flushLoop(runCtx)
	})
	e.stateMu.Unlock()
	if !started {
		return errors.New("reassembly engine Run called more than once")
	}
	<-e.done
	return nil
}

func (e *ReassemblyEngine) flushLoop(ctx context.Context) {
	defer close(e.done)
	ticker := e.cfg.Clock.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			e.flushOlder()
		}
	}
}

func (e *ReassemblyEngine) flushOlder() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.closed {
		return
	}
	base := e.cfg.Clock.Now()
	if e.captureTimeAging && !e.latestCaptureTime.IsZero() {
		base = e.latestCaptureTime
	}
	e.asm.FlushCloseOlderThan(base.Add(-e.cfg.IdleTimeout))
}

// Assemble decodes and feeds a TCP envelope. Non-TCP envelopes are rejected.
func (e *ReassemblyEngine) Assemble(env *PacketEnvelope) error {
	if env == nil {
		return errors.New("cannot assemble nil packet envelope")
	}
	packet := env.Packet()
	if packet == nil || packet.NetworkLayer() == nil {
		return errors.New("packet has no network layer")
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		return errors.New("packet is not TCP")
	}
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.closed {
		return ErrReassemblyClosed
	}
	e.asm.Assemble(packet.NetworkLayer().NetworkFlow(), tcp, env.CaptureTime)
	if env.CaptureTime.After(e.latestCaptureTime) {
		e.latestCaptureTime = env.CaptureTime
	}
	if env.Source.Kind == SourcePCAPReplay {
		e.captureTimeAging = true
	}
	env.Stages = env.Stages.With(StageReassembled)
	return nil
}

// AssembleTCP is a transition adapter for capture sites that already decoded the
// packet. New pipeline stages should pass a PacketEnvelope to Assemble.
func (e *ReassemblyEngine) AssembleTCP(netFlow gopacket.Flow, tcp *layers.TCP, ts time.Time) error {
	if tcp == nil {
		return errors.New("cannot assemble nil TCP layer")
	}
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.closed {
		return ErrReassemblyClosed
	}
	e.asm.Assemble(netFlow, tcp, ts)
	if ts.After(e.latestCaptureTime) {
		e.latestCaptureTime = ts
	}
	return nil
}

func (e *ReassemblyEngine) LimitStats() capture.ReassemblyLimitSnapshot { return e.asm.LimitStats() }
func (e *ReassemblyEngine) BufferedPageLimits() (int, int)              { return e.asm.BufferedPageLimits() }

// Close prevents new input, drains streams, shuts down the factory, and waits.
func (e *ReassemblyEngine) Close() error {
	e.closeOnce.Do(func() {
		e.stateMu.Lock()
		e.closed = true
		e.asm.FlushAll()
		e.stateMu.Unlock()
		if e.cancel != nil {
			e.cancel()
			<-e.done
		} else {
			close(e.done)
		}
		if err := e.factory.Shutdown(); err != nil {
			e.closeErr = fmt.Errorf("shutdown reassembly stream factory: %w", err)
		}
	})
	return e.closeErr
}
