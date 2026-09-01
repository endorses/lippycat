package pipeline

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
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
	// ShardCount is the number of independent TCP assemblers. A flow and its
	// reverse direction always select the same shard. Values below one retain
	// the compatibility default of one shard.
	ShardCount                    int
	FlushInterval                 time.Duration
	IdleTimeout                   time.Duration
	MaxBufferedPagesPerConnection int
	MaxBufferedPagesTotal         int
	Clock                         Clock
}

func DefaultReassemblyConfig() ReassemblyConfig {
	return ReassemblyConfig{
		ShardCount:                    1,
		FlushInterval:                 30 * time.Second,
		IdleTimeout:                   2 * time.Minute,
		MaxBufferedPagesPerConnection: capture.DefaultMaxBufferedPagesPerConnection,
		MaxBufferedPagesTotal:         capture.DefaultMaxBufferedPagesTotal,
		Clock:                         systemClock{},
	}
}

// ReassemblyEngine owns flow-sharded assemblers, their periodic flush loop, and
// their shared factory.
type ReassemblyEngine struct {
	factory StreamFactory
	shards  []*capture.TCPAssembler
	cfg     ReassemblyConfig

	// stateMu is a lifecycle gate. Assembly holds a read lock for the complete
	// selected-shard operation, allowing independent shards to run concurrently
	// while Close excludes new input and waits for in-flight input.
	stateMu sync.RWMutex
	closed  bool

	agingMu           sync.Mutex
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
	if cfg.ShardCount <= 0 {
		cfg.ShardCount = defaults.ShardCount
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaults.FlushInterval
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaults.IdleTimeout
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	if cfg.MaxBufferedPagesPerConnection <= 0 {
		cfg.MaxBufferedPagesPerConnection = defaults.MaxBufferedPagesPerConnection
	}
	if cfg.MaxBufferedPagesTotal <= 0 {
		cfg.MaxBufferedPagesTotal = defaults.MaxBufferedPagesTotal
	}
	// A zero per-shard limit would be interpreted by capture as "use the
	// default", multiplying the intended memory bound. Limit the effective
	// shard count instead so every shard receives at least one page and the sum
	// remains exactly MaxBufferedPagesTotal.
	if cfg.ShardCount > cfg.MaxBufferedPagesTotal {
		cfg.ShardCount = cfg.MaxBufferedPagesTotal
	}
	shards := make([]*capture.TCPAssembler, cfg.ShardCount)
	basePages := cfg.MaxBufferedPagesTotal / cfg.ShardCount
	extraPages := cfg.MaxBufferedPagesTotal % cfg.ShardCount
	for i := range shards {
		pages := basePages
		if i < extraPages {
			pages++
		}
		shards[i] = capture.NewTCPAssemblerWithLimits(factory, cfg.MaxBufferedPagesPerConnection, pages)
	}
	return &ReassemblyEngine{
		factory: factory,
		shards:  shards,
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
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	if e.closed {
		return
	}
	base := e.cfg.Clock.Now()
	e.agingMu.Lock()
	if e.captureTimeAging && !e.latestCaptureTime.IsZero() {
		base = e.latestCaptureTime
	}
	e.agingMu.Unlock()
	cutoff := base.Add(-e.cfg.IdleTimeout)
	for _, shard := range e.shards {
		shard.FlushCloseOlderThan(cutoff)
	}
}

// FlowHash returns a direction-independent hash over both network and transport
// endpoints. Both gopacket flow hashes are direction-independent, so reversing
// the complete TCP tuple produces the same result.
func FlowHash(netFlow, transportFlow gopacket.Flow) uint64 {
	// Mix the two component hashes before combining them. A plain XOR has poor
	// low-bit distribution for similarly shaped IP and port flows because
	// FastHash uses the same combiner for both endpoint pairs.
	return mixFlowHash(netFlow.FastHash()) ^ bits.RotateLeft64(mixFlowHash(transportFlow.FastHash()), 1)
}

func mixFlowHash(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	return value ^ (value >> 31)
}

// FlowShard selects the stable shard for a bidirectional flow.
func FlowShard(netFlow, transportFlow gopacket.Flow, shardCount int) int {
	if shardCount <= 1 {
		return 0
	}
	return int(FlowHash(netFlow, transportFlow) % uint64(shardCount))
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
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	if e.closed {
		return ErrReassemblyClosed
	}
	netFlow := packet.NetworkLayer().NetworkFlow()
	e.shards[FlowShard(netFlow, tcp.TransportFlow(), len(e.shards))].Assemble(netFlow, tcp, env.CaptureTime)
	e.agingMu.Lock()
	if env.CaptureTime.After(e.latestCaptureTime) {
		e.latestCaptureTime = env.CaptureTime
	}
	if env.Source.Kind == SourcePCAPReplay {
		e.captureTimeAging = true
	}
	e.agingMu.Unlock()
	env.Stages = env.Stages.With(StageReassembled)
	return nil
}

// AssembleTCP is a transition adapter for capture sites that already decoded the
// packet. New pipeline stages should pass a PacketEnvelope to Assemble.
func (e *ReassemblyEngine) AssembleTCP(netFlow gopacket.Flow, tcp *layers.TCP, ts time.Time) error {
	if tcp == nil {
		return errors.New("cannot assemble nil TCP layer")
	}
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	if e.closed {
		return ErrReassemblyClosed
	}
	e.shards[FlowShard(netFlow, tcp.TransportFlow(), len(e.shards))].Assemble(netFlow, tcp, ts)
	e.agingMu.Lock()
	if ts.After(e.latestCaptureTime) {
		e.latestCaptureTime = ts
	}
	e.agingMu.Unlock()
	return nil
}

func (e *ReassemblyEngine) LimitStats() capture.ReassemblyLimitSnapshot {
	var total capture.ReassemblyLimitSnapshot
	for _, shard := range e.shards {
		stats := shard.LimitStats()
		total.BufferedPageLimitReleases += stats.BufferedPageLimitReleases
		total.MissingSequenceBytes += stats.MissingSequenceBytes
		total.NormalDiscontinuities += stats.NormalDiscontinuities
		total.NormalMissingBytes += stats.NormalMissingBytes
		total.ExplicitFlushDiscontinuities += stats.ExplicitFlushDiscontinuities
		total.ExplicitFlushMissingBytes += stats.ExplicitFlushMissingBytes
	}
	return total
}

// BufferedPageLimits returns the per-connection cap and exact global page cap.
func (e *ReassemblyEngine) BufferedPageLimits() (int, int) {
	return e.cfg.MaxBufferedPagesPerConnection, e.cfg.MaxBufferedPagesTotal
}

func (e *ReassemblyEngine) ShardCount() int { return len(e.shards) }

// Close prevents new input, drains streams, shuts down the factory, and waits.
func (e *ReassemblyEngine) Close() error {
	e.closeOnce.Do(func() {
		e.stateMu.Lock()
		e.closed = true
		for _, shard := range e.shards {
			shard.FlushAll()
		}
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
