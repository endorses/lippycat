package voip

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newAutoTuneTestFactory(cfg Config) *sipStreamFactory {
	return &sipStreamFactory{
		ctx:               context.Background(),
		config:            &cfg,
		autoTuneBatchSize: cfg.TCPBatchSize,
	}
}

func TestAutoTuningUsesEnforcedStreamCapacity(t *testing.T) {
	cfg := *DefaultConfig()
	cfg.MaxGoroutines = 10
	cfg.MaxStreams = 100
	cfg.TCPBatchSize = 32
	cfg.MemoryOptimization = false
	factory := newAutoTuneTestFactory(cfg)

	// This is above the soft monitoring threshold, but well below the actual
	// enforced stream capacity and must not activate control pressure.
	atomic.StoreInt64(&factory.activeGoroutines, 20)
	for range 10 {
		factory.performAutoTuning()
	}

	assert.False(t, factory.backpressureEnabled)
	assert.Equal(t, 32, factory.getCurrentBatchSize())

	atomic.StoreInt64(&factory.activeGoroutines, 81)
	factory.performAutoTuning()

	assert.True(t, factory.backpressureEnabled)
	assert.Equal(t, 16, factory.getCurrentBatchSize())
}

func TestAutoTuningRespectsDisabledBackpressure(t *testing.T) {
	cfg := *DefaultConfig()
	cfg.MaxStreams = 100
	cfg.TCPBatchSize = 64
	cfg.EnableBackpressure = false
	cfg.MemoryOptimization = false
	factory := newAutoTuneTestFactory(cfg)

	atomic.StoreInt64(&factory.activeGoroutines, 90)
	for range 10 {
		factory.performAutoTuning()
	}

	assert.False(t, factory.backpressureEnabled)
	assert.Equal(t, 64, factory.getCurrentBatchSize())
}

func TestAutoTuningUnlimitedStreamsIgnoresSoftThreshold(t *testing.T) {
	cfg := *DefaultConfig()
	cfg.MaxGoroutines = 10
	cfg.MaxStreams = 0
	cfg.TCPBatchSize = 32
	cfg.MemoryOptimization = false
	factory := newAutoTuneTestFactory(cfg)

	atomic.StoreInt64(&factory.activeGoroutines, 1_000)
	factory.performAutoTuning()

	assert.False(t, factory.backpressureEnabled)
	assert.Equal(t, 32, factory.getCurrentBatchSize())
}

func TestBackpressureTransitionsAreIdempotent(t *testing.T) {
	cfg := *DefaultConfig()
	cfg.TCPBatchSize = 32
	factory := newAutoTuneTestFactory(cfg)

	factory.enableBackpressure()
	assert.True(t, factory.backpressureEnabled)
	assert.Equal(t, 16, factory.getCurrentBatchSize())

	factory.enableBackpressure()
	assert.Equal(t, 16, factory.getCurrentBatchSize())

	factory.relaxBackpressure()
	assert.False(t, factory.backpressureEnabled)
	assert.Equal(t, 32, factory.getCurrentBatchSize())

	factory.relaxBackpressure()
	assert.Equal(t, 32, factory.getCurrentBatchSize())
}
