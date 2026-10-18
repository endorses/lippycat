//go:build hunter || all

package forwarding

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestCapturePolicyProtectsDelayedProducerCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var allowed atomic.Bool
	allowed.Store(true)
	var accepted []*pipeline.PacketBatch
	stats := &flowStats{}
	m := New(Config{HunterID: "hunter.example.invalid", BatchSize: 10, RequireCaptureProvenance: true, ValidateCaptureSelection: func(*pipeline.PacketEnvelope) bool { return true }, CaptureAllowed: func(time.Time) bool { return allowed.Load() }, InitialCapturePolicy: []byte("old-policy"), BatchSink: func(batch *pipeline.PacketBatch) error { accepted = append(accepted, batch); return nil }}, stats, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	info := sipPacketInfo(t)
	capture.StampCapturePolicy(info.Packet, m.captureGeneration)
	old := convertPacket(info, []string{"selected"})
	// Immediate UDP already holds processingMu. Admission must not acquire it
	// recursively, while asynchronous callbacks use the identical acceptance API.
	require.NoError(t, m.WithCaptureBoundary(func() error { _, err := m.AddObservedPacket(old); return err }))
	require.NoError(t, m.ApplyCapturePolicy([]byte("new-policy"), func() error { return nil }))
	require.Len(t, accepted, 1)
	require.Equal(t, []byte("old-policy"), accepted[0].SignedCapturePolicy)
	_, err := m.AddObservedPacket(old)
	require.ErrorIs(t, err, ErrCaptureProvenance)
	_, err = m.AddObservedPacket(&pipeline.PacketEnvelope{})
	require.ErrorIs(t, err, ErrCaptureProvenance)
	current := sipPacketInfo(t)
	capture.StampCapturePolicy(current.Packet, m.captureGeneration)
	_, err = m.AddObservedPacket(convertPacket(current, nil))
	require.NoError(t, err)
	allowed.Store(false)
	m.SendBatch()
	require.Len(t, accepted, 1, "expiry between analysis and spool acceptance drops pending capture")
	require.Equal(t, uint64(3), stats.dropped.Load())
}

func TestCaptureSelectionRecheckedWhenBatchIsSealed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var generation atomic.Uint64
	generation.Store(1)
	accepted := 0
	stats := &flowStats{}
	m := New(Config{BatchSize: 10, BatchSink: func(batch *pipeline.PacketBatch) error { accepted += len(batch.Packets); return nil }}, stats, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	_, err := m.AddObservedPacket(&pipeline.PacketEnvelope{CurrentCaptureSelection: func() bool { return generation.Load() == 1 }})
	require.NoError(t, err)
	generation.Store(2)
	m.SendBatch()
	require.Zero(t, accepted, "reused call or withdrawn rule cannot inherit pending capture")
	_, err = m.AddObservedPacket(&pipeline.PacketEnvelope{CurrentCaptureSelection: func() bool { return generation.Load() == 2 }})
	require.NoError(t, err)
	m.SendBatch()
	require.Equal(t, 1, accepted)
	require.Equal(t, uint64(1), stats.dropped.Load())
}

func TestObservedBoundaryRejectsBeforeStateMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stats := &flowStats{}
	m := New(Config{RequireCaptureProvenance: true, ValidateCaptureSelection: func(*pipeline.PacketEnvelope) bool { return true }, CaptureAllowed: func(time.Time) bool { return true }}, stats, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	original := m.captureGeneration
	mutations := 0
	require.True(t, m.WithObservedCaptureBoundary(original, func() bool { mutations++; return true }))
	require.NoError(t, m.ApplyCapturePolicy(nil, func() error { return nil }))
	require.False(t, m.WithObservedCaptureBoundary(original, func() bool { mutations++; return true }))
	require.False(t, m.WithObservedCaptureBoundary(0, func() bool { mutations++; return true }))
	require.Equal(t, 1, mutations)
}

func TestTypedMediaProofRequiresValidationWithoutGlobalProvenanceLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var valid atomic.Bool
	accepted := 0
	m := New(Config{BatchSize: 10, ValidateCaptureSelection: func(*pipeline.PacketEnvelope) bool { return valid.Load() }, BatchSink: func(batch *pipeline.PacketBatch) error { accepted += len(batch.Packets); return nil }}, &flowStats{}, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	_, err := m.AddObservedPacket(&pipeline.PacketEnvelope{})
	require.NoError(t, err)
	m.SendBatch()
	require.Equal(t, 1, accepted, "ordinary no-proof traffic remains unleased")
	proof := func() *pipeline.PacketEnvelope {
		return &pipeline.PacketEnvelope{CaptureSelectionProof: []byte("immutable-signed-rule")}
	}
	_, err = m.AddObservedPacket(proof())
	require.ErrorIs(t, err, ErrCaptureProvenance)
	valid.Store(true)
	_, err = m.AddObservedPacket(proof())
	require.NoError(t, err)
	valid.Store(false)
	m.SendBatch()
	require.Equal(t, 1, accepted, "proof must be revalidated at sealing even without a current-selection callback")
	valid.Store(true)
	_, err = m.AddObservedPacket(proof())
	require.NoError(t, err)
	m.SendBatch()
	require.Equal(t, 2, accepted)
	m.config.ValidateCaptureSelection = nil
	_, err = m.AddObservedPacket(proof())
	require.ErrorIs(t, err, ErrCaptureProvenance, "missing proof validator fails closed")
}
