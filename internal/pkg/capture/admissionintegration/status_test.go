package admissionintegration

import (
	"context"
	"encoding/binary"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSessionSamplingUsesInstalledIntervalForAllHooks(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.ShadowSampleEvery = 7
	s := &Session{Config: cfg, telemetry: &sessionTelemetry{
		correlator:  mediaadmission.NewSampledShadowCorrelator(1, 1, 100, cfg.ShadowSampleEvery),
		diagnostics: mediaadmission.NewDiagnostics(1, time.Second),
	}}
	// Public configuration mutation cannot change one packet hook independently
	// of the interval already bound to the kernel generation and correlator.
	s.Config.ShadowSampleEvery = 1
	owner := mediaadmission.OwnerID{Session: 1, Generation: 1}
	frame := make([]byte, 64)
	for i := uint32(0); i < 100; i++ {
		binary.LittleEndian.PutUint32(frame[60:], i)
		want := mediaadmission.ShadowFrameEligible(0, frame, 7)
		require.Equal(t, want, s.ShadowFrameEligible(0, frame))
		if !want {
			s.RecordObservedPacket(0, frame)
			s.RecordAttributedPacket(owner, 0, frame)
		}
	}
	require.Zero(t, s.telemetry.correlator.Snapshot().Pending)
	require.Zero(t, s.telemetry.correlator.Snapshot().TrackingRejected)
	s.RecordMediaAttributionUnavailable()
	require.Equal(t, uint64(1), s.telemetry.diagnostics.Snapshot(time.Now()).AttributionDropped)
	require.Zero(t, s.telemetry.correlator.Snapshot().Incomplete)
}

func TestDisabledAdmissionStatus(t *testing.T) {
	s, err := NewSession(context.Background(), mediaadmission.DefaultConfig())
	require.NoError(t, err)
	require.Nil(t, s.Controller)
	require.Nil(t, s.Metadata)
	require.Nil(t, s.Installer())
	require.Nil(t, s.telemetry)
	require.Nil(t, s.closeBackend)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())
	status := s.Status()
	require.False(t, status.Enabled)
	require.Equal(t, mediaadmission.StateDisabled, status.Scopes[0].State)
	require.Empty(t, s.ShadowEvidence())
}
func TestBoundedAdmissionEvidenceSnapshot(t *testing.T) {
	s := &Session{Config: mediaadmission.DefaultConfig()}
	s.Config.ShadowEvidenceCapacity = 2
	s.telemetry = &sessionTelemetry{samples: []mediaadmission.ShadowSample{{Generation: 3}, {Generation: 2}}, next: 1, diagnostics: mediaadmission.NewDiagnostics(2, time.Second)}
	samples := s.ShadowEvidence()
	require.Equal(t, uint64(2), samples[0].Generation)
	require.Equal(t, uint64(3), samples[1].Generation)
	samples[0].Generation = 999
	require.Equal(t, uint64(2), s.ShadowEvidence()[0].Generation)
}
