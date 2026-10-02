package admissionintegration

import (
	"context"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

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
