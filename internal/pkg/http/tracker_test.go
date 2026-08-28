package http

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCorrelateResponsePreservesRequestIdentity(t *testing.T) {
	tracker := NewRequestTracker(DefaultTrackerConfig())
	t.Cleanup(tracker.Close)

	tracker.TrackRequest("192.0.2.1", "192.0.2.2", "50000", "80", &types.HTTPMetadata{
		Type: "request", Method: "GET", Host: "example.test", Path: "/resource",
	})
	response := &types.HTTPMetadata{Type: "response", IsServer: true, StatusCode: 200}

	require.True(t, tracker.CorrelateResponse("192.0.2.2", "192.0.2.1", "80", "50000", response))
	require.True(t, response.CorrelatedResponse)
	require.Equal(t, "GET", response.Method)
	require.Equal(t, "example.test", response.Host)
	require.Equal(t, "/resource", response.Path)
}
