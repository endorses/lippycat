package upstream

import (
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSSHRelayProductionPromiseAndOptionalOldReceiver(t *testing.T) {
	old := &management.ProcessorRegistrationResponse{AcceptedEventApiMajor: 1, AcceptedSemanticProfileRevision: 1, AcceptedEventKinds: []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}
	for _, enabled := range []bool{false, true} {
		m := NewManager(Config{ForwardMode: "events", SSHEnabled: enabled}, nil)
		defer m.Disconnect()
		if enabled {
			require.Contains(t, m.eventAnalysisFeatures(), protoadapter.SSHProductionFeature)
		} else {
			require.NotContains(t, m.eventAnalysisFeatures(), protoadapter.SSHProductionFeature)
		}
		require.NoError(t, validateAcceptedEventProfile(old, m.config.RequiredEventKinds...))
		require.Empty(t, m.config.RequiredEventKinds)
	}
	required := []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_SSH}
	m := NewManager(Config{ForwardMode: "events", RequiredEventKinds: required}, nil)
	defer m.Disconnect()
	require.Contains(t, m.eventAnalysisFeatures(), protoadapter.SSHProductionFeature, "disabled local parser may relay enforcing child producers")
	require.ErrorContains(t, validateAcceptedEventProfile(old, m.config.RequiredEventKinds...), "kind 13")
	require.Equal(t, required, protoadapter.RequiredSSHKinds(nil, true))
	require.Equal(t, required, protoadapter.RequiredSSHKinds(required, true))
	require.Empty(t, protoadapter.RequiredSSHKinds(nil, false))
}
