//go:build hunter || all

package connection

import (
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSSHSourceCapabilitiesDistinguishProductionFromCodec(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		manager, client := newLegacyProcessorManager("packets", false)
		manager.config.SSHEnabled = enabled
		require.NoError(t, manager.register())
		caps := client.request.EventForwarding
		require.Contains(t, caps.EventKinds, int32(eventsv1.EventKind_EVENT_KIND_SSH))
		if enabled {
			require.Contains(t, caps.StatefulAnalysisFeatures, protoadapter.SSHProductionFeature)
		} else {
			require.NotContains(t, caps.StatefulAnalysisFeatures, protoadapter.SSHProductionFeature)
		}
		require.Empty(t, manager.config.RequiredEventKinds, "ordinary optional SSH must not require a new receiver")
	}
}
