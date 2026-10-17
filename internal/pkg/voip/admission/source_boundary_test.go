package admission

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestRemoteObservationRequiresExplicitAuthenticatedScope(t *testing.T) {
	bridge, registry, maps := fixture(t)
	remote := offer("remote-call")
	remote.Packet.Source.Kind = pipeline.SourceGRPC
	remote.Packet.Source.NodeID = "hunter-a"
	require.NoError(t, bridge.ObserveValidatedReceipt(&remote))
	require.Zero(t, maps.count())
	require.Zero(t, registry.ActiveCallCount())
	require.Equal(t, uint64(1), bridge.Stats().IgnoredNonlocal)
	bridge.mu.Lock()
	bridge.cfg.AcceptSource = func(source pipeline.SourceProvenance) bool {
		return source.Kind == pipeline.SourceGRPC && source.NodeID == "hunter-a" && source.InterfaceName == "eth0"
	}
	bridge.mu.Unlock()
	require.NoError(t, submitDerivation(t, bridge, registry, remote))
	require.Positive(t, maps.count())
	require.Equal(t, pipeline.SourceGRPC, remote.Packet.Source.Kind)
	other := offer("other-source")
	other.Packet.Source = pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: "hunter-b", InterfaceName: "eth0"}
	require.NoError(t, bridge.ObserveValidatedReceipt(&other))
	require.Equal(t, uint64(2), bridge.Stats().IgnoredNonlocal)
}
