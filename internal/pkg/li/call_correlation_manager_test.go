//go:build li

package li

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCallCorrelationPacketSnapshot(t *testing.T) {
	m, identity, identityFilter, ip, ipFilter := phase4BoundaryManager(t)
	pkt := phase4RTP("snapshot-call")
	var batchCalls, legacyCalls int
	m.SetPacketProcessor(func(*InterceptTask, *types.PacketDisplay) { legacyCalls++ })
	m.SetPacketBatchProcessor(func(tasks []*InterceptTask, packet *types.PacketDisplay) {
		batchCalls++
		require.Same(t, pkt, packet)
		seen := map[uuid.UUID]bool{}
		for _, task := range tasks {
			require.True(t, task.IsActive())
			require.NotZero(t, task.ActivationGeneration)
			seen[task.XID] = true
		}
		require.Equal(t, map[uuid.UUID]bool{identity: true, ip: true}, seen)
	})
	m.ProcessPacketWithProvenance(pkt, PacketFilterProvenance{
		DirectFilterIDs: []string{ipFilter}, InheritedFilterIDs: []string{identityFilter},
		AuthoritativeCallID: "snapshot-call",
		InheritedFromCallID: "snapshot-call",
	})
	require.Equal(t, 1, batchCalls)
	require.Zero(t, legacyCalls)
	m.SetPacketBatchProcessor(nil)
	m.ProcessPacketWithProvenance(pkt, PacketFilterProvenance{DirectFilterIDs: []string{ipFilter}})
	require.Equal(t, 1, legacyCalls)
	// Rejected inherited provenance never reaches packet preparation.
	m.SetPacketBatchProcessor(func([]*InterceptTask, *types.PacketDisplay) { batchCalls++ })
	m.ProcessPacketWithProvenance(pkt, PacketFilterProvenance{InheritedFilterIDs: []string{identityFilter}, AuthoritativeCallID: "different-call"})
	require.Equal(t, 1, batchCalls)
}

func TestCallCorrelationDisabledPreservesCallbackLookupOrder(t *testing.T) {
	m, identity, identityFilter, ip, ipFilter := phase4BoundaryManager(t)
	var calls int
	m.SetPacketProcessor(func(task *InterceptTask, _ *types.PacketDisplay) {
		calls++
		other := identity
		if task.XID == identity {
			other = ip
		}
		require.NoError(t, m.DeactivateTask(other))
	})
	m.ProcessPacketWithProvenance(phase4RTP("snapshot-call"), PacketFilterProvenance{
		DirectFilterIDs: []string{ipFilter}, InheritedFilterIDs: []string{identityFilter},
		AuthoritativeCallID: "snapshot-call", InheritedFromCallID: "snapshot-call",
	})
	require.Equal(t, 1, calls, "disabled preparation retains per-task active lookup after prior callbacks")
}
