//go:build li

package li

import (
	"hash/fnv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func phase4BoundaryManager(t *testing.T) (*Manager, uuid.UUID, string, uuid.UUID, string) {
	t.Helper()
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{
		DID: did, Address: "mdf.invalid", Port: 8443, X3Enabled: true,
	}))
	activate := func(target TargetIdentity) (uuid.UUID, string) {
		xid := uuid.New()
		require.NoError(t, m.ActivateTask(&InterceptTask{
			XID: xid, Targets: []TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX3Only,
		}))
		ids := m.filters.GetFiltersForXID(xid)
		require.Len(t, ids, 1)
		return xid, ids[0]
	}
	identityXID, identityFilter := activate(TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:synthetic-a@example.invalid"})
	ipXID, ipFilter := activate(TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:synthetic-ip-task@example.invalid"})
	// Raw-IP task activation is intentionally unsupported today. Model the
	// already-created LI filter at the boundary, where only its filter class is
	// relevant to this test.
	m.filters.mu.Lock()
	m.filters.filterStore[ipFilter].Type = management.FilterType_FILTER_IP_ADDRESS
	m.filters.mu.Unlock()
	return m, identityXID, identityFilter, ipXID, ipFilter
}

func phase4RTP(callID string) *types.PacketDisplay {
	return &types.PacketDisplay{SrcIP: "192.0.2.44", DstIP: "198.51.100.8", VoIPData: &types.VoIPMetadata{IsRTP: true, CallID: callID, SSRC: 7}}
}

func TestProcessPacketWithProvenance_RTPFailsClosedButPreservesDirectIP(t *testing.T) {
	m, identityXID, identityFilter, ipXID, ipFilter := phase4BoundaryManager(t)
	var delivered []uuid.UUID
	var correlations []uint64
	encoder := x2x3.NewX3Encoder()
	m.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		delivered = append(delivered, task.XID)
		pdu, err := encoder.EncodeCC(pkt, task.XID)
		require.NoError(t, err)
		correlations = append(correlations, pdu.Header.CorrelationID)
	})

	m.ProcessPacketWithProvenance(phase4RTP("call-b"), PacketFilterProvenance{
		DirectFilterIDs: []string{ipFilter}, InheritedFilterIDs: []string{identityFilter},
		AuthoritativeCallID: "call-b", InheritedFromCallID: "call-a",
	})

	require.Equal(t, []uuid.UUID{ipXID}, delivered, "foreign inherited identity must not cross the LI boundary")
	require.NotContains(t, delivered, identityXID)
	callAHash := fnv.New64a()
	_, err := callAHash.Write([]byte("call-a"))
	require.NoError(t, err)
	require.NotContains(t, correlations, callAHash.Sum64(), "call B media must never carry call A's FNV correlation")
	require.Equal(t, uint64(1), m.Stats().InheritedProvenanceRejected)
}

func TestProcessPacketWithProvenance_RequiresMatchingAuthoritativeCall(t *testing.T) {
	m, identityXID, identityFilter, _, _ := phase4BoundaryManager(t)
	var delivered []uuid.UUID
	m.SetPacketProcessor(func(task *InterceptTask, _ *types.PacketDisplay) { delivered = append(delivered, task.XID) })

	m.ProcessPacketWithProvenance(phase4RTP("call-b"), PacketFilterProvenance{
		InheritedFilterIDs: []string{identityFilter}, AuthoritativeCallID: "call-b", InheritedFromCallID: "call-b",
	})
	require.Equal(t, []uuid.UUID{identityXID}, delivered)

	delivered = nil
	m.ProcessPacketWithProvenance(phase4RTP("call-a"), PacketFilterProvenance{
		InheritedFilterIDs: []string{identityFilter}, AuthoritativeCallID: "call-b", InheritedFromCallID: "call-b",
	})
	require.Empty(t, delivered)
}

func TestTaskAdmissionSerializesDeactivationAndRejectsStaleGeneration(t *testing.T) {
	m, xid, _, _, _ := phase4BoundaryManager(t)
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)

	admission, ok := m.AcquireTaskAdmission(xid, task.ActivationGeneration)
	require.True(t, ok)
	deactivated := make(chan error, 1)
	go func() { deactivated <- m.DeactivateTask(xid) }()

	select {
	case err := <-deactivated:
		t.Fatalf("deactivation crossed an admitted enqueue step: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	admission.Release()
	require.NoError(t, <-deactivated)

	_, ok = m.AcquireTaskAdmission(xid, task.ActivationGeneration)
	require.False(t, ok)

	// Reactivation creates a new generation; delayed work from the old one must
	// remain invalid even though the XID is active again.
	task.Status = TaskStatusPending
	task.StartTime = time.Time{}
	require.NoError(t, m.ActivateTask(task))
	newTask, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Greater(t, newTask.ActivationGeneration, task.ActivationGeneration)
	_, ok = m.AcquireTaskAdmission(xid, task.ActivationGeneration)
	require.False(t, ok)
	newAdmission, ok := m.AcquireTaskAdmission(xid, newTask.ActivationGeneration)
	require.True(t, ok)
	newAdmission.Release()
}

func TestTaskAdmissionReleaseIsIdempotent(t *testing.T) {
	m, xid, _, _, _ := phase4BoundaryManager(t)
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	admission, ok := m.AcquireTaskAdmission(xid, task.ActivationGeneration)
	require.True(t, ok)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); admission.Release() }()
	}
	wg.Wait()
}
