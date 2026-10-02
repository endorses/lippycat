package hunter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAdmissionHeartbeatSnapshotIsolation(t *testing.T) {
	manager := NewManager("processor", 1, nil)
	_, _, err := manager.Register("hunter", "host", nil, nil)
	require.NoError(t, err)
	status := &management.MediaAdmissionStatus{Enabled: true, Scopes: []*management.MediaAdmissionScope{{State: "enforcing", InstalledEndpoints: 2, DecisionCounters: []uint64{11, 22}}}}
	manager.UpdateHeartbeat("hunter", 1, management.HunterStatus_STATUS_HEALTHY, &management.HunterStats{RtpEbpf: status})
	status.Scopes[0].DecisionCounters[0] = 999
	got := manager.AdmissionStatus("hunter")
	require.Equal(t, uint64(11), got.Scopes[0].DecisionCounters[0])
	got.Scopes[0].InstalledEndpoints = 99
	require.Equal(t, uint64(2), manager.AdmissionStatus("hunter").Scopes[0].InstalledEndpoints)
	manager.UpdateHeartbeat("hunter", 2, management.HunterStatus_STATUS_HEALTHY, &management.HunterStats{})
	require.Nil(t, manager.AdmissionStatus("hunter"))
	require.Nil(t, manager.AdmissionStatus("missing"))
}
