//go:build li

package li

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRestoredElapsedWindowPreservesExplicitDeactivationGeneration(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit=%t", implicit), func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			details := convergenceDetails(xid, did, true)
			end := schema.QualifiedMicrosecondDateTime("2020-01-02T00:00:00Z")
			details.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
			details.TaskDetails.ImplicitDeactivationAllowed = &implicit
			definition, err := ConvertSnapshotTask(details)
			require.NoError(t, err)
			task := definition.Task
			task.Status, task.ActivationGeneration = TaskStatusActive, 7
			path := filepath.Join(t.TempDir(), "state")
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "127.0.0.1", Port: 8443}}}))
			m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: path}, nil)
			defer m.Stop()
			require.NoError(t, m.restorePersistedState())
			require.Zero(t, m.ActiveTaskCount(), "restoration alone cannot authorize capture")
			require.False(t, m.ReplayTaskAuthorized(xid, 7))
			if implicit {
				require.NotContains(t, m.persistedActive, xid, "implicit expiry must not retain live replay authority")
				return
			}
			require.Contains(t, m.persistedActive, xid)
			require.NoError(t, m.applySnapshotDefinition(definition))
			live, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, uint64(7), live.ActivationGeneration)
			require.True(t, live.IsActive())
			require.True(t, m.ReplayTaskAuthorized(xid, 7), "exact ADMF confirmation restores explicit-deactivation replay authority")
		})
	}
}
