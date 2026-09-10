//go:build li

package li

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistedReplayCandidateSurvivesStartupActivationRollback(t *testing.T) {
	for _, stage := range []string{"checkpoint", "commit"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			xid, did := uuid.New(), uuid.New()
			task := &InterceptTask{XID: xid, Status: TaskStatusActive, ActivationGeneration: 7, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "mdf.example", Port: 8443}}}))
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, m.restorePersistedState())
			if stage == "checkpoint" {
				m.config.StateFile = t.TempDir()
			} else {
				m.commitActivation = func(uuid.UUID, time.Time) error { return errors.New("injected commit failure") }
			}
			require.Error(t, m.activateStartupTask(task))
			require.Zero(t, m.TaskCount())
			require.Zero(t, m.FilterCount())
			m.config.StateFile = path
			require.NoError(t, m.persistState())
			restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, restarted.restorePersistedState())
			require.Contains(t, restarted.persistedActive, xid)
			require.False(t, restarted.ReplayTaskAuthorized(xid, 7))
			require.NoError(t, restarted.activateStartupTask(task))
			active, err := restarted.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, uint64(7), active.ActivationGeneration)
		})
	}
}

func TestPersistedReplayCandidateSurvivesInterruptedStartup(t *testing.T) {
	for _, outcome := range []string{"confirmed", "absent", "superseded"} {
		t.Run(outcome, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			xid, did := uuid.New(), uuid.New()
			target := schema.SIPURI("sip:alice@example.com")
			details := makeTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})
			task, err := TaskResponseDetailsToInterceptTask(details)
			require.NoError(t, err)
			task.Status, task.ActivationGeneration = TaskStatusActive, 7
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "127.0.0.1", Port: 8443}}}))

			// Simulate two exits after the startup writability checkpoint and
			// before ADMF reconciliation (also covers failed/unsupported sync).
			for i := 0; i < 2; i++ {
				interrupted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
				require.NoError(t, interrupted.restorePersistedState())
				require.Zero(t, interrupted.TaskCount(), "unconfirmed tasks remain disarmed")
				require.False(t, interrupted.ReplayTaskAuthorized(xid, 7))
				require.NoError(t, interrupted.persistState())
			}

			responseTasks := []*schema.TaskResponseDetails{details}
			if outcome == "absent" {
				responseTasks = nil
			}
			response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, responseTasks)
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				if _, err := fmt.Fprint(w, response); err != nil {
					t.Errorf("write ADMF response: %v", err)
				}
			})
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path, ADMFEndpoint: server.URL, SyncOnStartup: true}, nil)
			require.NoError(t, m.Start())
			if outcome == "absent" {
				require.Zero(t, m.TaskCount())
				require.False(t, m.ReplayTaskAuthorized(xid, 7))
			} else {
				active, err := m.GetTaskDetails(xid)
				require.NoError(t, err)
				require.Equal(t, uint64(7), active.ActivationGeneration)
				require.True(t, m.ReplayTaskAuthorized(xid, 7))
			}
			m.Stop()
			if outcome == "superseded" {
				require.NoError(t, m.DeactivateTask(xid))
				require.Equal(t, 1, m.PurgeDeactivatedTasks(0))
				require.NoError(t, m.persistState())
			}
			restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, restarted.restorePersistedState())
			if outcome == "confirmed" {
				require.Contains(t, restarted.persistedActive, xid)
			} else {
				require.NotContains(t, restarted.persistedActive, xid)
				require.NoError(t, restarted.activateStartupTask(task))
				active, err := restarted.GetTaskDetails(xid)
				require.NoError(t, err)
				require.Greater(t, active.ActivationGeneration, uint64(7))
			}
		})
	}
}
