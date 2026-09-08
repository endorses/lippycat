//go:build li

package li

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestStartupReplayGenerationRequiresSameTaskDefinition(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			did, xid := uuid.New(), uuid.New()
			target := schema.SIPURI("sip:alice@example.com")
			details := makeTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})
			restored, err := TaskResponseDetailsToInterceptTask(details)
			require.NoError(t, err)
			restored.ActivationGeneration = 7
			if changed {
				restored.Targets[0].Value = "sip:previous@example.com"
			}
			response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{details})
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				if _, err := fmt.Fprint(w, response); err != nil {
					t.Errorf("write ADMF response: %v", err)
				}
			})
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true}, nil)
			m.persistedActive[xid] = restored
			require.NoError(t, m.Start())
			defer m.Stop()
			active, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			expected := uint64(7)
			if changed {
				expected = 8
			}
			require.Equal(t, expected, active.ActivationGeneration)
			require.Equal(t, !changed, m.ReplayTaskAuthorized(xid, 7))
		})
	}
}

func TestTaskDestinationModificationRevokesDeliveryGeneration(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	first, second, xid := uuid.New(), uuid.New(), uuid.New()
	for _, did := range []uuid.UUID{first, second} {
		require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 8443}))
	}
	require.NoError(t, m.ActivateTask(&InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{first}, DeliveryType: DeliveryX2andX3}))
	previous, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	var revoked uint64
	m.SetTaskModifiedCallback(func(task *InterceptTask) { revoked = task.ActivationGeneration })
	destinations := []uuid.UUID{second}
	require.NoError(t, m.ModifyTask(xid, &TaskModification{DestinationIDs: &destinations}))
	require.Equal(t, previous.ActivationGeneration, revoked)
	_, valid := m.AcquireTaskAdmission(xid, previous.ActivationGeneration)
	require.False(t, valid)
	current, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Greater(t, current.ActivationGeneration, previous.ActivationGeneration)
	admission, valid := m.AcquireTaskAdmission(xid, current.ActivationGeneration)
	require.True(t, valid)
	admission.Release()
	revoked = 0
	require.NoError(t, m.ModifyTask(xid, &TaskModification{DestinationIDs: &destinations}))
	require.Zero(t, revoked, "equivalent modification does not revoke delivery")
}
