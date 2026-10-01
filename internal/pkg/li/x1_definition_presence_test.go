//go:build li

package li

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestOmittedX1ActivationCannotCompletePartialPull(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true, ADMFCompleteTaskContract: strict}, nil)
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			partial := applyConvergence(t, m, convergenceDetails(xid, did, false))
			push := &x1.Task{XID: xid, Targets: []x1.TargetIdentity{{Type: x1.TargetTypeSIPURI, Value: partial.Task.Targets[0].Value}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: x1.DeliveryX2andX3, DefinitionPresence: &x1.TaskDefinitionPresence{}}
			before := m.Stats().Definitions
			// An equivalent compatibility retry may succeed as a pure no-op;
			// a strict candidate cannot become enforcing from an incomplete push.
			err := m.ActivateTaskX1(push)
			require.NoError(t, err)
			if strict {
				_, getErr := m.GetTaskDetails(xid)
				require.ErrorIs(t, getErr, ErrTaskNotFound)
				require.Zero(t, m.FilterCount())
				require.Equal(t, DefinitionPull, m.persistenceCandidates[xid].Definition.Source)
			} else {
				live, getErr := m.GetTaskDetails(xid)
				require.NoError(t, getErr)
				require.Equal(t, DefinitionPull, live.Definition.Source)
				require.False(t, live.Definition.Completeness.Complete())
				readback, getErr := m.GetTaskDetailsX1(xid)
				require.NoError(t, getErr)
				require.Equal(t, &x1.TaskDefinitionPresence{}, readback.DefinitionPresence)
			}
			require.Equal(t, before, m.Stats().Definitions)
			push.Targets[0].Value = "sip:different@example.invalid"
			require.ErrorIs(t, m.ActivateTaskX1(push), x1.ErrTaskDefinitionConflict)
			require.Equal(t, before, m.Stats().Definitions)
			push.Targets[0].Value = partial.Task.Targets[0].Value
			full, convErr := ConvertSnapshotTask(convergenceDetails(xid, did, true))
			require.NoError(t, convErr)
			push.StartTime = full.Task.StartTime
			push.ImplicitDeactivationAllowed = full.Task.ImplicitDeactivationAllowed
			push.DefinitionPresence = &x1.TaskDefinitionPresence{Mediation: true, Start: true, End: true, Implicit: true}
			require.NoError(t, m.ActivateTaskX1(push))
			live, getErr := m.GetTaskDetails(xid)
			require.NoError(t, getErr)
			require.Equal(t, DefinitionPush, live.Definition.Source)
			require.True(t, live.Definition.Completeness.Complete())
		})
	}
}
