//go:build li

package li

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryReactivationValidationIsAtomic(t *testing.T) {
	for _, tc := range []struct {
		name        string
		destination *Destination
		wantErr     error
	}{
		{
			name:    "missing destination",
			wantErr: ErrDestinationNotFound,
		},
		{
			name: "incompatible destination",
			destination: &Destination{
				DID: uuid.New(), Address: "mdf.example", Port: 5001,
				X3Enabled: true, ProtocolType: "X3Only",
			},
			wantErr: ErrUnsupportedDeliveryCombination,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry(nil)
			originalDID := uuid.New()
			require.NoError(t, r.CreateDestination(&Destination{
				DID: originalDID, Address: "mdf.example", Port: 5001,
				X2Enabled: true, ProtocolType: "X2Only",
			}))
			if tc.destination != nil {
				require.NoError(t, r.CreateDestination(tc.destination))
			}

			xid := uuid.New()
			original := &InterceptTask{
				XID:            xid,
				Targets:        []TargetIdentity{{Type: TargetTypeUsername, Value: "alice"}},
				DestinationIDs: []uuid.UUID{originalDID},
				DeliveryType:   DeliveryX2Only,
			}
			require.NoError(t, r.ActivateTask(original))
			require.NoError(t, r.commitActivation(xid, mustTask(t, r, xid).ActivatedAt))
			require.NoError(t, r.DeactivateTask(xid))
			before := mustTask(t, r, xid)
			generationBefore := r.generations[xid]
			historyBefore := append([]InterceptTask(nil), r.auditHistory[xid]...)

			replacement := cloneInterceptTask(original)
			if tc.destination == nil {
				replacement.DestinationIDs = []uuid.UUID{uuid.New()}
			} else {
				replacement.DestinationIDs = []uuid.UUID{tc.destination.DID}
			}
			err := r.ActivateTask(replacement)
			require.ErrorIs(t, err, tc.wantErr)

			assert.Equal(t, before, mustTask(t, r, xid))
			assert.Equal(t, generationBefore, r.generations[xid])
			assert.Equal(t, historyBefore, r.auditHistory[xid])
			assert.NotContains(t, r.rollbackTask, xid)
		})
	}
}

func TestRegistryReactivationRollbackRestoresTombstoneAndAudit(t *testing.T) {
	r := NewRegistry(nil)
	did := uuid.New()
	require.NoError(t, r.CreateDestination(&Destination{
		DID: did, Address: "mdf.example", Port: 5001,
		X2Enabled: true, ProtocolType: "X2Only",
	}))
	xid := uuid.New()
	original := &InterceptTask{
		XID:            xid,
		Targets:        []TargetIdentity{{Type: TargetTypeUsername, Value: "alice"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only,
	}
	require.NoError(t, r.ActivateTask(original))
	require.NoError(t, r.commitActivation(xid, mustTask(t, r, xid).ActivatedAt))
	require.NoError(t, r.DeactivateTask(xid))
	tombstone := mustTask(t, r, xid)

	replacement := cloneInterceptTask(original)
	replacement.ImplicitDeactivationAllowed = true
	require.NoError(t, r.ActivateTask(replacement))
	provisional := mustTask(t, r, xid)
	require.Equal(t, tombstone.ActivationGeneration+1, provisional.ActivationGeneration)
	require.Len(t, r.auditHistory[xid], 1)
	require.Contains(t, r.rollbackTask, xid)

	require.NoError(t, r.rollbackActivation(xid, provisional.ActivatedAt))
	assert.Equal(t, tombstone, mustTask(t, r, xid))
	assert.Empty(t, r.auditHistory[xid])
	assert.NotContains(t, r.rollbackTask, xid)
	// Failed provisional activations consume an internal generation, while the
	// restored task remains externally visible at its prior generation.
	assert.Equal(t, provisional.ActivationGeneration, r.generations[xid])
}

func mustTask(t *testing.T, r *Registry, xid uuid.UUID) *InterceptTask {
	t.Helper()
	task, err := r.GetTaskDetails(xid)
	require.NoError(t, err)
	return task
}
