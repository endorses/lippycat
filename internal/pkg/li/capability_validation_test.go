//go:build li

package li

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegistryRejectsDestinationWithoutRequestedInterface(t *testing.T) {
	registry := NewRegistry(nil)
	did := uuid.New()
	require.NoError(t, registry.CreateDestination(&Destination{
		DID: did, Address: "192.0.2.40", Port: 9443,
		X2Enabled: true, ProtocolType: "X2Only",
	}))
	task := &InterceptTask{
		XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:alice@example.net"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3,
	}
	err := registry.ActivateTask(task)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnsupportedDeliveryCombination))
	_, lookupErr := registry.GetTaskDetails(task.XID)
	require.ErrorIs(t, lookupErr, ErrTaskNotFound)
}
