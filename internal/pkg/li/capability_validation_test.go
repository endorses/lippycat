//go:build li

package li

import (
	"errors"
	"fmt"
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
	require.Contains(t, err.Error(), fmt.Sprintf("task XID %s requires X3", task.XID))
	require.NotContains(t, err.Error(), did.String())
	_, lookupErr := registry.GetTaskDetails(task.XID)
	require.ErrorIs(t, lookupErr, ErrTaskNotFound)
}

func TestRegistryValidatesDestinationCapabilitiesAcrossTask(t *testing.T) {
	tests := []struct {
		name         string
		deliveryType DeliveryType
		destinations []*Destination
		wantErr      string
	}{
		{
			name: "combined destination satisfies combined task", deliveryType: DeliveryX2andX3,
			destinations: []*Destination{{X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3"}},
		},
		{
			name: "split destinations satisfy combined task", deliveryType: DeliveryX2andX3,
			destinations: []*Destination{
				{X2Enabled: true, ProtocolType: "X2Only"},
				{X3Enabled: true, ProtocolType: "X3Only"},
			},
		},
		{
			name: "combined task missing X3", deliveryType: DeliveryX2andX3,
			destinations: []*Destination{{X2Enabled: true, ProtocolType: "X2Only"}}, wantErr: "requires X3",
		},
		{
			name: "X2 task with X2 destination", deliveryType: DeliveryX2Only,
			destinations: []*Destination{{X2Enabled: true, ProtocolType: "X2Only"}},
		},
		{
			name: "X2 task with X3 destination", deliveryType: DeliveryX2Only,
			destinations: []*Destination{{X3Enabled: true, ProtocolType: "X3Only"}}, wantErr: "requires X2",
		},
		{
			name: "legacy destination remains compatible", deliveryType: DeliveryX2andX3,
			destinations: []*Destination{{}},
		},
		{
			name: "declared destination with no interface", deliveryType: DeliveryX2Only,
			destinations: []*Destination{{ProtocolType: "unsupported"}}, wantErr: "declares neither X2 nor X3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry(nil)
			dids := make([]uuid.UUID, 0, len(tc.destinations))
			for _, destination := range tc.destinations {
				destination.DID = uuid.New()
				destination.Address = "mdf.example"
				destination.Port = 9443
				require.NoError(t, registry.CreateDestination(destination))
				dids = append(dids, destination.DID)
			}
			task := &InterceptTask{
				XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:alice@example.net"}},
				DestinationIDs: dids, DeliveryType: tc.deliveryType,
			}

			err := registry.ActivateTask(task)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrUnsupportedDeliveryCombination)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestManagerActivatesSplitX2X3DestinationsAndArmsFilters(t *testing.T) {
	pusher := &mockFilterPusher{}
	manager := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher}, nil)
	x2DID := uuid.New()
	x3DID := uuid.New()
	require.NoError(t, manager.CreateDestination(&Destination{
		DID: x2DID, Address: "mdf.example", Port: 9443, X2Enabled: true, ProtocolType: "X2Only",
	}))
	require.NoError(t, manager.CreateDestination(&Destination{
		DID: x3DID, Address: "mdf.example", Port: 9443, X3Enabled: true, ProtocolType: "X3Only",
	}))
	task := &InterceptTask{
		XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:alice@example.net"}},
		DestinationIDs: []uuid.UUID{x2DID, x3DID}, DeliveryType: DeliveryX2andX3,
	}

	require.NoError(t, manager.ActivateTask(task))
	retrieved, err := manager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, retrieved.Status)
	require.Equal(t, 1, manager.FilterCount())
	require.Len(t, pusher.updates, 1)
}
