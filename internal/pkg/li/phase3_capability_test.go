//go:build li

package li

import (
	"errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIPX2OnlyRejectedBeforeFilterInstall(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeIPv4Address, Value: "192.0.2.1"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2Only}
	err := m.ActivateTask(task)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnsupportedDeliveryCombination))
	require.Zero(t, m.FilterCount())
	require.Equal(t, uint64(1), m.Stats().RejectedCombinations)
}
func TestIPX3ActivationRejectedUntilRawIPSessionModelExists(t *testing.T) {
	tests := []TargetIdentity{
		{Type: TargetTypeIPv4Address, Value: "192.0.2.1"},
		{Type: TargetTypeIPv4CIDR, Value: "192.0.2.0/24"},
		{Type: TargetTypeIPv6Address, Value: "2001:db8::1"},
		{Type: TargetTypeIPv6CIDR, Value: "2001:db8::/32"},
	}
	for _, target := range tests {
		for _, deliveryType := range []DeliveryType{DeliveryX3Only, DeliveryX2andX3} {
			t.Run(target.Type.String()+"/"+deliveryType.String(), func(t *testing.T) {
				m := NewManager(ManagerConfig{Enabled: true}, nil)
				did := uuid.New()
				require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true}))
				task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{target}, DestinationIDs: []uuid.UUID{did}, DeliveryType: deliveryType}
				err := m.ActivateTask(task)
				require.Error(t, err)
				require.True(t, errors.Is(err, ErrUnsupportedDeliveryCombination))
				require.Zero(t, m.FilterCount())
			})
		}
	}
}
