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
func TestIPX3ActivationAccepted(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X3Enabled: true}))
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeIPv6CIDR, Value: "2001:db8::/32"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX3Only}
	require.NoError(t, m.ActivateTask(task))
	require.Equal(t, 1, m.FilterCount())
}
