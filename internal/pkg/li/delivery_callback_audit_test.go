//go:build li

package li

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTaskModificationCallbackDoesNotTakeStartupMutex(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	first, second, xid := uuid.New(), uuid.New(), uuid.New()
	for _, did := range []uuid.UUID{first, second} {
		require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	}
	require.NoError(t, m.ActivateTask(&InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{first}, DeliveryType: DeliveryX2andX3}))
	invoked := make(chan struct{}, 1)
	m.SetTaskModifiedCallback(func(*InterceptTask) { invoked <- struct{}{} })
	m.mu.Lock()
	done := make(chan error, 1)
	go func() {
		destinations := []uuid.UUID{second}
		done <- m.ModifyTask(xid, &TaskModification{DestinationIDs: &destinations})
	}()
	select {
	case err := <-done:
		m.mu.Unlock()
		require.NoError(t, err)
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("modification blocked on startup mutex")
	}
	<-invoked
}

func TestDegradedTaskModificationRevokesPreviousDeliveryGeneration(t *testing.T) {
	pusher := newTransactionalPusher()
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher}, nil)
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	task := &InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}, {Type: TargetTypeSIPURI, Value: "bob@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3}
	require.NoError(t, m.ActivateTask(task))
	previous, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	ids := m.filters.GetFiltersForXID(xid)
	require.Len(t, ids, 2)
	pusher.failDeletes[ids[1]] = true
	var revoked uint64
	m.SetTaskModifiedCallback(func(old *InterceptTask) { revoked = old.ActivationGeneration })
	targets := previous.Targets[:1]
	require.Error(t, m.ModifyTask(xid, &TaskModification{Targets: &targets}))
	require.Equal(t, previous.ActivationGeneration, revoked)
	current, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusFailed, current.Status)
}

func TestDestinationCallbacksPublishCanonicalIncarnationExactlyOnce(t *testing.T) {
	for _, viaX1 := range []bool{false, true} {
		t.Run(map[bool]string{false: "programmatic", true: "x1"}[viaX1], func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true}, nil)
			did := uuid.New()
			created, modified, removed := 0, 0, 0
			check := func(dest *Destination) {
				canonical, err := m.GetDestination(did)
				require.NoError(t, err)
				require.False(t, dest.CreatedAt.IsZero())
				require.Equal(t, DestinationDeliveryGeneration(canonical), DestinationDeliveryGeneration(dest))
			}
			m.SetDestinationCreatedCallback(func(dest *Destination) { created++; check(dest) })
			m.SetDestinationModifiedCallback(func(dest *Destination) { modified++; check(dest) })
			m.SetDestinationRemovedCallback(func(got uuid.UUID) { removed++; require.Equal(t, did, got) })
			if viaX1 {
				require.NoError(t, m.CreateDestinationX1(&x1.Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
				require.NoError(t, m.ModifyDestinationX1(did, &x1.Destination{DID: did, Address: "127.0.0.2", Port: 8443}))
				require.NoError(t, m.RemoveDestinationX1(did))
			} else {
				require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
				require.NoError(t, m.ModifyDestination(did, &Destination{DID: did, Address: "127.0.0.2", Port: 8443}))
				require.NoError(t, m.RemoveDestination(did))
			}
			require.Equal(t, 1, created)
			require.Equal(t, 1, modified)
			require.Equal(t, 1, removed)
		})
	}
}
