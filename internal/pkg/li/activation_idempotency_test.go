//go:build li

package li

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIdempotencyManager(t *testing.T, stateFile string) (*Manager, *mockFilterPusher, []uuid.UUID) {
	t.Helper()
	pusher := &mockFilterPusher{}
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher, StateFile: stateFile}, nil)
	dids := []uuid.UUID{uuid.New(), uuid.New()}
	for _, did := range dids {
		require.NoError(t, m.CreateDestination(&Destination{
			DID: did, Address: "mdf.example", Port: 5001, X2Enabled: true, X3Enabled: true,
		}))
	}
	return m, pusher, dids
}

func idempotencyTask(xid uuid.UUID, dids []uuid.UUID, start time.Time) *InterceptTask {
	return &InterceptTask{
		XID: xid,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example"},
			{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
		},
		DestinationIDs: dids, DeliveryType: DeliveryX2andX3,
		StartTime: start, EndTime: time.Now().Add(24 * time.Hour).UTC(),
		ImplicitDeactivationAllowed: true,
	}
}

func cloneActivationTask(task *InterceptTask) *InterceptTask {
	copyTask := *task
	copyTask.Targets = append([]TargetIdentity(nil), task.Targets...)
	copyTask.DestinationIDs = append([]uuid.UUID(nil), task.DestinationIDs...)
	return &copyTask
}

func TestActivateTaskEquivalentRetryIsNoOp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start time.Time
	}{
		{name: "active"},
		{name: "pending", start: time.Now().Add(time.Hour).UTC()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, pusher, dids := newIdempotencyManager(t, "")
			task := idempotencyTask(uuid.New(), dids, tc.start)
			require.NoError(t, m.ActivateTask(task))
			before, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			pusher.reset()

			retry := cloneActivationTask(task)
			retry.Targets[0], retry.Targets[1] = retry.Targets[1], retry.Targets[0]
			retry.Targets = append(retry.Targets, retry.Targets[0])
			retry.DestinationIDs[0], retry.DestinationIDs[1] = retry.DestinationIDs[1], retry.DestinationIDs[0]
			retry.DestinationIDs = append(retry.DestinationIDs, retry.DestinationIDs[0])
			retry.StartTime = retry.StartTime.In(time.FixedZone("peer", 3600))
			retry.EndTime = retry.EndTime.In(time.FixedZone("peer", -3600))
			require.NoError(t, m.ActivateTask(retry))

			after, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			assert.Empty(t, pusher.updates)
			assert.Empty(t, pusher.deletes)
		})
	}
}

func TestActivateTaskConflictingRetryIsAtomic(t *testing.T) {
	mutations := map[string]func(*InterceptTask, []uuid.UUID){
		"target":           func(v *InterceptTask, _ []uuid.UUID) { v.Targets[0].Value = "sip:bob@example" },
		"destination":      func(v *InterceptTask, ds []uuid.UUID) { v.DestinationIDs = ds[1:] },
		"delivery type":    func(v *InterceptTask, _ []uuid.UUID) { v.DeliveryType = DeliveryX2Only },
		"start time":       func(v *InterceptTask, _ []uuid.UUID) { v.StartTime = time.Now().Add(time.Minute) },
		"end time":         func(v *InterceptTask, _ []uuid.UUID) { v.EndTime = v.EndTime.Add(time.Minute) },
		"lifecycle option": func(v *InterceptTask, _ []uuid.UUID) { v.ImplicitDeactivationAllowed = false },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m, pusher, dids := newIdempotencyManager(t, "")
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			before, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			filtersBefore := m.filters.GetFiltersForXID(task.XID)
			pusher.reset()
			retry := cloneActivationTask(task)
			mutate(retry, dids)

			err = m.ActivateTask(retry)
			require.ErrorIs(t, err, ErrTaskDefinitionConflict)
			after, getErr := m.GetTaskDetails(task.XID)
			require.NoError(t, getErr)
			assert.Equal(t, before, after)
			assert.Equal(t, filtersBefore, m.filters.GetFiltersForXID(task.XID))
			assert.Empty(t, pusher.updates)
			assert.Empty(t, pusher.deletes)
		})
	}
}

func TestActivateTaskConcurrentDuplicatesConverge(t *testing.T) {
	m, pusher, dids := newIdempotencyManager(t, "")
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	const attempts = 24
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.ActivateTask(cloneActivationTask(task))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	stored, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), stored.ActivationGeneration)
	assert.Len(t, pusher.updates, len(task.Targets))
}

func TestActivateTaskRetryAfterPendingRestoration(t *testing.T) {
	stateFile := t.TempDir() + "/li-state.json"
	m1, _, dids := newIdempotencyManager(t, stateFile)
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
	require.NoError(t, m1.ActivateTask(task))

	pusher := &mockFilterPusher{}
	m2 := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher, StateFile: stateFile}, nil)
	require.NoError(t, m2.Start())
	t.Cleanup(m2.Stop)
	beforeBytes, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	before, err := m2.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.NoError(t, m2.ActivateTask(cloneActivationTask(task)))
	after, err := m2.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	afterBytes, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	assert.Equal(t, beforeBytes, afterBytes)

	conflict := cloneActivationTask(task)
	conflict.Targets[0].Value = "sip:conflict@example"
	require.ErrorIs(t, m2.ActivateTask(conflict), ErrTaskDefinitionConflict)
	afterConflict, err := m2.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, before, afterConflict)
	conflictBytes, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	assert.Equal(t, beforeBytes, conflictBytes)
	assert.Empty(t, pusher.updates)
	assert.Empty(t, pusher.deletes)
}

func TestActivateTaskClosedLifecycleStatesConflict(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusSuspended, TaskStatusFailed, TaskStatusDeactivated} {
		t.Run(status.String(), func(t *testing.T) {
			m, _, dids := newIdempotencyManager(t, "")
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			switch status {
			case TaskStatusSuspended:
				m.registry.mu.Lock()
				m.registry.tasks[task.XID].Status = TaskStatusSuspended
				m.registry.mu.Unlock()
			case TaskStatusFailed:
				require.NoError(t, m.registry.MarkTaskFailed(task.XID, "test"))
			case TaskStatusDeactivated:
				require.NoError(t, m.registry.DeactivateTask(task.XID))
			}
			err := m.ActivateTask(cloneActivationTask(task))
			require.True(t, errors.Is(err, ErrTaskDefinitionConflict), err)
		})
	}
}
