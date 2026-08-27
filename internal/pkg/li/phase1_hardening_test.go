//go:build li

package li

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
)

type transactionalPusher struct {
	mu             sync.Mutex
	installed      map[string]*management.Filter
	updateCalls    int
	failUpdateCall int
	failDeletes    map[string]bool
}

func newTransactionalPusher() *transactionalPusher {
	return &transactionalPusher{installed: make(map[string]*management.Filter), failDeletes: make(map[string]bool)}
}

func (p *transactionalPusher) UpdateFilter(filter *management.Filter) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updateCalls++
	if p.updateCalls == p.failUpdateCall {
		return errors.New("injected update failure")
	}
	p.installed[filter.Id] = filter
	return nil
}

func (p *transactionalPusher) DeleteFilter(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDeletes[id] {
		return errors.New("injected delete failure")
	}
	delete(p.installed, id)
	return nil
}

func phase1Task(xid uuid.UUID, targets ...string) *InterceptTask {
	task := &InterceptTask{XID: xid, DeliveryType: DeliveryX2Only}
	for _, target := range targets {
		task.Targets = append(task.Targets, TargetIdentity{Type: TargetTypeUsername, Value: target})
	}
	return task
}

func TestFilterCreatePushFailureIsTransactional(t *testing.T) {
	t.Run("first push", func(t *testing.T) {
		p := newTransactionalPusher()
		p.failUpdateCall = 1
		m := NewFilterManager(p)
		_, err := m.CreateFiltersForTask(phase1Task(uuid.New(), "one", "two"))
		require.Error(t, err)
		assert.Empty(t, p.installed)
		assert.Zero(t, m.FilterCount())
		assert.Zero(t, m.TaskCount())
	})

	t.Run("later push rolls back", func(t *testing.T) {
		p := newTransactionalPusher()
		p.failUpdateCall = 2
		m := NewFilterManager(p)
		_, err := m.CreateFiltersForTask(phase1Task(uuid.New(), "one", "two"))
		require.Error(t, err)
		assert.Empty(t, p.installed)
		assert.Zero(t, m.FilterCount())
	})

	t.Run("rollback failure identifies residual", func(t *testing.T) {
		xid := uuid.New()
		p := newTransactionalPusher()
		p.failUpdateCall = 2
		residual := "li-" + xid.String() + "-0"
		p.failDeletes[residual] = true
		m := NewFilterManager(p)
		_, err := m.CreateFiltersForTask(phase1Task(xid, "one", "two"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), residual)
		assert.Contains(t, p.installed, residual)
		assert.Zero(t, m.FilterCount())
	})
}

func TestFilterUpdateFailurePreservesOriginalAndCleanupIsRetryable(t *testing.T) {
	xid := uuid.New()
	p := newTransactionalPusher()
	m := NewFilterManager(p)
	original, err := m.CreateFiltersForTask(phase1Task(xid, "old", "remove-me"))
	require.NoError(t, err)

	p.failUpdateCall = p.updateCalls + 1
	err = m.UpdateFiltersForTask(phase1Task(xid, "new"))
	require.Error(t, err)
	assert.Equal(t, original, m.GetFiltersForXID(xid))
	assert.Contains(t, p.installed, original[0])

	p.failUpdateCall = 0
	p.failDeletes[original[1]] = true
	err = m.UpdateFiltersForTask(phase1Task(xid, "new"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), original[1])
	assert.Contains(t, m.GetFiltersForXID(xid), original[1])

	delete(p.failDeletes, original[1])
	require.NoError(t, m.RemoveFiltersForTask(xid))
	assert.Empty(t, p.installed)
}

func TestActivationFailureCanRetrySameXID(t *testing.T) {
	p := newTransactionalPusher()
	p.failUpdateCall = 1
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: p}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 1}))
	task := phase1Task(uuid.New(), "alice")
	task.DestinationIDs = []uuid.UUID{did}

	require.Error(t, m.ActivateTask(task))
	_, err := m.GetTaskDetails(task.XID)
	assert.ErrorIs(t, err, ErrTaskNotFound)
	p.failUpdateCall = 0
	require.NoError(t, m.ActivateTask(task))
}

func TestActivationRollbackCannotRemoveAnotherActivation(t *testing.T) {
	r := NewRegistry(nil)
	did := uuid.New()
	require.NoError(t, r.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 1}))
	task := phase1Task(uuid.New(), "alice")
	task.DestinationIDs = []uuid.UUID{did}
	require.NoError(t, r.ActivateTask(task))
	registered, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)

	err = r.rollbackActivation(task.XID, registered.ActivatedAt.Add(-time.Nanosecond))
	require.Error(t, err)
	stillRegistered, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, registered.ActivatedAt, stillRegistered.ActivatedAt)
}

func TestFullXIDFilterIDsDoNotCollide(t *testing.T) {
	xid1 := uuid.MustParse("12345678-0000-4000-8000-000000000001")
	xid2 := uuid.MustParse("12345678-0000-4000-8000-000000000002")
	p := newTransactionalPusher()
	m := NewFilterManager(p)
	ids1, err := m.CreateFiltersForTask(phase1Task(xid1, "one"))
	require.NoError(t, err)
	ids2, err := m.CreateFiltersForTask(phase1Task(xid2, "two"))
	require.NoError(t, err)
	require.NotEqual(t, ids1[0], ids2[0])
	assert.True(t, strings.Contains(ids1[0], xid1.String()))
	require.NoError(t, m.RemoveFiltersForTask(xid1))
	_, ok := m.GetFilter(ids2[0])
	assert.True(t, ok)

	owner, ok := liFilterXIDPrefix(ids2[0])
	assert.True(t, ok)
	assert.Equal(t, xid2.String(), owner)
	owner, ok = liFilterXIDPrefix("li-12345678-3")
	assert.True(t, ok)
	assert.Equal(t, "12345678", owner)
}
