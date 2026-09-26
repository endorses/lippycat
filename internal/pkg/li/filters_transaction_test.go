package li

import (
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type callbackFilterPusher struct {
	update func(*management.Filter) error
	remove func(string) error
}

func (p *callbackFilterPusher) UpdateFilter(f *management.Filter) error { return p.update(f) }
func (p *callbackFilterPusher) DeleteFilter(id string) error            { return p.remove(id) }

func filterTransactionTask(xid uuid.UUID, targets ...string) *InterceptTask {
	task := &InterceptTask{XID: xid, DeliveryType: DeliveryX2Only}
	for _, target := range targets {
		task.Targets = append(task.Targets, TargetIdentity{Type: TargetTypeUsername, Value: target})
	}
	return task
}

func TestFilterMutationPushAllowsPacketLookups(t *testing.T) {
	m := NewFilterManager(nil)
	xid := uuid.New()
	ids, err := m.CreateFiltersForTask(filterTransactionTask(xid, "old"))
	require.NoError(t, err)
	lookup := func() {
		_, _ = m.LookupFilter(ids[0])
		_ = m.LookupMatches(ids)
		_ = m.GetFiltersForXID(xid)
	}
	m.filterPusher = &callbackFilterPusher{
		update: func(f *management.Filter) error { lookup(); f.Pattern = "pusher mutation"; return nil },
		remove: func(string) error { lookup(); return nil },
	}
	done := make(chan error, 1)
	go func() {
		if _, err := m.CreateFiltersForTask(filterTransactionTask(uuid.New(), "other")); err != nil {
			done <- err
			return
		}
		if err := m.UpdateFiltersForTask(filterTransactionTask(xid, "replacement")); err != nil {
			done <- err
			return
		}
		match, _ := m.LookupFilter(ids[0])
		if match.Filter.Pattern != "replacement" {
			done <- errors.New("external pusher mutated the published candidate")
			return
		}
		match.Filter.Pattern = "reader mutation"
		still, _ := m.LookupFilter(ids[0])
		if still.Filter.Pattern != "replacement" {
			done <- errors.New("lookup exposed mutable policy")
			return
		}
		done <- m.RemoveFiltersForTask(xid)
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("external push blocked packet lookup/drain")
	}
}

func TestFilterCreateCommittedFailureCompensatesCurrentID(t *testing.T) {
	installed := make(map[string]bool)
	deletes := 0
	p := &callbackFilterPusher{
		update: func(f *management.Filter) error {
			installed[f.Id] = true
			return &securestore.CommitError{Outcome: securestore.Committed, Op: "distribution", Err: errors.New("warning")}
		},
		remove: func(id string) error { deletes++; delete(installed, id); return nil },
	}
	m := NewFilterManager(p)
	xid := uuid.New()
	_, err := m.CreateFiltersForTask(filterTransactionTask(xid, "candidate"))
	require.Error(t, err)
	require.Equal(t, 1, deletes)
	require.Empty(t, installed)
	require.Empty(t, m.GetFiltersForXID(xid))
	require.Zero(t, m.FilterCount())
}

func TestFilterCreateUncertaintyRetainsCleanupWithoutAuthorizing(t *testing.T) {
	updates, deletes := 0, 0
	p := &callbackFilterPusher{
		update: func(*management.Filter) error {
			updates++
			return &securestore.CommitError{Outcome: securestore.Uncertain, Op: "sync", Err: errors.New("fault")}
		},
		remove: func(string) error { deletes++; return nil },
	}
	m := NewFilterManager(p)
	xid := uuid.New()
	_, err := m.CreateFiltersForTask(filterTransactionTask(xid, "first", "second"))
	var cleanup *FilterCleanupError
	require.ErrorAs(t, err, &cleanup)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(err))
	require.Equal(t, 1, updates)
	require.Zero(t, deletes, "uncertainty must stop further external mutations")
	ids := m.GetFiltersForXID(xid)
	require.Len(t, ids, 1)
	require.Empty(t, m.LookupMatches(ids))
	require.Zero(t, m.FilterCount())
	require.NoError(t, m.RemoveFiltersForTask(xid))
	require.Equal(t, 1, deletes)
	require.Empty(t, m.GetFiltersForXID(xid))
}

func TestFilterReplacementFailedCompensationCannotRestoreAuthorization(t *testing.T) {
	m := NewFilterManager(nil)
	xid := uuid.New()
	ids, err := m.CreateFiltersForTask(filterTransactionTask(xid, "old-first", "old-second"))
	require.NoError(t, err)
	updates := 0
	m.filterPusher = &callbackFilterPusher{
		update: func(*management.Filter) error {
			updates++
			if updates >= 2 {
				return errors.New("failed new push and compensation")
			}
			return nil
		},
		remove: func(string) error { return nil },
	}
	err = m.UpdateFiltersForTask(filterTransactionTask(xid, "new-first", "new-second"))
	var cleanup *FilterCleanupError
	require.ErrorAs(t, err, &cleanup)
	require.Equal(t, ids, m.GetFiltersForXID(xid))
	_, active := m.LookupFilter(ids[0])
	require.False(t, active, "unrestored identity must be cleanup-only")
	old, active := m.LookupFilter(ids[1])
	require.True(t, active)
	require.Equal(t, "old-second", old.Filter.Pattern)
}

func TestFilterRemovalCommittedWarningsDoNotRetainDeletedIDs(t *testing.T) {
	m := NewFilterManager(nil)
	xid := uuid.New()
	_, err := m.CreateFiltersForTask(filterTransactionTask(xid, "first", "second"))
	require.NoError(t, err)
	deletes := 0
	m.filterPusher = &callbackFilterPusher{
		update: func(*management.Filter) error { return nil },
		remove: func(string) error {
			deletes++
			return &securestore.CommitError{Outcome: securestore.Committed, Op: "cleanup", Err: errors.New("warning")}
		},
	}
	err = m.RemoveFiltersForTask(xid)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	require.Equal(t, 2, deletes)
	require.Empty(t, m.GetFiltersForXID(xid))
	require.Zero(t, m.FilterCount())
}

func TestFilterRemovalUncertaintyStopsAndRetainsCleanupIDs(t *testing.T) {
	m := NewFilterManager(nil)
	xid := uuid.New()
	ids, err := m.CreateFiltersForTask(filterTransactionTask(xid, "first", "second"))
	require.NoError(t, err)
	deletes := 0
	m.filterPusher = &callbackFilterPusher{
		update: func(*management.Filter) error { return nil },
		remove: func(string) error {
			deletes++
			return &securestore.CommitError{Outcome: securestore.Uncertain, Op: "sync", Err: errors.New("fault")}
		},
	}
	err = m.RemoveFiltersForTask(xid)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(err))
	require.Equal(t, 1, deletes)
	require.Equal(t, ids, m.GetFiltersForXID(xid))
	require.Empty(t, m.LookupMatches(ids))
}
