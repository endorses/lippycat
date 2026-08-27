//go:build li

package li

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// stubFilterStore stands in for the processor's persisted filter set, including
// filters restored from disk that the current process did not create.
type stubFilterStore struct {
	mu      sync.Mutex
	ids     map[string]bool
	deletes []string
}

func newStubFilterStore(preexisting ...string) *stubFilterStore {
	s := &stubFilterStore{ids: make(map[string]bool)}
	for _, id := range preexisting {
		s.ids[id] = true
	}
	return s
}

func (s *stubFilterStore) UpdateFilter(filter *management.Filter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids[filter.Id] = true
	return nil
}

func (s *stubFilterStore) DeleteFilter(filterID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, filterID)
	s.deletes = append(s.deletes, filterID)
	return nil
}

func (s *stubFilterStore) ListFilterIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, id)
	}
	return ids
}

func (s *stubFilterStore) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ids[id]
}

// testDestDID is the delivery destination every task in these tests refers to;
// a task without one is rejected as invalid.
var testDestDID = uuid.MustParse("11111111-2222-3333-4444-555555555555")

// admfServing returns a manager wired to an ADMF that always answers with the
// given tasks. Reconciliation is driven explicitly by the tests.
func admfServing(t *testing.T, store FilterPusher, orphanPolls int, tasks ...*schema.TaskResponseDetails) *Manager {
	t.Helper()

	respXML := buildGetAllDetailsResponseXML(
		[]*schema.DestinationResponseDetails{
			makeDestinationResponseDetails(testDestDID, "10.0.0.1", 8443),
		}, tasks)
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, respXML)
	})

	m := NewManager(ManagerConfig{
		Enabled:              true,
		ADMFEndpoint:         server.URL,
		SyncTimeout:          5 * time.Second,
		ReconcileOrphanPolls: orphanPolls,
		FilterPusher:         store,
	}, nil)
	require.NotNil(t, m)
	require.NotNil(t, m.x1Client)
	createTestDestination(t, m)
	return m
}

func createTestDestination(t *testing.T, m *Manager) {
	t.Helper()
	err := m.CreateDestination(&Destination{
		DID:     testDestDID,
		Address: "10.0.0.1",
		Port:    8443,
	})
	if err != nil && !errors.Is(err, ErrDestinationAlreadyExists) {
		require.NoError(t, err)
	}
}

func activateLocalTask(t *testing.T, m *Manager, xid uuid.UUID) {
	t.Helper()
	require.NoError(t, m.ActivateTask(&InterceptTask{
		XID:            xid,
		Targets:        []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"}},
		DestinationIDs: []uuid.UUID{testDestDID},
		DeliveryType:   DeliveryX2andX3,
	}))
}

func sipURITask(xid uuid.UUID) *schema.TaskResponseDetails {
	sipURI := schema.SIPURI("sip:alice@example.com")
	return makeTaskResponseDetails(xid, []uuid.UUID{testDestDID}, []schema.TargetIdentifier{{SipUri: &sipURI}})
}

// malformedTask fails TaskResponseDetailsToInterceptTask (unparseable XID).
func malformedTask() *schema.TaskResponseDetails {
	bad := schema.UUID("not-a-uuid")
	td := sipURITask(uuid.New())
	td.TaskDetails.XId = &bad
	return td
}

func requireTaskActive(t *testing.T, m *Manager, xid uuid.UUID) {
	t.Helper()
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err, "task %s should still exist", xid)
	assert.Equal(t, TaskStatusActive, task.Status, "task %s should still be active", xid)
}

func requireTaskNotActive(t *testing.T, m *Manager, xid uuid.UUID) {
	t.Helper()
	task, err := m.GetTaskDetails(xid)
	if err != nil {
		return // removed entirely
	}
	assert.NotEqual(t, TaskStatusActive, task.Status, "task %s should have been deactivated", xid)
}

// A filter restored from disk whose task the ADMF no longer has must be removed
// at startup, not re-armed. This is the path that kept a stale intercept alive
// across restarts.
func TestStartupSync_RemovesFilterWithNoADMFTask(t *testing.T) {
	liveXID := uuid.New()
	staleXID := uuid.New()

	staleFilterID := fmt.Sprintf("li-%s-0", staleXID.String()[:8])
	store := newStubFilterStore(staleFilterID, "operator-filter-1")

	m := admfServing(t, store, 1, sipURITask(liveXID))
	m.config.SyncOnStartup = true

	require.NoError(t, m.Start())
	defer m.Stop()

	assert.False(t, store.has(staleFilterID), "stale LI filter should be removed at startup")
	assert.Contains(t, store.deletes, staleFilterID)
	assert.True(t, store.has("operator-filter-1"), "non-LI filters must be left alone")

	requireTaskActive(t, m, liveXID)
}

func TestStartupSync_RetainsAmbiguousLegacyFilterOwnership(t *testing.T) {
	prefix := "a1b2c3d4"
	xidA := uuid.MustParse(prefix + "-0000-4000-8000-000000000001")
	xidB := uuid.MustParse(prefix + "-0000-4000-8000-000000000002")
	legacyID := "li-" + prefix + "-0"
	store := newStubFilterStore(legacyID)

	m := admfServing(t, store, 1, sipURITask(xidA), sipURITask(xidB))
	m.config.SyncOnStartup = true
	require.NoError(t, m.Start())
	defer m.Stop()

	assert.True(t, store.has(legacyID), "ambiguous legacy ownership must fail closed")
	assert.NotContains(t, store.deletes, legacyID)
}

func TestStartupSync_RemovesFiltersForFailedActivation(t *testing.T) {
	xid := uuid.New()
	missingDID := uuid.New()
	filterID := fmt.Sprintf("li-%s-0", xid.String())
	store := newStubFilterStore(filterID)
	sipURI := schema.SIPURI("sip:alice@example.com")
	task := makeTaskResponseDetails(xid, []uuid.UUID{missingDID}, []schema.TargetIdentifier{{SipUri: &sipURI}})

	m := admfServing(t, store, 1, task)
	m.config.SyncOnStartup = true
	require.NoError(t, m.Start())
	defer m.Stop()

	assert.False(t, store.has(filterID), "a refused task must not leave its persisted filter armed")
	assert.Contains(t, store.deletes, filterID)
	_, err := m.GetTaskDetails(xid)
	assert.ErrorIs(t, err, ErrTaskNotFound)
}

func TestStartupSync_RemovesTargetIndexesOutsideActiveTask(t *testing.T) {
	xid := uuid.New()
	canonical := fmt.Sprintf("li-%s-0", xid.String())
	duplicate := fmt.Sprintf("li-%s-1", xid.String())
	store := newStubFilterStore(canonical, duplicate)

	m := admfServing(t, store, 1, sipURITask(xid))
	m.config.SyncOnStartup = true
	require.NoError(t, m.Start())
	defer m.Stop()

	assert.True(t, store.has(canonical))
	assert.False(t, store.has(duplicate), "target index must not exceed the task target list")
	assert.Contains(t, store.deletes, duplicate)
}

// An orphaned task must be torn down, not merely logged.
func TestReconcile_DeactivatesOrphanedTask(t *testing.T) {
	liveXID := uuid.New()
	orphanXID := uuid.New()

	store := newStubFilterStore()
	m := admfServing(t, store, 1, sipURITask(liveXID))

	activateLocalTask(t, m, liveXID)
	activateLocalTask(t, m, orphanXID)

	m.reconcileWithADMF()

	requireTaskNotActive(t, m, orphanXID)
	requireTaskActive(t, m, liveXID)
	assert.Contains(t, store.deletes, fmt.Sprintf("li-%s-0", orphanXID.String()))
}

// A task that fails conversion is missing from the snapshot for reasons
// unrelated to the ADMF's intent, so nothing may be removed that cycle.
func TestReconcile_ConversionErrorSuppressesRemoval(t *testing.T) {
	liveXID := uuid.New()
	orphanXID := uuid.New()

	store := newStubFilterStore()
	m := admfServing(t, store, 1, sipURITask(liveXID), malformedTask())

	activateLocalTask(t, m, orphanXID)

	m.reconcileWithADMF()

	requireTaskActive(t, m, orphanXID)
	assert.Empty(t, store.deletes, "an incomplete ADMF picture must remove nothing")
}

// The ADMF recovery procedure answers successfully with zero tasks while its
// tables are being rebuilt; that must not disarm every intercept.
func TestReconcile_EmptyADMFResponseDoesNotMassTeardown(t *testing.T) {
	xidA := uuid.New()
	xidB := uuid.New()

	store := newStubFilterStore()
	m := admfServing(t, store, 1) // ADMF returns no tasks

	activateLocalTask(t, m, xidA)
	activateLocalTask(t, m, xidB)

	m.reconcileWithADMF()

	requireTaskActive(t, m, xidA)
	requireTaskActive(t, m, xidB)
	assert.Empty(t, store.deletes, "zero-task response must never clear local tasks")
}

// Regression guard for the existing early return: an ADMF outage must leave
// local state untouched, so a connection failure can never tear down warrants.
func TestReconcile_ADMFErrorLeavesStateUntouched(t *testing.T) {
	orphanXID := uuid.New()

	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	store := newStubFilterStore()
	m := NewManager(ManagerConfig{
		Enabled:              true,
		ADMFEndpoint:         server.URL,
		SyncTimeout:          5 * time.Second,
		ReconcileOrphanPolls: 1,
		FilterPusher:         store,
	}, nil)
	require.NotNil(t, m.x1Client)
	createTestDestination(t, m)

	activateLocalTask(t, m, orphanXID)

	m.reconcileWithADMF()

	requireTaskActive(t, m, orphanXID)
	assert.Empty(t, store.deletes)
}

// Periodic reconciliation waits for N consecutive agreeing polls, so a single
// anomalous response cannot drop a warrant.
func TestReconcile_RequiresConsecutivePolls(t *testing.T) {
	liveXID := uuid.New()
	orphanXID := uuid.New()

	store := newStubFilterStore()
	m := admfServing(t, store, 2, sipURITask(liveXID))

	activateLocalTask(t, m, liveXID)
	activateLocalTask(t, m, orphanXID)

	m.reconcileWithADMF()
	requireTaskActive(t, m, orphanXID) // first poll only records the streak

	m.reconcileWithADMF()
	requireTaskNotActive(t, m, orphanXID)
	requireTaskActive(t, m, liveXID)
}

// A task that reappears in the ADMF resets its streak.
func TestReconcile_StreakResetsWhenTaskReappears(t *testing.T) {
	xid := uuid.New()

	var absent bool
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		tasks := []*schema.TaskResponseDetails{sipURITask(xid)}
		if absent {
			tasks = []*schema.TaskResponseDetails{sipURITask(uuid.New())}
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, buildGetAllDetailsResponseXML(nil, tasks))
	})

	store := newStubFilterStore()
	m := NewManager(ManagerConfig{
		Enabled:              true,
		ADMFEndpoint:         server.URL,
		SyncTimeout:          5 * time.Second,
		ReconcileOrphanPolls: 2,
		FilterPusher:         store,
	}, nil)
	createTestDestination(t, m)
	activateLocalTask(t, m, xid)

	absent = true
	m.reconcileWithADMF() // streak 1
	absent = false
	m.reconcileWithADMF() // present again: streak cleared
	absent = true
	m.reconcileWithADMF() // streak 1 again, not 2

	requireTaskActive(t, m, xid)
}

func TestLIFilterXIDPrefix(t *testing.T) {
	tests := []struct {
		id     string
		want   string
		isLI   bool
		reason string
	}{
		{"li-a1b2c3d4-0", "a1b2c3d4", true, "standard LI filter"},
		{"li-a1b2c3d4-12", "a1b2c3d4", true, "multi-digit index"},
		{"operator-filter-1", "", false, "non-LI filter"},
		{"li-", "", false, "no XID or index"},
		{"li-a1b2c3d4", "", false, "no index separator"},
		{"li-a1b2c3d4-", "", false, "empty index"},
	}
	for _, tt := range tests {
		got, isLI := liFilterXIDPrefix(tt.id)
		assert.Equal(t, tt.isLI, isLI, tt.reason)
		assert.Equal(t, tt.want, got, tt.reason)
	}
}
