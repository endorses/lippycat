package filtering

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type transactionPersistence struct {
	mu          sync.Mutex
	stored      map[string]*management.Filter
	fail        error
	saveEntered chan struct{}
	releaseSave chan struct{}
	saves       int
	closed      bool
}

func (p *transactionPersistence) Load(string) (map[string]*management.Filter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneFilterMap(p.stored), nil
}
func (p *transactionPersistence) Save(_ string, candidate map[string]*management.Filter) error {
	if p.saveEntered != nil {
		p.saveEntered <- struct{}{}
		<-p.releaseSave
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	if p.fail == nil || securestore.OutcomeOf(p.fail) != securestore.NotCommitted {
		p.stored = cloneFilterMap(candidate)
	}
	return p.fail
}
func (p *transactionPersistence) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

func TestManagerFailedSaveNeverPublishesOrConsumesRevision(t *testing.T) {
	initial := &management.Filter{Id: "radius", Type: management.FilterType_FILTER_RADIUS_USERNAME, Revision: 1, Pattern: "old", Enabled: true}
	p := &transactionPersistence{stored: map[string]*management.Filter{initial.Id: initial}}
	changes := 0
	m := NewManager("unused", p, nil, nil, func() { changes++ })
	require.NoError(t, m.Load())
	ch := m.AddChannel("hunter")
	failure := errors.New("injected storage failure")
	p.fail = failure
	candidate := proto.Clone(initial).(*management.Filter)
	candidate.Pattern = "new"
	candidate.Revision = 2
	before := proto.Clone(candidate)
	_, err := m.Update(candidate)
	require.ErrorIs(t, err, failure)
	require.True(t, proto.Equal(before, candidate), "caller input must stay detached")
	require.True(t, proto.Equal(initial, m.GetAll()[0]))
	require.Equal(t, uint64(1), m.radiusRevisions[initial.Id])
	require.Nil(t, m.Fault())
	select {
	case <-ch:
		t.Fatal("failed update was published")
	default:
	}
	_, err = m.Delete(initial.Id)
	require.ErrorIs(t, err, failure)
	require.Len(t, m.GetAll(), 1)
	require.Zero(t, changes)
	p.fail = nil
	_, err = m.Update(candidate)
	require.NoError(t, err, "same proposed revision remains reusable after definite failure")
	require.Equal(t, uint64(2), m.radiusRevisions[initial.Id])
	require.NoError(t, m.Close())
	require.True(t, p.closed)
}

func TestManagerGeneratedIDAndNormalizationDoNotMutateCaller(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	input := &management.Filter{Type: management.FilterType_FILTER_PHONE_NUMBER, Pattern: "+1 (555) 010-0123", Enabled: true}
	before := proto.Clone(input)
	accepted, _, err := m.UpdateCommitted(input)
	require.NoError(t, err)
	require.NotEmpty(t, accepted.Id)
	require.NotEqual(t, input.Pattern, accepted.Pattern)
	require.True(t, proto.Equal(before, input))
	accepted.Pattern = "caller changed returned value"
	require.NotEqual(t, accepted.Pattern, m.GetAll()[0].Pattern)
}

func TestManagerUncertainSaveLatchesAndReconcilesOnlyOnRestart(t *testing.T) {
	p := &transactionPersistence{stored: map[string]*management.Filter{}}
	m := NewManager("unused", p, nil, nil, nil)
	ch, snapshot := m.SubscribeSnapshot("hunter")
	require.Empty(t, snapshot)
	p.fail = &securestore.CommitError{Outcome: securestore.Uncertain, Op: "sync directory", Err: errors.New("injected sync failure")}
	input := &management.Filter{Id: "new", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}
	_, err := m.Update(input)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(err))
	require.NotNil(t, m.Fault())
	require.Empty(t, m.GetAll())
	_, open := <-ch
	require.False(t, open, "uncertain policy must invalidate subscriptions")
	p.fail = nil
	_, err = m.Update(input)
	require.ErrorIs(t, err, ErrFilterStoreFault)
	require.Equal(t, 1, p.saves)
	blocked, snapshot := m.SubscribeSnapshot("reconnect")
	require.Empty(t, snapshot)
	_, open = <-blocked
	require.False(t, open)
	require.NoError(t, m.Close())
	restarted := NewManager("unused", p, nil, nil, nil)
	require.NoError(t, restarted.Load())
	require.Len(t, restarted.GetAll(), 1, "restart sees the actually committed candidate")
}

func TestManagerCommittedCleanupErrorPublishesExactlyOnce(t *testing.T) {
	p := &transactionPersistence{stored: map[string]*management.Filter{}}
	m := NewManager("unused", p, nil, nil, nil)
	ch, _ := m.SubscribeSnapshot("hunter")
	p.fail = &securestore.CommitError{Outcome: securestore.Committed, Op: "cleanup", Err: errors.New("injected cleanup failure")}
	accepted, count, err := m.UpdateCommitted(&management.Filter{Id: "accepted", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
	require.Error(t, err)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	require.NotNil(t, accepted)
	require.EqualValues(t, 1, count)
	require.Len(t, m.GetAll(), 1)
	require.Equal(t, "accepted", (<-ch).Filter.Id)
	select {
	case <-ch:
		t.Fatal("policy published twice")
	default:
	}
	require.Nil(t, m.Fault())
}

func TestManagerSnapshotWaitsForDurablePublication(t *testing.T) {
	p := &transactionPersistence{stored: map[string]*management.Filter{}, saveEntered: make(chan struct{}, 1), releaseSave: make(chan struct{})}
	m := NewManager("unused", p, nil, nil, nil)
	require.NoError(t, m.Load())
	updated := make(chan error, 1)
	go func() {
		_, err := m.Update(&management.Filter{Id: "accepted", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
		updated <- err
	}()
	<-p.saveEntered
	require.Empty(t, m.GetAll(), "readers must see the old committed state while disk blocks")
	type subscription struct {
		ch       chan *management.FilterUpdate
		snapshot []*management.Filter
	}
	subscribed := make(chan subscription, 1)
	go func() { ch, snapshot := m.SubscribeSnapshot("hunter"); subscribed <- subscription{ch, snapshot} }()
	select {
	case <-subscribed:
		t.Fatal("subscription passed an unfinished mutation")
	case <-time.After(20 * time.Millisecond):
	}
	close(p.releaseSave)
	require.NoError(t, <-updated)
	result := <-subscribed
	require.Len(t, result.snapshot, 1)
	require.Equal(t, "accepted", result.snapshot[0].Id)
	select {
	case <-result.ch:
		t.Fatal("snapshot included a duplicate queued update")
	default:
	}
}

func TestManagerFirstMutationLoadsExistingCompletePolicy(t *testing.T) {
	old := &management.Filter{Id: "old", Type: management.FilterType_FILTER_BPF, Pattern: "tcp", Enabled: true}
	p := &transactionPersistence{stored: map[string]*management.Filter{old.Id: old}}
	m := NewManager("unused", p, nil, nil, nil)
	_, err := m.Update(&management.Filter{Id: "new", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
	require.NoError(t, err)
	require.Len(t, p.stored, 2)
	require.True(t, proto.Equal(old, p.stored[old.Id]))
}
