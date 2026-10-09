//go:build li

package li

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestCallCorrelationWaitDeadlinePinsEveryLateOutcome(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/async=%t", securestore.OutcomeName(outcome), async), func(t *testing.T) {
				cfg := DefaultCallCorrelationConfig()
				cfg.SessionHeaders = []string{"X-Session"}
				cfg.WaitTimeout = 30 * time.Millisecond
				store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), correlationFakeStore: correlationFakeStore{outcomes: []securestore.Outcome{outcome}}}
				c, now := newContractCorrelator(t, cfg, store)
				t.Cleanup(func() {
					select {
					case <-store.release:
					default:
						close(store.release)
					}
					require.NoError(t, c.Close())
				})
				root := contractResolve(c, contractHeader(contractInvite("deadline-root", 0, *now), "X-Session", "same"))
				child := contractHeader(contractInvite("deadline-child", 4, *now), "X-Session", "same")
				products := make(chan CallCorrelationDecision, 3)
				if async {
					require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) { c.Published(d); products <- d }))
				} else {
					go func() { d := contractResolve(c, child); c.Published(d); products <- d }()
				}
				<-store.entered
				c.mu.Lock()
				deadline := c.records[child.VoIPData.CallID].deadline
				c.mu.Unlock()
				require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) { c.Published(d); products <- d }))
				c.mu.Lock()
				require.Equal(t, deadline, c.records[child.VoIPData.CallID].deadline, "additional packets cannot renew the logical deadline")
				c.mu.Unlock()
				for range 2 {
					select {
					case d := <-products:
						require.Equal(t, root.CorrelationID, d.CorrelationID)
					case <-time.After(5 * time.Second):
						t.Fatal("adopted product waited for physical storage completion")
					}
				}
				require.Equal(t, uint64(1), c.Stats().WaitTimeouts)
				require.Zero(t, c.Stats().DeferredPackets)
				c.Finalize(child.VoIPData.CallID)
				require.NoError(t, c.Maintain(), "retry must not compete with the active physical write")
				other := contractResolve(c, contractHeader(contractInvite("deadline-other", 8, *now), "X-Session", "same"))
				require.Equal(t, "persistence_busy", other.Reason)
				close(store.release)
				c.asyncWG.Wait()
				d := contractResolve(c, child)
				require.Equal(t, root.CorrelationID, d.CorrelationID, "late NotCommitted cannot revert a released ID")
				require.NoError(t, c.Maintain())
				require.Len(t, store.records, 1)
				require.Equal(t, root.CorrelationID, store.records[0].GroupID)
				require.False(t, store.records[0].TerminalUntil.IsZero(), "retry retains the newer revision")
				require.Zero(t, c.Stats().UnresolvedWrites)
				require.NoError(t, c.Close())
			})
		}
	}
}

func TestCallCorrelationPressurePinsIDAndPreservesFIFO(t *testing.T) {
	for _, bytePressure := range []bool{false, true} {
		for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
			t.Run(fmt.Sprintf("bytes=%t/%s", bytePressure, securestore.OutcomeName(outcome)), func(t *testing.T) {
				cfg := DefaultCallCorrelationConfig()
				cfg.SessionHeaders = []string{"X-Session"}
				cfg.MaxCandidates = 2
				store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), correlationFakeStore: correlationFakeStore{outcomes: []securestore.Outcome{outcome}}}
				c, now := newContractCorrelator(t, cfg, store)
				t.Cleanup(func() {
					select {
					case <-store.release:
					default:
						close(store.release)
					}
					require.NoError(t, c.Close())
				})
				root := contractResolve(c, contractHeader(contractInvite("pressure-root", 0, *now), "X-Session", "same"))
				child := contractHeader(contractInvite("pressure-child", 4, *now), "X-Session", "same")
				products := make(chan int, 4)
				bytes := 100
				if bytePressure {
					bytes = maxCallCorrelationStoreBytes/2 + 1
				}
				callback := func(i int) func(CallCorrelationDecision) {
					return func(d CallCorrelationDecision) {
						require.Equal(t, root.CorrelationID, d.CorrelationID)
						c.Published(d)
						products <- i
					}
				}
				require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, bytes, callback(0)))
				<-store.entered
				for i := 1; i < 4; i++ {
					require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, bytes, callback(i)))
				}
				for i := 0; i < 4; i++ {
					require.Equal(t, i, <-products)
				}
				s := c.Stats()
				require.Equal(t, uint64(1), s.PressureReleases)
				require.Zero(t, s.DeferredRejected)
				require.Zero(t, s.DeferredPackets)
				require.Zero(t, s.WaitTimeouts)
				close(store.release)
				c.asyncWG.Wait()
				require.Equal(t, root.CorrelationID, contractResolve(c, child).CorrelationID)
				require.NoError(t, c.Close())
			})
		}
	}
}

type closingBlockedCorrelationStore struct {
	blockedCorrelationStore
	closed chan struct{}
	closes atomic.Int32
}

func (s *closingBlockedCorrelationStore) Close() error {
	if s.closes.Add(1) == 1 {
		close(s.closed)
	}
	return nil
}

func TestCallCorrelationCloseDeadlineRetainsPhysicalOwner(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		t.Run(fmt.Sprint(maintenance), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			cfg.ShutdownTimeout = 30 * time.Millisecond
			store := &closingBlockedCorrelationStore{blockedCorrelationStore: blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), correlationFakeStore: correlationFakeStore{outcomes: []securestore.Outcome{securestore.NotCommitted}}}, closed: make(chan struct{})}
			c, now := newContractCorrelator(t, cfg, store)
			t.Cleanup(func() {
				select {
				case <-store.release:
				default:
					close(store.release)
				}
				require.NoError(t, c.Close())
			})
			contractResolve(c, contractHeader(contractInvite("close-root", 0, *now), "X-Session", "same"))
			child := contractHeader(contractInvite("close-child", 4, *now), "X-Session", "same")
			if maintenance {
				// Make the first adoption commit without a hold; block only maintenance.
				store.once.Do(func() {})
				store.outcomes = []securestore.Outcome{securestore.Committed, securestore.NotCommitted}
				contractResolve(c, child)
				store.once = sync.Once{}
				c.Finalize(child.VoIPData.CallID)
				go func() { _ = c.Maintain() }()
			} else {
				require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { t.Error("shutdown published a retained packet") }))
			}
			<-store.entered
			require.ErrorIs(t, c.Close(), context.DeadlineExceeded)
			require.Equal(t, uint64(1), c.Stats().ShutdownTimeouts)
			require.Zero(t, store.closes.Load(), "store may not close underneath Save")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.True(t, errors.Is(c.CloseContext(ctx), context.Canceled))
			require.Equal(t, uint64(1), c.Stats().ShutdownTimeouts, "repeated close does not recount an owner")
			close(store.release)
			select {
			case <-store.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("physical owner never performed eventual cleanup")
			}
			require.NoError(t, c.Close())
			require.Equal(t, int32(1), store.closes.Load())
		})
	}
}

func TestCallCorrelationCancelledInitialWaitDoesNotCancelOwner(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.WaitTimeout = 30 * time.Millisecond
	store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
	c, now := newContractCorrelator(t, cfg, store)
	t.Cleanup(func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
		require.NoError(t, c.Close())
	})
	root := contractResolve(c, contractHeader(contractInvite("cancel-root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("cancel-child", 4, *now), "X-Session", "same")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.ResolveContext(ctx, child, []CallCorrelationTask{correlationTaskX}); done <- err }()
	<-store.entered
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	products := make(chan CallCorrelationDecision, 1)
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) { products <- d }))
	select {
	case d := <-products:
		require.Equal(t, root.CorrelationID, d.CorrelationID)
	case <-time.After(5 * time.Second):
		t.Fatal("packet cancellation cancelled independent logical recovery")
	}
	close(store.release)
	c.asyncWG.Wait()
	require.NoError(t, c.Close())
}

func TestCallCorrelationCloseDeadlinePreservesAuthenticatedStoreLock(t *testing.T) {
	store, path, keys := openTestCorrelationStore(t)
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.MaxRecords = 10
	cfg.ShutdownTimeout = 30 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	original := store.write
	var held atomic.Bool
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		if held.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return original(name, data)
	}
	c, now := newContractCorrelator(t, cfg, store)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		require.NoError(t, c.Close())
	})
	contractResolve(c, contractHeader(contractInvite("lock-root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("lock-child", 4, *now), "X-Session", "same")
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { t.Error("closed product was published") }))
	<-entered
	require.ErrorIs(t, c.Close(), context.DeadlineExceeded)
	_, err := OpenCallCorrelationStore(path, keys, 10)
	require.ErrorIs(t, err, securestore.ErrLocked, "bounded caller return cannot relinquish the writer's exclusive file lock")
	close(release)
	select {
	case <-c.closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("authenticated owner never completed cleanup")
	}
	require.NoError(t, c.Close())
	reopened, err := OpenCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()
	records, err := reopened.Load()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, child.VoIPData.CallID, records[0].CallID)
}

func TestCallCorrelationImmediateNonCommitSynchronousDecision(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	store := &correlationFakeStore{}
	c, now := newContractCorrelator(t, cfg, store)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	for i := range 100 {
		// Store completes immediately; sync resolution must use the completed
		// record even if the FIFO worker closes ready before the caller reads it.
		store.outcomes = []securestore.Outcome{securestore.NotCommitted}
		id := fmt.Sprintf("noncommit-child-%d", i)
		key := fmt.Sprintf("session-%d", i)
		contractResolve(c, contractHeader(contractInvite(fmt.Sprintf("noncommit-root-%d", i), 0, *now), "X-Session", key))
		d := contractResolve(c, contractHeader(contractInvite(id, 4, *now), "X-Session", key))
		require.Equal(t, hashCorrelationCallID(id), d.CorrelationID)
		require.Equal(t, "persistence_not_committed", d.Reason)
		c.asyncWG.Wait()
	}
	require.NoError(t, c.Close())
}

func TestCallCorrelationReleasedDecisionExpiresBeforePhysicalCompletion(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			cfg.WaitTimeout = 30 * time.Millisecond
			store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), correlationFakeStore: correlationFakeStore{outcomes: []securestore.Outcome{securestore.NotCommitted}}}
			c, now := newContractCorrelator(t, cfg, store)
			t.Cleanup(func() {
				select {
				case <-store.release:
				default:
					close(store.release)
				}
				require.NoError(t, c.Close())
			})
			root := contractResolve(c, contractHeader(contractInvite("expiry-root", 0, *now), "X-Session", "same"))
			child := contractHeader(contractInvite("expiry-child", 4, *now), "X-Session", "same")
			products := make(chan CallCorrelationDecision, 1)
			require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) { products <- d }))
			<-store.entered
			d := <-products
			require.Equal(t, root.CorrelationID, d.CorrelationID)
			// Wait for the logical worker's FIFO to finish before changing the
			// controllable clock; the physical writer remains behind its barrier.
			c.mu.Lock()
			ready := c.records[child.VoIPData.CallID].ready
			c.mu.Unlock()
			if ready != nil {
				<-ready
			}
			if terminal {
				c.Finalize(child.VoIPData.CallID)
				*now = now.Add(cfg.TerminalGrace)
			} else {
				*now = now.Add(11 * time.Minute)
			}
			replacement := contractResolve(c, child)
			require.Equal(t, hashCorrelationCallID(child.VoIPData.CallID), replacement.CorrelationID)
			require.NotEqual(t, d.token, replacement.token)
			close(store.release)
			c.asyncWG.Wait()
			require.Equal(t, replacement, contractResolve(c, child), "late completion revived or mutated the replacement lifetime")
			c.mu.Lock()
			revived := false
			for _, candidate := range c.candidates {
				if candidate.callID == child.VoIPData.CallID && candidate.recordToken == d.token {
					revived = revived || c.candidateLive(candidate, *now)
				}
			}
			c.mu.Unlock()
			require.False(t, revived, "replacement lifetime revived an old candidate")
			require.NoError(t, c.Maintain())
			require.Empty(t, store.records, "latest snapshot removes expired adopted state")
			require.NoError(t, c.Close())
		})
	}
}

func TestCallCorrelationPressureTriggerCannotBeOvertakenDuringFIFO(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.MaxCandidates = 2
	store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
	c, now := newContractCorrelator(t, cfg, store)
	t.Cleanup(func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
		require.NoError(t, c.Close())
	})
	contractResolve(c, contractHeader(contractInvite("fifo-root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("fifo-child", 4, *now), "X-Session", "same")
	entered, resume := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	})
	products := make(chan int, 4)
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { close(entered); <-resume; products <- 0 }))
	<-store.entered
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { products <- 1 }))
	trigger := make(chan error, 1)
	go func() {
		trigger <- c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { products <- 2 })
	}()
	<-entered
	// The trigger owns the direct-handoff gate before the FIFO is released,
	// independent of scheduler ordering when ready closes.
	c.mu.Lock()
	r := c.records[child.VoIPData.CallID]
	c.mu.Unlock()
	available := r.dispatchMu.TryLock()
	if available {
		r.dispatchMu.Unlock()
	}
	require.False(t, available, "pressure trigger did not reserve ordering before releasing the FIFO")
	next := make(chan error, 1)
	go func() {
		next <- c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { products <- 3 })
	}()
	close(resume)
	for i := range 4 {
		require.Equal(t, i, <-products)
	}
	require.NoError(t, <-trigger)
	require.NoError(t, <-next)
	close(store.release)
	require.NoError(t, c.Close())
}
