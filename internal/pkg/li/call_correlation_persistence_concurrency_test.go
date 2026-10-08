//go:build li

package li

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

type blockedCorrelationStore struct {
	correlationFakeStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockedCorrelationStore) Save(records []StoredCallCorrelation) (securestore.Outcome, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.correlationFakeStore.Save(records)
}

func TestCallCorrelationBlockedWriteIsolatesUnrelatedCalls(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{}), correlationFakeStore: correlationFakeStore{outcomes: []securestore.Outcome{outcome}}}
			c, now := newContractCorrelator(t, cfg, store)
			root := contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
			childPacket := contractHeader(contractInvite("child", 4, *now), "X-Session", "same")
			result := make(chan CallCorrelationDecision, 1)
			go func() { result <- c.Resolve(childPacket, []CallCorrelationTask{correlationTaskX}) }()
			<-store.entered
			// Save remains held until these operations complete. A deadline only prevents
			// a broken implementation from hanging the test; it is not a latency gate.
			done := make(chan struct{})
			go func() {
				retained := c.Resolve(contractInvite("root", 0, *now), []CallCorrelationTask{correlationTaskX})
				if retained != root {
					t.Errorf("retained decision changed")
				}
				c.Published(root)
				standalone := c.Resolve(contractInvite("unrelated", 8, *now), []CallCorrelationTask{correlationTaskX})
				if standalone.CorrelationID != hashCorrelationCallID("unrelated") {
					t.Errorf("unrelated leg grouped")
				}
				busy := c.Resolve(contractHeader(contractInvite("busy", 8, *now), "X-Session", "same"), []CallCorrelationTask{correlationTaskX})
				if busy.Reason != "persistence_busy" {
					t.Errorf("pending group allowed speculative join: %s", busy.Reason)
				}
				if err := c.Maintain(); err != nil {
					t.Errorf("busy maintenance: %v", err)
				}
				c.Finalize("child")
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				close(store.release)
				t.Fatal("unrelated operations blocked by storage")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := c.ResolveContext(ctx, childPacket, []CallCorrelationTask{correlationTaskX})
			require.ErrorIs(t, err, context.Canceled)
			wait := make(chan CallCorrelationDecision, 1)
			go func() { wait <- c.Resolve(childPacket, []CallCorrelationTask{correlationTaskX}) }()
			close(store.release)
			decision := <-result
			require.Equal(t, decision, <-wait)
			if outcome == securestore.NotCommitted {
				require.Equal(t, hashCorrelationCallID("child"), decision.CorrelationID)
			} else {
				require.Equal(t, root.CorrelationID, decision.CorrelationID)
			}
			// Finalization during Save advances the revision. Maintenance must retain it.
			require.NoError(t, c.Maintain())
			if outcome != securestore.NotCommitted {
				require.Len(t, store.records, 1)
				require.False(t, store.records[0].TerminalUntil.IsZero())
			}
			require.NoError(t, c.Close())
		})
	}
}

func TestCallCorrelationLocalExpiryWithoutMaintenance(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	c, now := newContractCorrelator(t, cfg, nil)
	root := contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
	*now = now.Add(11 * time.Minute)
	child := contractResolve(c, contractHeader(contractInvite("child", 4, *now), "X-Session", "same"))
	require.NotEqual(t, root.CorrelationID, child.CorrelationID)
	require.Empty(t, child.Rule)
}

func TestCallCorrelationIneligibleExactStopsWeakFallback(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	contractResolve(c, contractHeader(contractInvite("exact", 8, *now), "X-Session", "same"), correlationTaskX)
	weak := contractResolve(c, contractInvite("weak", 0, *now), correlationTaskY)
	result := contractResolve(c, contractHeader(contractInvite("incoming", 1, *now), "X-Session", "same"), correlationTaskY)
	require.NotEqual(t, weak.CorrelationID, result.CorrelationID)
	require.Equal(t, "ineligible_exact", result.Reason)
}

func TestCallCorrelationMalformedSingleHeaderFallsThrough(t *testing.T) {
	for _, rule := range []string{"S", "R1", "R2"} {
		t.Run(rule, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"Session-ID"}
			cfg.SDPOriginMatching = rule == "S"
			cfg.AddressChaining = rule == "R1"
			cfg.NumberChaining = rule == "R2"
			c, now := newContractCorrelator(t, cfg, nil)
			rootPacket := contractInvite("root", 0, *now)
			childPacket := contractInvite("child", 1, *now)
			if rule == "S" {
				contractSDP(rootPacket, "1")
				contractSDP(childPacket, "1")
			}
			if rule == "R2" {
				rootPacket.SrcIP = ""
				rootPacket.DstIP = ""
				childPacket.SrcIP = ""
				childPacket.DstIP = ""
			}
			root := contractResolve(c, rootPacket)
			child := contractResolve(c, contractHeader(childPacket, "Session-ID", "invalid"))
			require.Equal(t, root.CorrelationID, child.CorrelationID)
			require.Equal(t, rule, child.Rule)
		})
	}
}

func TestCallCorrelationUnknownResponseCannotGroup(t *testing.T) {
	for _, seq := range []uint64{0, 1, 2, 100} {
		cfg := DefaultCallCorrelationConfig()
		cfg.AddressChaining = true
		c, now := newContractCorrelator(t, cfg, nil)
		root := contractResolve(c, contractInvite("root", 0, *now))
		p := contractInvite("response", 1, *now)
		p.VoIPData.CSeqNumber = seq
		p.VoIPData.Status = 200
		p.VoIPData.Method = ""
		p.VoIPData.ToTag = "dialog"
		if seq == 0 {
			p.VoIPData.Headers = map[string]string{"CSeq": "0 INVITE"}
		}
		p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
		d := contractResolve(c, p)
		require.Equal(t, "not_eligible", d.Reason)
		require.NotEqual(t, root.CorrelationID, d.CorrelationID)
		p.VoIPData.Status = 0
		p.VoIPData.Method = "INVITE"
		p.VoIPData.ToTag = ""
		require.Equal(t, d, c.Resolve(p, []CallCorrelationTask{correlationTaskX}))
	}
}

// Keep compile-time API coverage for packet cancellation callers.
var _ func(context.Context, *types.PacketDisplay, []CallCorrelationTask) (CallCorrelationDecision, error) = (*CallCorrelator)(nil).ResolveContext

func TestCallCorrelationAsyncBoundedOrderedPublication(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.MaxCandidates = 3
	store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
	c, now := newContractCorrelator(t, cfg, store)
	root := contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("child", 4, *now), "X-Session", "same")
	products := make(chan int, 4)
	callback := func(index int) func(CallCorrelationDecision) {
		return func(d CallCorrelationDecision) {
			if d.CorrelationID != root.CorrelationID {
				t.Errorf("decision changed")
			}
			c.Published(d)
			products <- index
		}
	}
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, callback(0)))
	<-store.entered
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, callback(1)))
	canceled, cancel := context.WithCancel(context.Background())
	require.NoError(t, c.ResolveAsync(canceled, child, []CallCorrelationTask{correlationTaskX}, 100, callback(2)))
	cancel()
	require.Error(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, callback(3)))
	// Queue exhaustion must not suppress unrelated standalone publication.
	unrelated := 0
	require.NoError(t, c.ResolveAsync(context.Background(), contractInvite("unrelated", 8, *now), []CallCorrelationTask{correlationTaskX}, 100, func(d CallCorrelationDecision) {
		unrelated++
		require.Equal(t, hashCorrelationCallID("unrelated"), d.CorrelationID)
	}))
	require.Equal(t, 1, unrelated)
	close(store.release)
	require.Equal(t, 0, <-products)
	require.Equal(t, 1, <-products)
	c.asyncWG.Wait()
	require.Empty(t, products)
	require.Zero(t, c.deferredPackets)
	require.Zero(t, c.deferredBytes)
	require.NoError(t, c.Maintain())
	require.NoError(t, c.Close())
}

func TestCallCorrelationAsyncShutdownCancelsPendingPackets(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
	c, now := newContractCorrelator(t, cfg, store)
	contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("child", 4, *now), "X-Session", "same")
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) { t.Error("closed packet published") }))
	<-store.entered
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	<-c.stop
	_, err := c.ResolveContext(context.Background(), child, []CallCorrelationTask{correlationTaskX})
	require.Error(t, err)
	require.Error(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
	close(store.release)
	require.NoError(t, <-closed)
	require.Zero(t, c.deferredPackets)
}

func TestCallCorrelationClockAndSymmetricNumberWindows(t *testing.T) {
	for _, direction := range []time.Duration{-1, 1} {
		for _, outside := range []bool{false, true} {
			cfg := DefaultCallCorrelationConfig()
			cfg.NumberChaining = true
			c, now := newContractCorrelator(t, cfg, nil)
			first := contractResolve(c, contractInvite("a", 0, *now))
			offset := cfg.NumberWindow
			if outside {
				offset += time.Nanosecond
			}
			second := contractResolve(c, contractInvite("b", 4, now.Add(direction*offset)))
			if outside {
				require.Empty(t, second.Rule)
			} else {
				require.Equal(t, "R2", second.Rule)
				require.Equal(t, first.CorrelationID, second.CorrelationID)
			}
		}
	}
	t.Run("missing capture timestamp uses processor clock", func(t *testing.T) {
		cfg := DefaultCallCorrelationConfig()
		cfg.AddressChaining = true
		c, now := newContractCorrelator(t, cfg, nil)
		first := contractResolve(c, contractInvite("a", 0, time.Time{}))
		second := contractResolve(c, contractInvite("b", 1, now.Add(time.Millisecond)))
		require.Equal(t, first.CorrelationID, second.CorrelationID)
	})
	t.Run("late batch cannot use processor-expired candidate", func(t *testing.T) {
		cfg := DefaultCallCorrelationConfig()
		cfg.AddressChaining = true
		c, now := newContractCorrelator(t, cfg, nil)
		captured := *now
		first := contractResolve(c, contractInvite("a", 0, captured))
		*now = now.Add(cfg.AddressWindow + time.Nanosecond)
		second := contractResolve(c, contractInvite("b", 1, captured.Add(time.Millisecond)))
		require.NotEqual(t, first.CorrelationID, second.CorrelationID)
		require.Empty(t, second.Rule)
	})
}

func TestCallCorrelationMaintenanceSkipsUnchangedSnapshot(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	store := &correlationFakeStore{}
	c, now := newContractCorrelator(t, cfg, store)
	contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
	child := contractResolve(c, contractHeader(contractInvite("child", 4, *now), "X-Session", "same"))
	saves := store.saves
	require.NoError(t, c.Maintain())
	// Published at the same instant only changes accounting, not retained content.
	c.Published(child)
	require.NoError(t, c.Maintain())
	require.Equal(t, saves, store.saves)
	*now = now.Add(time.Second)
	c.Published(child)
	require.NoError(t, c.Maintain())
	require.Equal(t, saves+1, store.saves)
	require.Equal(t, *now, store.records[0].LastActivity)
	require.NoError(t, c.Maintain())
	require.Equal(t, saves+1, store.saves)
}

func TestCallCorrelationPendingFinalResponseClosesSetup(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			if reject {
				cfg.MaxCandidates = 2
			}
			store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
			c, now := newContractCorrelator(t, cfg, store)
			root := contractResolve(c, contractInvite("root", 0, *now))
			child := contractInvite("child", 1, now.Add(time.Millisecond))
			require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
			<-store.entered
			if reject {
				require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
			}
			final := contractInvite("child", 1, now.Add(2*time.Millisecond))
			final.SrcIP, final.DstIP = final.DstIP, final.SrcIP
			final.VoIPData.Method = ""
			final.VoIPData.Status = 200
			final.VoIPData.ToTag = "final"
			err := c.ResolveAsync(context.Background(), final, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {})
			if reject {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			c.mu.Lock()
			tx, _ := correlationTx(child)
			at := c.transactions[tx].candidate.finalAt
			c.mu.Unlock()
			require.Equal(t, final.Timestamp, at)
			close(store.release)
			c.asyncWG.Wait()
			// Free unrelated transaction accounting in the bounded case; retain the
			// candidate whose captured final response must close R1 setup.
			if reject {
				c.mu.Lock()
				rootTx, _ := correlationTx(contractInvite("root", 0, *now))
				delete(c.transactions, rootTx)
				c.mu.Unlock()
			}
			later := contractResolve(c, contractInvite("later", 2, now.Add(3*time.Millisecond)))
			require.NotEqual(t, root.CorrelationID, later.CorrelationID)
			require.Empty(t, later.Rule)
			require.NoError(t, c.Close())
		})
	}
}

func TestCallCorrelationPendingDelayedOfferAndACKKeepRoles(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.SDPOriginMatching = true
	store := &blockedCorrelationStore{entered: make(chan struct{}), release: make(chan struct{})}
	c, now := newContractCorrelator(t, cfg, store)
	root := contractResolve(c, contractHeader(contractInvite("root", 0, *now), "X-Session", "same"))
	child := contractHeader(contractInvite("child", 4, *now), "X-Session", "same")
	require.NoError(t, c.ResolveAsync(context.Background(), child, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
	<-store.entered
	response := roleResponse(child, roleSDPBody("111"))
	ack := roleACK(child, roleSDPBody("222"))
	require.NoError(t, c.ResolveAsync(context.Background(), response, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
	require.NoError(t, c.ResolveAsync(context.Background(), ack, []CallCorrelationTask{correlationTaskX}, 100, func(CallCorrelationDecision) {}))
	c.mu.Lock()
	tx, _ := correlationTx(child)
	candidate := c.transactions[tx].candidate
	roles := len(candidate.originKeys)
	generations := make([]uint64, 0, roles)
	for _, key := range candidate.originKeys {
		generations = append(generations, candidate.originGenerations[key])
	}
	c.mu.Unlock()
	require.Equal(t, 2, roles)
	for _, generation := range generations {
		require.NotZero(t, generation)
	}
	close(store.release)
	c.asyncWG.Wait()
	later := contractResolve(c, contractSDP(contractInvite("later", 8, *now), "111"))
	require.Equal(t, root.CorrelationID, later.CorrelationID)
	require.Equal(t, "S", later.Rule)
	require.NoError(t, c.Close())
}
