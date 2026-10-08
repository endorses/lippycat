//go:build li

package li

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var (
	correlationTaskX = CallCorrelationTask{XID: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Generation: 1}
	correlationTaskY = CallCorrelationTask{XID: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Generation: 1}
)

type correlationFakeStore struct {
	records           []StoredCallCorrelation
	outcomes          []securestore.Outcome
	saves, reconciles int
	closed            bool
}

func (s *correlationFakeStore) Load() ([]StoredCallCorrelation, error) {
	return append([]StoredCallCorrelation(nil), s.records...), nil
}
func (s *correlationFakeStore) Save(r []StoredCallCorrelation) (securestore.Outcome, error) {
	s.saves++
	out := securestore.Committed
	if len(s.outcomes) > 0 {
		out = s.outcomes[0]
		s.outcomes = s.outcomes[1:]
	}
	if out == securestore.Committed {
		s.records = append([]StoredCallCorrelation(nil), r...)
		return out, nil
	}
	return out, errors.New("injected correlation write failure")
}
func (s *correlationFakeStore) Close() error     { s.closed = true; return nil }
func (s *correlationFakeStore) Reconcile() error { s.reconciles++; return nil }

func newContractCorrelator(t *testing.T, cfg CallCorrelationConfig, store CallCorrelationPersistence) (*CallCorrelator, *time.Time) {
	t.Helper()
	c, err := NewCallCorrelator(cfg, 10*time.Minute, store)
	require.NoError(t, err)
	now := time.Now().UTC()
	c.now = func() time.Time { return now }
	c.blindUntil = now
	return c, &now
}
func contractInvite(id string, hop int, at time.Time) *types.PacketDisplay {
	return &types.PacketDisplay{Timestamp: at, SrcIP: fmt.Sprintf("192.0.2.%d", hop+1), DstIP: fmt.Sprintf("192.0.2.%d", hop+2), VoIPData: &types.VoIPMetadata{CallID: id, Method: "INVITE", CSeqMethod: "INVITE", CSeqNumber: 1, ViaBranch: "z9hG4bK-" + id, FromTag: "from-" + id, From: "<sip:12025550101@example.test>", To: "<sip:12025550102@example.test>"}}
}
func contractResolve(c *CallCorrelator, p *types.PacketDisplay, tasks ...CallCorrelationTask) CallCorrelationDecision {
	if len(tasks) == 0 {
		tasks = []CallCorrelationTask{correlationTaskX}
	}
	d := c.Resolve(p, tasks)
	c.Published(d)
	return d
}
func contractHeader(p *types.PacketDisplay, name, value string) *types.PacketDisplay {
	if p.VoIPData.Headers == nil {
		p.VoIPData.Headers = map[string]string{}
	}
	p.VoIPData.Headers[name] = value
	return p
}
func contractSDP(p *types.PacketDisplay, session string) *types.PacketDisplay {
	p.VoIPData.Body = "v=0\r\no=- " + session + " 1 IN IP4 198.51.100.1\r\ns=call\r\nt=0 0\r\n"
	return p
}

func TestCallCorrelationChainArrivalPermutations(t *testing.T) {
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			c, now := newContractCorrelator(t, cfg, nil)
			packets := []*types.PacketDisplay{contractInvite("a", 0, *now), contractInvite("b", 1, now.Add(100*time.Millisecond)), contractInvite("c", 2, now.Add(200*time.Millisecond))}
			decisions := map[int]CallCorrelationDecision{}
			for _, i := range order {
				decisions[i] = contractResolve(c, packets[i])
			}
			if order[1] == order[0]+2 || order[1] == order[0]-2 {
				require.NotEqual(t, decisions[0].CorrelationID, decisions[2].CorrelationID, "separated groups cannot be retrospectively merged")
				require.Empty(t, decisions[1].Rule)
				require.Equal(t, "ambiguous", decisions[1].Reason)
			} else {
				require.Equal(t, decisions[0].CorrelationID, decisions[1].CorrelationID)
				require.Equal(t, decisions[1].CorrelationID, decisions[2].CorrelationID)
			}
			for i, p := range packets {
				require.Equal(t, decisions[i], c.Resolve(p, []CallCorrelationTask{correlationTaskX}), "first decision must remain immutable")
			}
		})
	}
}
func TestCallCorrelationFourHopAndAliases(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	cfg.NodeAliases = [][]string{{"192.0.2.2", "198.51.100.2"}}
	c, now := newContractCorrelator(t, cfg, nil)
	first := contractResolve(c, contractInvite("a", 0, *now))
	for i := 1; i < 4; i++ {
		p := contractInvite(fmt.Sprint(i), i, now.Add(time.Duration(i)*100*time.Millisecond))
		if i == 1 {
			p.SrcIP = "198.51.100.2"
		}
		d := contractResolve(c, p)
		require.Equal(t, first.CorrelationID, d.CorrelationID)
		require.Equal(t, "R1", d.Rule)
	}
	require.Equal(t, 1, c.Stats().GroupsFourOrMore)
	require.Equal(t, uint64(3), c.Stats().Adopted["R1"])
}
func TestCallCorrelationCommonTaskIntersection(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now), correlationTaskX)
	b := contractResolve(c, contractInvite("b", 1, now.Add(100*time.Millisecond)), correlationTaskX, correlationTaskY)
	require.Equal(t, a.CorrelationID, b.CorrelationID)
	d := contractResolve(c, contractInvite("c", 2, now.Add(200*time.Millisecond)), correlationTaskY)
	require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	fresh := correlationTaskX
	fresh.Generation++
	d = contractResolve(c, contractInvite("d", 2, now.Add(300*time.Millisecond)), fresh)
	require.NotEqual(t, a.CorrelationID, d.CorrelationID)
}
func TestCallCorrelationTrustedEvidenceHierarchy(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session", "X-Other"}
	cfg.ParentCallIDHeaders = []string{"X-Parent"}
	cfg.AddressChaining = true
	cfg.SDPOriginMatching = true
	t.Run("header beats SDP and address", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractSDP(contractHeader(contractInvite("a", 0, *now), "X-Session", "exact"), "111"))
		b := contractResolve(c, contractSDP(contractHeader(contractInvite("b", 3, *now), "X-Session", "other"), "222"))
		require.NotEqual(t, a.CorrelationID, b.CorrelationID)
		p := contractSDP(contractHeader(contractInvite("c", 4, now.Add(100*time.Millisecond)), "X-Session", "exact"), "222")
		d := contractResolve(c, p)
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "H", d.Rule)
	})
	t.Run("two exact groups conflict", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractHeader(contractInvite("a", 0, *now), "X-Session", "one"))
		contractResolve(c, contractHeader(contractInvite("b", 3, *now), "X-Other", "two"))
		p := contractHeader(contractHeader(contractInvite("c", 1, now.Add(time.Millisecond)), "X-Session", "one"), "X-Other", "two")
		d := contractResolve(c, p)
		require.NotEqual(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "conflicting_exact", d.Reason)
	})
	t.Run("contradictory exact vetoes fallback", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractHeader(contractInvite("a", 0, *now), "X-Session", "one"))
		d := contractResolve(c, contractHeader(contractInvite("b", 1, now.Add(time.Millisecond)), "X-Session", "two"))
		require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	})
	t.Run("parent chain and immutable unknown parent", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractInvite("a", 0, *now))
		b := contractResolve(c, contractHeader(contractInvite("b", 4, *now), "X-Parent", "a"))
		require.Equal(t, a.CorrelationID, b.CorrelationID)
		require.Equal(t, "P", b.Rule)
		d := contractResolve(c, contractHeader(contractInvite("d", 7, *now), "X-Parent", "b"))
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		unknown := contractHeader(contractInvite("unknown", 9, *now), "X-Parent", "later")
		u := contractResolve(c, unknown)
		require.Equal(t, "unresolved_parent", u.Reason)
		contractResolve(c, contractInvite("later", 8, *now))
		require.Equal(t, u, c.Resolve(unknown, []CallCorrelationTask{correlationTaskX}))
	})
	t.Run("header and parent disagree", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		contractResolve(c, contractHeader(contractInvite("a", 0, *now), "X-Session", "one"))
		contractResolve(c, contractHeader(contractInvite("b", 3, *now), "X-Session", "two"))
		d := contractResolve(c, contractHeader(contractHeader(contractInvite("c", 1, *now), "X-Session", "one"), "X-Parent", "b"))
		require.Equal(t, "conflicting_exact", d.Reason)
		require.Empty(t, d.Rule)
	})
}
func TestCallCorrelationSDPPrecedenceAndFallback(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	cfg.AddressChaining = true
	t.Run("unique SDP before address", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractSDP(contractInvite("a", 0, *now), "111"))
		b := contractResolve(c, contractSDP(contractInvite("b", 3, *now), "222"))
		require.NotEqual(t, a.CorrelationID, b.CorrelationID)
		d := contractResolve(c, contractSDP(contractInvite("c", 4, now.Add(time.Millisecond)), "111"))
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "S", d.Rule)
	})
	t.Run("different origin does not veto address", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractSDP(contractInvite("a", 0, *now), "111"))
		d := contractResolve(c, contractSDP(contractInvite("b", 1, now.Add(time.Millisecond)), "222"))
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "R1", d.Rule)
	})
}
func TestCallCorrelationWeakRulesAndRedial(t *testing.T) {
	t.Run("exact numbers and window", func(t *testing.T) {
		cfg := DefaultCallCorrelationConfig()
		cfg.NumberChaining = true
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractInvite("a", 0, *now))
		b := contractResolve(c, contractInvite("b", 4, now.Add(100*time.Millisecond)))
		require.Equal(t, a.CorrelationID, b.CorrelationID)
		require.Equal(t, "R2", b.Rule)
		p := contractInvite("suffix", 7, now.Add(100*time.Millisecond))
		p.VoIPData.From = "<sip:99912025550101@example.test>"
		d := contractResolve(c, p)
		require.NotEqual(t, a.CorrelationID, d.CorrelationID)
		d = contractResolve(c, contractInvite("redial", 10, now.Add(time.Second)))
		require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	})
	t.Run("rewritten disabled and enabled", func(t *testing.T) {
		for _, enabled := range []bool{false, true} {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			cfg.AddressChainingRewritten = enabled
			c, now := newContractCorrelator(t, cfg, nil)
			a := contractResolve(c, contractInvite("a", 0, *now))
			p := contractInvite("b", 1, now.Add(time.Millisecond))
			p.VoIPData.To = "<sip:12025550999@example.test>"
			d := contractResolve(c, p)
			if enabled {
				require.Equal(t, a.CorrelationID, d.CorrelationID)
				require.Equal(t, "R1_rewritten", d.Rule)
			} else {
				require.NotEqual(t, a.CorrelationID, d.CorrelationID)
			}
		}
	})
}

func TestCallCorrelationFirstPublicationAndCounters(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	p := contractInvite("a", 0, *now)
	first := c.Resolve(p, []CallCorrelationTask{correlationTaskX})
	require.Empty(t, c.Stats().Standalone)
	c.Published(first)
	c.Published(first)
	require.Equal(t, uint64(1), c.Stats().Standalone["no_candidate"])
	rtp := contractInvite("rtp-first", 1, now.Add(time.Millisecond))
	rtp.VoIPData.IsRTP = true
	d := contractResolve(c, rtp)
	require.Equal(t, "not_eligible", d.Reason)
	rtp.VoIPData.IsRTP = false
	require.Equal(t, d, c.Resolve(rtp, []CallCorrelationTask{correlationTaskX}))
	reinvite := contractInvite("reinvite-first", 1, now.Add(time.Millisecond))
	reinvite.VoIPData.ToTag = "existing-dialog"
	d = contractResolve(c, reinvite)
	require.Empty(t, d.Rule)
	require.Equal(t, "not_eligible", d.Reason)
	stats := c.Stats()
	stats.Standalone["no_candidate"] = 999
	require.Equal(t, uint64(1), c.Stats().Standalone["no_candidate"])
}

func TestCallCorrelationPersistenceOutcomesAndRestart(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.Committed, securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			store := &correlationFakeStore{outcomes: []securestore.Outcome{outcome}}
			c, now := newContractCorrelator(t, cfg, store)
			a := contractResolve(c, contractInvite("a", 0, *now))
			p := contractInvite("b", 1, now.Add(time.Millisecond))
			b := contractResolve(c, p)
			if outcome == securestore.NotCommitted {
				require.NotEqual(t, a.CorrelationID, b.CorrelationID)
				require.Equal(t, "persistence_not_committed", b.Reason)
			} else {
				require.Equal(t, a.CorrelationID, b.CorrelationID)
			}
			require.Equal(t, b, c.Resolve(p, []CallCorrelationTask{correlationTaskX}))
			require.NoError(t, c.Maintain())
			if outcome == securestore.Uncertain {
				require.Equal(t, 1, store.reconciles)
				require.Zero(t, c.Stats().UnresolvedWrites)
			}
			if outcome != securestore.NotCommitted {
				restored, err := NewCallCorrelator(cfg, 10*time.Minute, store)
				require.NoError(t, err)
				got := restored.Resolve(p, []CallCorrelationTask{correlationTaskX})
				require.Equal(t, b.CorrelationID, got.CorrelationID)
				require.Equal(t, "restored", got.Rule)
			}
		})
	}
}
func TestCallCorrelationRetentionAndGrace(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now))
	p := contractInvite("b", 1, now.Add(time.Millisecond))
	b := contractResolve(c, p)
	require.Equal(t, a.CorrelationID, b.CorrelationID)
	c.Finalize("b")
	*now = now.Add(cfg.TerminalGrace - time.Millisecond)
	p.VoIPData.Method = "BYE"
	p.VoIPData.CSeqMethod = "BYE"
	require.Equal(t, b, c.Resolve(p, []CallCorrelationTask{correlationTaskX}))
	*now = now.Add(2 * time.Millisecond)
	got := c.Resolve(p, []CallCorrelationTask{correlationTaskX})
	require.NotEqual(t, b.CorrelationID, got.CorrelationID)
}
func TestCallCorrelationCapacityBlindnessAndRetainedIDs(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	cfg.MaxRecords = 2
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now))
	b := contractResolve(c, contractInvite("b", 1, now.Add(time.Millisecond)))
	require.Equal(t, a.CorrelationID, b.CorrelationID)
	d := contractResolve(c, contractInvite("c", 2, now.Add(2*time.Millisecond)))
	require.Equal(t, "record_limit", d.Reason)
	require.True(t, c.Stats().Blind)
	*now = now.Add(time.Minute)
	contractResolve(c, contractInvite("d", 2, *now))
	require.Equal(t, cfg.DecisionHorizon, c.Stats().BlindRemaining)
	require.Equal(t, b.CorrelationID, c.Resolve(contractInvite("b", 1, *now), []CallCorrelationTask{correlationTaskX}).CorrelationID)
	require.Equal(t, 2, c.Stats().Records)
}
func TestCallCorrelationConcurrentFirstDecision(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now))
	p := contractInvite("b", 1, now.Add(time.Millisecond))
	const workers = 32
	results := make(chan CallCorrelationDecision, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- contractResolve(c, p) }()
	}
	wg.Wait()
	close(results)
	for d := range results {
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "R1", d.Rule)
	}
	require.Equal(t, uint64(1), c.Stats().Adopted["R1"])
	require.Equal(t, 2, c.Stats().Records)
}

func TestCallCorrelationResponseFirstAndFinalCaptureTime(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	t.Run("response first has no proven initial transaction", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		p := contractInvite("a", 0, *now)
		p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
		p.VoIPData.Method = ""
		p.VoIPData.Status = 180
		p.VoIPData.ToTag = "early"
		a := contractResolve(c, p)
		b := contractResolve(c, contractInvite("b", 1, now.Add(time.Millisecond)))
		require.NotEqual(t, a.CorrelationID, b.CorrelationID)
		require.Equal(t, "not_eligible", a.Reason)
		require.Empty(t, b.Rule)
	})
	for _, afterFinal := range []bool{false, true} {
		t.Run(fmt.Sprintf("final-before-arrival-later-start-%t", afterFinal), func(t *testing.T) {
			c, now := newContractCorrelator(t, cfg, nil)
			invite := contractInvite("a", 0, *now)
			a := contractResolve(c, invite)
			response := contractInvite("a", 0, now.Add(100*time.Millisecond))
			response.SrcIP, response.DstIP = response.DstIP, response.SrcIP
			response.VoIPData.Method = ""
			response.VoIPData.Status = 200
			response.VoIPData.ToTag = "final"
			require.Equal(t, a.CorrelationID, contractResolve(c, response).CorrelationID)
			start := now.Add(50 * time.Millisecond)
			if afterFinal {
				start = now.Add(150 * time.Millisecond)
			}
			b := contractResolve(c, contractInvite("b", 1, start))
			if afterFinal {
				require.NotEqual(t, a.CorrelationID, b.CorrelationID)
			} else {
				require.Equal(t, a.CorrelationID, b.CorrelationID, "capture-time setup before final response remains eligible despite later arrival")
			}
		})
	}
}

func TestCallCorrelationConcurrentIntersectionShrink(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now), correlationTaskX, correlationTaskY)
	results := make(chan CallCorrelationDecision, 2)
	var wg sync.WaitGroup
	for i, task := range []CallCorrelationTask{correlationTaskX, correlationTaskY} {
		wg.Add(1)
		go func(i int, task CallCorrelationTask) {
			defer wg.Done()
			results <- contractResolve(c, contractInvite(fmt.Sprintf("joining-%d", i), 1, now.Add(time.Millisecond)), task)
		}(i, task)
	}
	wg.Wait()
	close(results)
	adopted := 0
	for d := range results {
		if d.CorrelationID == a.CorrelationID {
			adopted++
		}
	}
	require.Equal(t, 1, adopted, "mutually disjoint task sets cannot both extend the shared group")
}

func TestCallCorrelationCandidateBoundsAndIndexExpiry(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.SDPOriginMatching = true
	cfg.MaxCandidates = 1
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractSDP(contractHeader(contractInvite("a", 0, *now), "X-Session", "one"), "111"))
	d := contractResolve(c, contractSDP(contractHeader(contractInvite("b", 1, now.Add(time.Millisecond)), "X-Session", "one"), "111"))
	require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	require.Equal(t, "candidate_limit", d.Reason)
	require.Equal(t, 1, c.Stats().Candidates)
	require.Equal(t, 1, c.Stats().Transactions)
	*now = now.Add(c.lifetime + time.Millisecond)
	require.NoError(t, c.Maintain())
	require.Zero(t, c.Stats().Candidates)
	require.Zero(t, c.Stats().Transactions)
	require.Empty(t, c.headerIndex)
	require.Empty(t, c.addressIndex)
	require.Empty(t, c.numberIndex)
	require.Empty(t, c.originIndex, "expired candidates cannot leave SDP answer/index entries behind")
}

func TestCallCorrelationRestoredRetentionAndTaskGenerations(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.ParentCallIDHeaders = []string{"X-Parent"}
	cfg.DecisionHorizon = time.Millisecond
	now := time.Now().UTC()
	store := &correlationFakeStore{records: []StoredCallCorrelation{
		{CallID: "active", GroupID: 42, LastActivity: now, CommonTasks: []CallCorrelationTask{correlationTaskX}},
		{CallID: "expired", GroupID: 42, LastActivity: now.Add(-time.Hour), CommonTasks: []CallCorrelationTask{correlationTaskX}},
		{CallID: "terminal", GroupID: 42, LastActivity: now, TerminalUntil: now.Add(-time.Second), CommonTasks: []CallCorrelationTask{correlationTaskX}},
	}}
	c, err := NewCallCorrelator(cfg, 10*time.Minute, store)
	require.NoError(t, err)
	clock := now.Add(time.Second)
	c.now = func() time.Time { return clock }
	require.Equal(t, 1, c.Stats().Records)
	fresh := correlationTaskX
	fresh.Generation++
	p := contractHeader(contractInvite("fresh", 1, clock), "X-Parent", "active")
	d := contractResolve(c, p, fresh)
	require.Equal(t, "ineligible_parent", d.Reason)
	require.NotEqual(t, uint64(42), d.CorrelationID)
	active := contractInvite("active", 0, clock)
	active.VoIPData.Method = "BYE"
	d = c.Resolve(active, []CallCorrelationTask{fresh})
	require.Equal(t, uint64(42), d.CorrelationID, "live eligibility cannot rewrite restored decisions")
}

func TestCallCorrelationAmbiguousAndSuspendedSDPFallThrough(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	cfg.AddressChaining = true
	t.Run("ambiguous SDP falls through to unique address", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractSDP(contractInvite("a", 0, *now), "111"), correlationTaskX)
		b := contractResolve(c, contractSDP(contractInvite("b", 3, *now), "111"), correlationTaskY)
		require.NotEqual(t, a.CorrelationID, b.CorrelationID)
		d := contractResolve(c, contractSDP(contractInvite("c", 1, now.Add(time.Millisecond)), "111"), correlationTaskX, correlationTaskY)
		require.Equal(t, a.CorrelationID, d.CorrelationID)
		require.Equal(t, "R1", d.Rule)
		require.Equal(t, uint64(1), c.Stats().SDP["ambiguous"])
	})
	t.Run("suspended origin falls through to address", func(t *testing.T) {
		c, now := newContractCorrelator(t, cfg, nil)
		a := contractResolve(c, contractSDP(contractInvite("a", 0, *now), "111"))
		*now = now.Add(40 * time.Second)
		b := contractResolve(c, contractSDP(contractInvite("b", 3, *now), "111"))
		require.NotEqual(t, a.CorrelationID, b.CorrelationID)
		require.Equal(t, 1, c.Stats().SuspendedOrigins)
		d := contractResolve(c, contractSDP(contractInvite("c", 4, now.Add(time.Millisecond)), "111"))
		require.Equal(t, b.CorrelationID, d.CorrelationID)
		require.Equal(t, "R1", d.Rule)
	})
}

func TestCallCorrelationNumberRequiresNoAddressCandidate(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.NumberChaining = true
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	p := contractInvite("address", 0, *now)
	p.VoIPData.To = "<sip:12025550999@example.test>"
	contractResolve(c, p)
	number := contractResolve(c, contractInvite("number", 4, *now))
	d := contractResolve(c, contractInvite("new", 1, now.Add(time.Millisecond)))
	require.NotEqual(t, number.CorrelationID, d.CorrelationID)
	require.Empty(t, d.Rule, "R2 must not override an available address candidate with rewritten numbers")
}

func TestCallCorrelationCommonTaskContextBound(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	anchor := contractResolve(c, contractInvite("anchor", 0, *now))
	tasks := []CallCorrelationTask{correlationTaskX}
	for i := 0; i < maxCallCorrelationStoredTasks; i++ {
		tasks = append(tasks, CallCorrelationTask{XID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("bounded-task-%d", i))), Generation: 1})
	}
	d := contractResolve(c, contractInvite("oversized", 1, now.Add(time.Millisecond)), tasks...)
	require.NotEqual(t, anchor.CorrelationID, d.CorrelationID, "overflow cannot select a subset to manufacture shared task evidence")
	if record := c.records[d.CallID]; record != nil {
		require.LessOrEqual(t, len(record.group.tasks), maxCallCorrelationStoredTasks, "retained task context has the same bound as persistence")
	}
}

func TestCallCorrelationRestoredRootSharesRestrictedContext(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.ParentCallIDHeaders = []string{"X-Parent"}
	cfg.DecisionHorizon = time.Millisecond
	for _, disjoint := range []bool{false, true} {
		t.Run(fmt.Sprintf("disjoint-%t", disjoint), func(t *testing.T) {
			rootID := hashCorrelationCallID("root")
			now := time.Now().UTC()
			store := &correlationFakeStore{records: []StoredCallCorrelation{{CallID: "adopted", GroupID: rootID, LastActivity: now, CommonTasks: []CallCorrelationTask{correlationTaskX}}}}
			c, err := NewCallCorrelator(cfg, 10*time.Minute, store)
			require.NoError(t, err)
			clock := now.Add(time.Second)
			c.now = func() time.Time { return clock }
			rootTask := correlationTaskX
			if disjoint {
				rootTask = correlationTaskY
			}
			root := contractResolve(c, contractInvite("root", 0, clock), rootTask)
			require.Equal(t, rootID, root.CorrelationID)
			child := contractHeader(contractInvite("child", 4, clock), "X-Parent", "root")
			decision := contractResolve(c, child, rootTask)
			if disjoint {
				require.NotEqual(t, rootID, decision.CorrelationID)
				require.Equal(t, "ineligible_parent", decision.Reason)
			} else {
				require.Equal(t, rootID, decision.CorrelationID)
			}
			require.NoError(t, c.Maintain())
			var adopted *StoredCallCorrelation
			for i := range store.records {
				if store.records[i].CallID == "adopted" {
					adopted = &store.records[i]
				}
			}
			require.NotNil(t, adopted)
			if disjoint {
				require.Empty(t, adopted.CommonTasks, "empty intersection must be persisted, retaining the child's ID without authorizing new members")
			} else {
				require.Equal(t, []CallCorrelationTask{correlationTaskX}, adopted.CommonTasks)
			}
		})
	}
}

func TestCallCorrelationStateIncarnationSeparatesMembership(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.ParentCallIDHeaders = []string{"X-Parent"}
	cfg.DecisionHorizon = time.Millisecond
	old := correlationTaskX
	old.StateIncarnation = uuid.New()
	current := old
	current.StateIncarnation = uuid.New()
	c, now := newContractCorrelator(t, cfg, nil)
	a := contractResolve(c, contractInvite("a", 0, *now), old)
	d := contractResolve(c, contractHeader(contractInvite("b", 4, *now), "X-Parent", "a"), current)
	require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	require.Equal(t, "ineligible_parent", d.Reason)
	store := &correlationFakeStore{records: []StoredCallCorrelation{{CallID: "adopted", GroupID: 42, LastActivity: *now, CommonTasks: []CallCorrelationTask{old}}}}
	restored, err := NewCallCorrelator(cfg, 10*time.Minute, store)
	require.NoError(t, err)
	clock := now.Add(time.Second)
	restored.now = func() time.Time { return clock }
	d = contractResolve(restored, contractHeader(contractInvite("new-leg", 4, clock), "X-Parent", "adopted"), current)
	require.NotEqual(t, uint64(42), d.CorrelationID)
	require.Equal(t, "ineligible_parent", d.Reason)
	retained := contractInvite("adopted", 0, clock)
	retained.VoIPData.Method = "BYE"
	d = restored.Resolve(retained, []CallCorrelationTask{current})
	require.Equal(t, uint64(42), d.CorrelationID, "administrative context affects membership, never an already sent ID")
}

func TestCallCorrelationIdentityHostNormalizationAndUserCase(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.NumberChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	p := contractInvite("a", 0, *now)
	p.VoIPData.From = "<sip:Alice@EXAMPLE.test>"
	p.VoIPData.To = "<sip:Bob@EXAMPLE.test>"
	a := contractResolve(c, p)
	lowerHost := contractInvite("b", 4, *now)
	lowerHost.VoIPData.From = "<sip:Alice@example.test>"
	lowerHost.VoIPData.To = "<sip:Bob@example.test>"
	b := contractResolve(c, lowerHost)
	require.Equal(t, a.CorrelationID, b.CorrelationID)
	lowerUser := contractInvite("c", 7, *now)
	lowerUser.VoIPData.From = "<sip:alice@example.test>"
	lowerUser.VoIPData.To = "<sip:Bob@example.test>"
	d := contractResolve(c, lowerUser)
	require.NotEqual(t, a.CorrelationID, d.CorrelationID)
	require.Empty(t, correlationIdentity(strings.Repeat("x", correlationMaxValue+1)))
	require.Empty(t, correlationIdentity("<sip:bad user@example.test>"))
	require.Empty(t, correlationIdentity("<sip:a@>"))
}

func TestCallCorrelationInvalidAddressesCannotChain(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	for _, value := range []string{"", "hostname.test", "192.0.2.999", "fe80::1%eth0"} {
		t.Run(value, func(t *testing.T) {
			c, now := newContractCorrelator(t, cfg, nil)
			p := contractInvite("a", 0, *now)
			p.DstIP = value
			a := contractResolve(c, p)
			q := contractInvite("b", 1, now.Add(time.Millisecond))
			q.SrcIP = value
			d := contractResolve(c, q)
			require.NotEqual(t, a.CorrelationID, d.CorrelationID)
		})
	}
}
