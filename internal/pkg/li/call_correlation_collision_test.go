//go:build li

package li

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

// Session labels describe the synthetic construction. They are deliberately not
// sent to the correlator: neither party identity nor temporal proximity supplies
// independent session ground truth.
type collisionSessionLeg struct {
	session string
	packet  *types.PacketDisplay
}

func collisionLeg(session, id string, hop int, at time.Time, caller, called string) collisionSessionLeg {
	p := contractInvite(id, hop, at)
	p.VoIPData.From, p.VoIPData.To = caller, called
	return collisionSessionLeg{session: session, packet: p}
}

func TestCallCorrelationWeakRuleSessionLimits(t *testing.T) {
	const caller = "sip:12025550101@example.test"
	const called = "sip:12025550102@example.test"
	const other = "sip:12025550103@example.test"
	for _, scenario := range []struct {
		name, rule      string
		sameSession     bool
		callerChanged   bool
		calledChanged   bool
		finalBeforeNext bool
	}{
		{name: "R1 legitimate caller rewrite", rule: "R1", sameSession: true, callerChanged: true},
		{name: "R1 unrelated concurrent call with one address candidate", rule: "R1", callerChanged: true},
		{name: "R2 unrelated concurrent exact pair", rule: "R2"},
		{name: "R2 rapid redial after final response", rule: "R2", finalBeforeNext: true},
		{name: "rewritten address unrelated party pair", rule: "R1_rewritten", callerChanged: true, calledChanged: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = scenario.rule == "R1"
			cfg.NumberChaining = scenario.rule == "R2"
			cfg.AddressChainingRewritten = scenario.rule == "R1_rewritten"
			t.Logf("effective configuration: identity_profiles=none R1=%t R2=%t rewritten=%t address_window=%s number_window=%s", cfg.AddressChaining, cfg.NumberChaining, cfg.AddressChainingRewritten, cfg.AddressWindow, cfg.NumberWindow)
			c, now := newContractCorrelator(t, cfg, nil)
			first := collisionLeg("session-a", "root", 0, *now, caller, called)
			secondSession := "session-b"
			if scenario.sameSession {
				secondSession = first.session
			}
			hop := 1
			if scenario.rule == "R2" {
				hop = 4 // no address evidence; R2 is the only applicable method
			}
			second := collisionLeg(secondSession, "next", hop, now.Add(100*time.Millisecond), caller, called)
			if scenario.callerChanged {
				second.packet.VoIPData.From = other
			}
			if scenario.calledChanged {
				second.packet.VoIPData.To = "sip:12025550104@example.test"
			}
			a := contractResolve(c, first.packet)
			if scenario.finalBeforeNext {
				response := contractInvite("root", 0, now.Add(50*time.Millisecond))
				response.SrcIP, response.DstIP = response.DstIP, response.SrcIP
				response.VoIPData.Method, response.VoIPData.Status = "", 486
				require.Equal(t, a.CorrelationID, contractResolve(c, response).CorrelationID)
			}
			b := contractResolve(c, second.packet)
			require.Equal(t, scenario.rule, b.Rule)
			require.Equal(t, a.CorrelationID, b.CorrelationID)
			if scenario.sameSession {
				require.Equal(t, first.session, second.session)
			} else {
				require.NotEqual(t, first.session, second.session)
				t.Log("known cross-session merge: opt-in weak evidence does not uniquely identify a session")
			}
		})
	}
}

func TestCallCorrelationWeakRuleResidualSplits(t *testing.T) {
	for _, scenario := range []string{"identity", "address window", "number window", "setup overlap", "task context", "expiry", "capacity", "address suppresses R2", "R1 ambiguity", "R2 ambiguity"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining = true
			if scenario == "number window" || scenario == "R2 ambiguity" {
				cfg.AddressChaining, cfg.NumberChaining = false, true
			}
			if scenario == "address suppresses R2" {
				cfg.NumberChaining = true
			}
			if scenario == "capacity" {
				cfg.MaxCandidates = 1
			}
			t.Logf("effective configuration: identity_profiles=none R1=%t R2=%t rewritten=%t address_window=%s number_window=%s max_candidates=%d", cfg.AddressChaining, cfg.NumberChaining, cfg.AddressChainingRewritten, cfg.AddressWindow, cfg.NumberWindow, cfg.MaxCandidates)
			c, now := newContractCorrelator(t, cfg, nil)
			first := contractInvite("root", 0, *now)
			a := contractResolve(c, first)
			next := contractInvite("next", 1, now.Add(100*time.Millisecond))
			tasks := []CallCorrelationTask{correlationTaskX}
			wantReason := "no_candidate"
			switch scenario {
			case "identity":
				next.VoIPData.To = "sip:12025550199@example.test"
			case "address window":
				next.Timestamp = now.Add(cfg.AddressWindow + time.Nanosecond)
			case "number window":
				next.SrcIP, next.DstIP = "198.51.100.1", "198.51.100.2"
				next.Timestamp = now.Add(cfg.NumberWindow + time.Nanosecond)
			case "setup overlap":
				response := contractInvite("root", 0, now.Add(50*time.Millisecond))
				response.SrcIP, response.DstIP = response.DstIP, response.SrcIP
				response.VoIPData.Method, response.VoIPData.Status = "", 200
				contractResolve(c, response)
			case "task context":
				tasks = []CallCorrelationTask{correlationTaskY}
			case "expiry":
				*now = now.Add(cfg.AddressWindow + time.Second)
			case "capacity":
				wantReason = "candidate_limit"
			case "address suppresses R2":
				// A remote exact pair is otherwise valid R2 evidence. The adjacent
				// root has a different called party, yet still suppresses fallback.
				remote := contractInvite("remote-pair", 5, next.Timestamp)
				remote.VoIPData.To = "sip:12025550199@example.test"
				contractResolve(c, remote)
				next.VoIPData.To = remote.VoIPData.To
			case "R1 ambiguity":
				other := contractInvite("other-root", 5, *now)
				other.DstIP = first.DstIP
				contractResolve(c, other)
				wantReason = "ambiguous"
			case "R2 ambiguity":
				other := contractInvite("other-root", 5, now.Add(cfg.NumberWindow+100*time.Millisecond))
				contractResolve(c, other)
				next.SrcIP, next.DstIP = "203.0.113.1", "203.0.113.2"
				next.Timestamp = now.Add(300 * time.Millisecond)
				wantReason = "ambiguous"
			}
			b := contractResolve(c, next, tasks...)
			require.NotEqual(t, a.CorrelationID, b.CorrelationID)
			require.Empty(t, b.Rule)
			require.Equal(t, wantReason, b.Reason)
		})
	}
}

func TestCallCorrelationWeakRuleNormalizedSessionLimits(t *testing.T) {
	for _, rule := range []string{"R1", "R2"} {
		t.Run(rule, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.AddressChaining, cfg.NumberChaining = rule == "R1", rule == "R2"
			cfg.IdentityProfiles = []CorrelationIdentityProfile{{
				Name: "example-global", Namespace: "example-tenant", SIPHosts: []string{"edge.example.test", "core.example.test"},
				AllowNumericSIP: true, AllowBareGlobal: true, InternationalPrefixes: []string{"00"},
			}}
			t.Logf("effective configuration: identity_profiles=%+v R1=%t R2=%t rewritten=false address_window=%s number_window=%s", cfg.IdentityProfiles, cfg.AddressChaining, cfg.NumberChaining, cfg.AddressWindow, cfg.NumberWindow)
			c, now := newContractCorrelator(t, cfg, nil)
			first := collisionLeg("session-a", "normalized-root", 0, *now, "sip:+12025550101@edge.example.test", "sip:+12025550102@edge.example.test")
			hop := 1
			if rule == "R2" {
				hop = 4
			}
			second := collisionLeg("session-b", "normalized-unrelated", hop, now.Add(100*time.Millisecond), "sip:0012025550101@core.example.test", "sip:0012025550102@core.example.test")
			a, b := contractResolve(c, first.packet), contractResolve(c, second.packet)
			require.NotEqual(t, first.session, second.session)
			require.Equal(t, rule, b.Rule)
			require.Equal(t, a.CorrelationID, b.CorrelationID, "normalization does not make weak session evidence unique")
		})
	}
}
