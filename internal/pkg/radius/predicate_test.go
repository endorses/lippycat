package radius

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func predicateMessage(t *testing.T, avps ...[]byte) *Message {
	t.Helper()
	raw := make([]byte, 20)
	raw[0] = 1
	for _, avp := range avps {
		raw = append(raw, avp...)
	}
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	message, err := Decode(raw)
	require.NoError(t, err)
	return message
}
func predicateAVP(typ byte, value string) []byte {
	return append([]byte{typ, byte(len(value) + 2)}, []byte(value)...)
}
func TestExactPredicates(t *testing.T) {
	username, err := CompilePredicate(PredicateSpec{Kind: PredicateUserName, Value: "alice@example.test"})
	require.NoError(t, err)
	for _, value := range []string{"alice@example.test", "Alice@example.test", "alice@EXAMPLE.test", "alice", " alice@example.test", "alice@example.test\x00", "xalice@example.testx"} {
		got, err := username.Match(predicateMessage(t, predicateAVP(1, value)))
		require.NoError(t, err)
		require.Equal(t, value == "alice@example.test", got)
	}
	decomposed, err := CompilePredicate(PredicateSpec{Kind: PredicateUserName, Value: "e\u0301"})
	require.NoError(t, err)
	got, err := decomposed.Match(predicateMessage(t, predicateAVP(1, "é")))
	require.NoError(t, err)
	require.False(t, got)
	for _, value := range []string{"", "\xff", strings.Repeat("é", 127)} {
		_, err := CompilePredicate(PredicateSpec{Kind: PredicateUserName, Value: value})
		require.Error(t, err)
	}
	raw, err := CompilePredicate(PredicateSpec{Kind: PredicateAttribute, Value: " \t0104ff00\r\n"})
	require.NoError(t, err)
	require.Equal(t, "0104FF00", raw.Spec().Value)
	got, err = raw.Match(predicateMessage(t, []byte{1, 4, 255, 0}))
	require.NoError(t, err)
	require.True(t, got)
	got, err = username.Match(predicateMessage(t, predicateAVP(1, "alice@"), predicateAVP(1, "example.test")))
	require.NoError(t, err)
	require.False(t, got)
	got, err = username.Match(predicateMessage(t, predicateAVP(1, "wrong"), predicateAVP(1, "alice@example.test")))
	require.NoError(t, err)
	require.True(t, got)
}

func TestSubscriberMACProfile(t *testing.T) {
	valid := "02-00-00-00-00-AB"
	p, err := CompilePredicate(PredicateSpec{Kind: PredicateMAC, Value: valid, MACProfile: MACProfileUppercaseHyphen})
	require.NoError(t, err)
	for _, value := range []string{valid, "02-00-00-00-00-ab", "02:00:00:00:00:AB", "0200000000AB", "0200.0000.00AB", valid + ":SSID", valid + " ", " " + valid, valid + "\x00", valid + "-00"} {
		got, err := p.Match(predicateMessage(t, predicateAVP(31, value)))
		require.NoError(t, err)
		require.Equal(t, value == valid, got)
		_, err = CompilePredicate(PredicateSpec{Kind: PredicateMAC, Value: value, MACProfile: MACProfileUppercaseHyphen})
		if value != valid {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
	for _, profile := range []string{"", "unknown"} {
		_, err := CompilePredicate(PredicateSpec{Kind: PredicateMAC, Value: valid, MACProfile: profile})
		require.Error(t, err)
	}
	got, err := p.Match(predicateMessage(t, predicateAVP(30, valid)))
	require.NoError(t, err)
	require.False(t, got)
}

func TestAttributeTargetValidation(t *testing.T) {
	for _, value := range []string{"", "0102", "01036100", "010361010362", "0x010361", "01 03 61", "01:03:61", "01036", "0103GG", "\v010361", "020361", "1A0900000DEA010361", "1A0900000DE9020361", "1A0900000DE9010261", "1A0B00000DE90103610202", "1A0900000DE9010461", "1A0800000DE90102"} {
		t.Run(value, func(t *testing.T) {
			_, err := CompilePredicate(PredicateSpec{Kind: PredicateAttribute, Value: value})
			require.Error(t, err)
		})
	}
	for _, n := range []int{1, 63, 64} {
		avp := append([]byte{26, byte(8 + n), 0, 0, 13, 233, 1, byte(2 + n)}, []byte(strings.Repeat("a", n))...)
		_, err := CompilePredicate(PredicateSpec{Kind: PredicateAttribute, Value: hex.EncodeToString(avp)})
		if n <= 63 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	p, err := CompilePredicate(PredicateSpec{Kind: PredicateAttribute, Value: "1A1100000DE9010B636972637569742D61"})
	require.NoError(t, err)
	grouped := []byte{26, 20, 0, 0, 13, 233, 2, 3, 120, 1, 11, 'c', 'i', 'r', 'c', 'u', 'i', 't', '-', 'a'}
	got, err := p.Match(predicateMessage(t, grouped))
	require.NoError(t, err)
	require.True(t, got)
}

func TestPredicateRevalidatesEntireMessage(t *testing.T) {
	p, err := CompilePredicate(PredicateSpec{Kind: PredicateUserName, Value: "alice"})
	require.NoError(t, err)
	m := predicateMessage(t, predicateAVP(1, "alice"))
	m.Raw = append(m.Raw, 26, 8, 0, 0, 13, 233, 1, 8)
	binary.BigEndian.PutUint16(m.Raw[2:4], uint16(len(m.Raw)))
	got, err := p.Match(m)
	require.Error(t, err)
	require.False(t, got)
	m = predicateMessage(t, predicateAVP(1, "wrong"))
	m.Attributes[0].Value = []byte("alice")
	got, err = p.Match(m)
	require.NoError(t, err)
	require.False(t, got)
}

func TestCompoundScopeAndIndependentOwnership(t *testing.T) {
	scope := CaptureScope{OperatorScope: "operator-a/nas-a/poi-a", ProfileRevision: "v1", OriginNodeID: "hunter-a", SourceID: "eth0", Epoch: [16]byte{1}}
	spec := GroupSpec{ID: "group-a", TaskID: "task-a", TaskGeneration: 3, Scope: ScopeBinding{OperatorScope: scope.OperatorScope, ProfileRevision: scope.ProfileRevision}, Criteria: []PredicateSpec{
		{Kind: PredicateUserName, Value: "alice", FilterID: "user", FilterRevision: 2},
		{Kind: PredicateAttribute, Value: "57086C696E652D61", FilterID: "line", FilterRevision: 4},
	}}
	g, err := CompileGroup(spec)
	require.NoError(t, err)
	obs := &Observation{Scope: scope, Capture: CaptureInfo{ID: Identity{Epoch: scope.Epoch, Sequence: 1}}, Message: predicateMessage(t, predicateAVP(1, "alice"), predicateAVP(87, "line-a"))}
	ref, ok, err := g.Match(obs)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "task-a", ref.TaskID)
	require.Equal(t, uint64(3), ref.TaskGeneration)
	require.Len(t, ref.Criteria, 2)
	require.Equal(t, "account", ref.Criteria[0].TargetKind)
	require.Equal(t, "line", ref.Criteria[1].TargetKind)
	ref.Criteria[0].Value[0] = 'X'
	spec.Criteria[0].Value = "wrong"
	exported := g.Spec()
	exported.Criteria[0].Value = "wrong"
	_, ok, err = g.Match(obs)
	require.NoError(t, err)
	require.True(t, ok)
	for _, message := range []*Message{predicateMessage(t, predicateAVP(1, "alice")), predicateMessage(t, predicateAVP(87, "line-a"))} {
		obs.Message = message
		_, ok, err = g.Match(obs)
		require.NoError(t, err)
		require.False(t, ok)
	}
	obs.Message = predicateMessage(t, predicateAVP(1, "alice"), predicateAVP(87, "line-a"))
	for _, bad := range []CaptureScope{{}, {OperatorScope: "operator-b", ProfileRevision: "v1", OriginNodeID: "hunter-a", SourceID: "eth0", Epoch: [16]byte{1}}, {OperatorScope: scope.OperatorScope, ProfileRevision: "v2", OriginNodeID: "hunter-a", SourceID: "eth0", Epoch: [16]byte{1}}} {
		obs.Scope = bad
		_, ok, err = g.Match(obs)
		require.NoError(t, err)
		require.False(t, ok)
	}
	obs.Scope = scope
	other := g.Spec()
	other.ID = "group-b"
	other.TaskID = "task-b"
	other.Criteria[1].Value = "57086C696E652D62"
	g2, err := CompileGroup(other)
	require.NoError(t, err)
	_, ok, err = g2.Match(obs)
	require.NoError(t, err)
	require.False(t, ok)
	other.Criteria = g.Spec().Criteria
	g2, err = CompileGroup(other)
	require.NoError(t, err)
	ref, ok, err = g2.Match(obs)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "task-b", ref.TaskID)
	for _, mutate := range []func(*GroupSpec){func(s *GroupSpec) { s.Scope.OperatorScope = "" }, func(s *GroupSpec) { s.Scope.ProfileRevision = "" }, func(s *GroupSpec) { s.TaskGeneration = 0 }, func(s *GroupSpec) { s.Criteria[0].Kind = "sip" }, func(s *GroupSpec) { s.Criteria[0].FilterRevision = 0 }} {
		bad := g.Spec()
		mutate(&bad)
		_, err := CompileGroup(bad)
		require.Error(t, err)
	}
}

func TestGroupCaptureIdentityAndSourceBinding(t *testing.T) {
	scope := CaptureScope{OperatorScope: "operator", ProfileRevision: "1", OriginNodeID: "node", SourceID: "eth0", Epoch: [16]byte{1}}
	g, err := CompileGroup(GroupSpec{ID: "g", Scope: ScopeBinding{OperatorScope: scope.OperatorScope, ProfileRevision: scope.ProfileRevision, OriginNodeID: scope.OriginNodeID, SourceID: scope.SourceID}, Criteria: []PredicateSpec{{Kind: PredicateUserName, Value: "alice", FilterID: "f", FilterRevision: 1}}})
	require.NoError(t, err)
	good := &Observation{Scope: scope, Capture: CaptureInfo{ID: Identity{Epoch: scope.Epoch, Sequence: 1}}, Message: predicateMessage(t, predicateAVP(1, "alice"))}
	for _, mutate := range []func(*Observation){func(o *Observation) { o.Capture.ID.Sequence = 0 }, func(o *Observation) { o.Capture.ID.Epoch = [16]byte{2} }, func(o *Observation) { o.Scope.OriginNodeID = "other" }, func(o *Observation) { o.Scope.SourceID = "other" }} {
		obs := good.Clone()
		mutate(obs)
		_, ok, err := g.Match(obs)
		require.NoError(t, err)
		require.False(t, ok)
	}
	_, ok, err := g.Match(good)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestOrdinaryPredicateReference(t *testing.T) {
	p, err := CompilePredicate(PredicateSpec{Kind: PredicateAttribute, Value: "010361", FilterID: "ordinary", FilterRevision: 7})
	require.NoError(t, err)
	scope := CaptureScope{OriginNodeID: "node", SourceID: "eth0", OperatorScope: "operator", ProfileRevision: "1", Epoch: [16]byte{1}}
	obs := &Observation{Scope: scope, Capture: CaptureInfo{ID: Identity{Epoch: scope.Epoch, Sequence: 1}}, Message: predicateMessage(t, predicateAVP(1, "a"))}
	ref, ok, err := p.Reference(obs)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "ordinary", ref.CriterionGroupID)
	require.Empty(t, ref.TaskID)
	require.Zero(t, ref.TaskGeneration)
	require.Equal(t, uint64(7), ref.Criteria[0].FilterRevision)
	require.Equal(t, scope, ref.Scope)
	require.Equal(t, []byte("a"), ref.Criteria[0].Value)
	obs.Message = predicateMessage(t, predicateAVP(1, "b"))
	_, ok, err = p.Reference(obs)
	require.NoError(t, err)
	require.False(t, ok)
	bad := p.Spec()
	bad.FilterRevision = 0
	p, err = CompilePredicate(bad)
	require.NoError(t, err)
	_, ok, err = p.Reference(obs)
	require.Error(t, err)
	require.False(t, ok)
	_, err = (&Predicate{}).Match(obs.Message)
	require.Error(t, err)
	_, ok, err = (&Group{}).Match(obs)
	require.Error(t, err)
	require.False(t, ok)
}
