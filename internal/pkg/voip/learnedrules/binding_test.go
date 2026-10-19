package learnedrules

import (
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func adapterRule() Rule {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	return Rule{ID: "rule", Session: Session{ProcessorID: "central", Generation: 2}, Revision: 7,
		Call:  CallAssociation{Lifetime: callregistry.Lifetime{Session: 3, Generation: 4}, CallID: "call", FromTag: "from", ToTag: "to", SelectionRevision: 5, FilterIDs: []string{"filter"}},
		Scope: []Scope{{HunterID: "source", Domain: 9}}, Endpoints: []Endpoint{{Key: mediaadmission.EndpointKey{Domain: 9, Addr: netip.MustParseAddr("192.0.2.1"), Port: 10000}, Kind: RTPAndRTCP}}, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
}

func TestBindingRoundTripAndOwnedContext(t *testing.T) {
	for _, protected := range []bool{false, true} {
		rule := adapterRule()
		if protected {
			rule.Call.CapturePolicyRevision = 9
			rule.Call.SelectionGrants = []SelectionRef{{ID: "opaque", Revision: 2}}
			rule.CaptureSignature = []byte("original signature")
		}
		binding := ToBinding(rule)
		require.Equal(t, core.Subject{ID: "call", Incarnation: "3:4"}, binding.Subject)
		require.Equal(t, "voip.call", binding.AttributionContext)
		require.NoError(t, Adapter().Validate(binding))
		decoded, err := FromBinding(binding)
		require.NoError(t, err)
		require.True(t, EqualRule(rule, decoded))
		rule.Call.FilterIDs[0] = "mutated"
		decoded, err = FromBinding(binding)
		require.NoError(t, err)
		require.Equal(t, "filter", decoded.Call.FilterIDs[0])
	}
}

func TestProtectedBindingCannotBroadenLegacyArtifact(t *testing.T) {
	rule := adapterRule()
	rule.Call.CapturePolicyRevision = 9
	rule.Call.SelectionGrants = []SelectionRef{{ID: "opaque", Revision: 2}}
	rule.CaptureSignature = []byte("signature")
	original := ToBinding(rule)
	tests := map[string]func(*core.Binding){
		"authority":         func(b *core.Binding) { b.Session.Generation++ },
		"incarnation":       func(b *core.Binding) { b.Subject.Incarnation = "3:5" },
		"revision":          func(b *core.Binding) { b.Revision++ },
		"intent":            func(b *core.Binding) { b.Intents[0].Revision++ },
		"scope":             func(b *core.Binding) { b.Scope[0].HunterID = "other" },
		"validity":          func(b *core.Binding) { b.ExpiresAt = b.ExpiresAt.Add(time.Second) },
		"endpoint":          func(b *core.Binding) { b.Selectors[0].Port++ },
		"transport":         func(b *core.Binding) { b.Selectors[0].Protocol = core.TCP },
		"direction":         func(b *core.Binding) { b.Selectors[0].Direction = core.Source },
		"qualification":     func(b *core.Binding) { b.Selectors[0].Qualifier = core.Qualifier{} },
		"context version":   func(b *core.Binding) { b.ContextVersion++ },
		"context namespace": func(b *core.Binding) { b.AttributionContext = "other" },
		"unknown context":   func(b *core.Binding) { b.Context = append(b.Context[:len(b.Context)-1], []byte(",\"unknown\":1}")...) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			binding := core.CloneBinding(original)
			change(&binding)
			require.Error(t, Adapter().Validate(binding))
		})
	}
}

func TestVoIPQualifierIsBranchSpecificAndUDPOnly(t *testing.T) {
	rtp := core.Packet{Protocol: core.UDP, Payload: []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	rtcp := core.Packet{Protocol: core.UDP, Payload: []byte{0x80, 200, 0, 0, 0, 0, 0, 0}}
	require.True(t, Qualify(qualifiers[RTP], rtp))
	require.False(t, Qualify(qualifiers[RTCP], rtp))
	require.True(t, Qualify(qualifiers[RTCP], rtcp))
	require.False(t, Qualify(qualifiers[RTP], rtcp))
	require.True(t, Qualify(qualifiers[RTPAndRTCP], rtp))
	require.True(t, Qualify(qualifiers[RTPAndRTCP], rtcp))
	rtp.Protocol = core.TCP
	require.False(t, Qualify(qualifiers[RTPAndRTCP], rtp))
}

func TestSelectionRevisionCannotRegress(t *testing.T) {
	before := adapterRule()
	after := CloneRule(before)
	after.Revision++
	after.Call.SelectionRevision--
	require.ErrorIs(t, Adapter().ValidateTransition(ToBinding(before), ToBinding(after)), core.ErrRevision)
}
