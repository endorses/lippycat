//go:build tap || all

package tap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	evidencepb "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTapLocalMediaSubscriptionScopesExpiryAndWithdrawal(t *testing.T) {
	settings, err := (mediarules.Settings{}).Normalize()
	require.NoError(t, err)
	publisher, err := mediarules.New(settings.StoreConfig("tap.example.invalid", "", nil, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, publisher.Close()) })
	session := mediarules.Session{ProcessorID: "tap.example.invalid", Generation: 1}
	control, err := publisher.StartSession(session.ProcessorID, session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, nil))
	subscription, err := publisher.Subscribe()
	require.NoError(t, err)
	store, err := mediarules.New(settings.StoreConfig(session.ProcessorID, "tap.example.invalid-local", []mediaadmission.DomainID{1, 2}, nil))
	require.NoError(t, err)
	localControl, err := store.StartSession(session.ProcessorID, session)
	require.NoError(t, err)
	r := &tapMediaRules{store: store, subscription: subscription, control: localControl, hunterID: "tap.example.invalid-local", domains: map[string]mediaadmission.DomainID{"left": 1, "right": 2}, interval: time.Millisecond}
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	require.NoError(t, r.apply(subscription.Initial.Snapshot))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	now := time.Now()
	rule := mediarules.Rule{ID: "selected", Session: session, Revision: 2, Call: mediarules.CallAssociation{Lifetime: callregistry.Lifetime{Session: 3, Generation: 4}, CallID: "selected@example.invalid", FromTag: "alice", ToTag: "bob", SelectionRevision: 1, FilterIDs: []string{"local-only"}}, Scope: []mediarules.Scope{{HunterID: r.hunterID, Domain: 1}, {HunterID: "remote-hunter", Domain: 2}}, Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Domain: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 40000}, Kind: mediarules.RTPAndRTCP}, {Key: mediaadmission.EndpointKey{Domain: 2, Addr: netip.MustParseAddr("192.0.2.1"), Port: 40000}, Kind: mediarules.RTPAndRTCP}}, NotBefore: now, ExpiresAt: now.Add(time.Second)}
	require.NoError(t, publisher.ApplySnapshot(control, 2, []mediarules.Rule{rule}))
	packet := tapRuleMediaPacket(t)
	require.Eventually(t, func() bool { _, ok := r.ResolveMedia(packet, "left"); return ok }, time.Second, time.Millisecond)
	_, ok := r.ResolveMedia(packet, "right")
	require.False(t, ok, "remote hunter domain does not become local authority")
	_, ok = r.ResolveSignalling(sip.Event{CallID: rule.Call.CallID, FromTag: "alice", ToTag: "bob", Method: "BYE", CSeqMethod: "BYE"}, packet, "left")
	require.True(t, ok)
	_, ok = r.ResolveSignalling(sip.Event{CallID: rule.Call.CallID, FromTag: "alice", ToTag: "wrong", Method: "BYE", CSeqMethod: "BYE"}, packet, "left")
	require.False(t, ok)
	require.NoError(t, publisher.ApplySnapshot(control, 3, nil))
	require.Eventually(t, func() bool { _, ok := r.ResolveMedia(packet, "left"); return !ok }, time.Second, time.Millisecond)
	rule.Revision = 4
	rule.ExpiresAt = time.Now().Add(40 * time.Millisecond)
	rule.NotBefore = time.Now()
	require.NoError(t, publisher.ApplySnapshot(control, 4, []mediarules.Rule{rule}))
	require.Eventually(t, func() bool { _, ok := r.ResolveMedia(packet, "left"); return ok }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { _, ok := r.ResolveMedia(packet, "left"); return !ok }, time.Second, time.Millisecond)
	cancel()
	require.True(t, errors.Is(<-done, context.Canceled))
	require.False(t, store.Status().Ready)
}

func tapRuleMediaPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 50000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2})))
	return gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeRaw, gopacket.Default)
}

func TestTapGrantRulesPreserveSignatureAndRequireTypedMediaPermission(t *testing.T) {
	settings, err := (mediarules.Settings{}).Normalize()
	require.NoError(t, err)
	store, err := mediarules.New(settings.StoreConfig("processor", "local", []mediaadmission.DomainID{1}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	session := mediarules.Session{ProcessorID: "processor", Generation: 1}
	control, err := store.StartSession("processor", session)
	require.NoError(t, err)
	r := &tapMediaRules{store: store, control: control, hunterID: "local", domains: map[string]mediaadmission.DomainID{"left": 1}}
	now := time.Now()
	rule := mediarules.Rule{ID: "grant", Session: session, Revision: 1, Call: mediarules.CallAssociation{Lifetime: callregistry.Lifetime{Session: 3, Generation: 4}, CallID: "call", FromTag: "from", ToTag: "to", SelectionRevision: 1, CapturePolicyRevision: 7, SelectionGrants: []mediarules.SelectionRef{{ID: "opaque", Revision: 3}}}, Scope: []mediarules.Scope{{HunterID: "local", Domain: 1}}, Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Domain: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 40000}, Kind: mediarules.RTP}}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), CaptureSignature: []byte("signature")}
	require.NoError(t, r.apply(mediarules.Snapshot{Ready: true, Session: session, Sequence: 5, Rules: []mediarules.Rule{rule}}))
	require.Equal(t, rule, store.ActiveRules()[0], "projection cannot rewrite signed revision")
	packet := tapRuleMediaPacket(t)
	_, ok := r.ResolveMedia(packet, "left")
	require.False(t, ok)
	permitted := true
	r.validateMediaRule = func(w *management.MediaRule, source string, domain uint32, p gopacket.Packet, at time.Time) bool {
		return permitted && source == "local" && domain == 1 && proto.Equal(w, wire.EncodeRule(rule))
	}
	association, ok := r.ResolveMedia(packet, "left")
	require.True(t, ok)
	require.Equal(t, []string{"opaque"}, association.InheritedFilterIDs)
	require.True(t, r.ValidateMediaProof(packet, "left", association.CaptureSelectionProof, now))
	_, ok = r.ResolveSignalling(sip.Event{CallID: "call", FromTag: "from", ToTag: "to", Method: "BYE", CSeqMethod: "BYE"}, packet, "left")
	require.False(t, ok)
	permitted = false
	_, ok = r.ResolveMedia(packet, "left")
	require.False(t, ok)
	require.False(t, r.ValidateMediaProof(packet, "left", association.CaptureSelectionProof, now))
	// The command's mixed runtime callback retains this same original artifact
	// and capture time instead of substituting the current rule definition.
	candidate := learnedwire.Candidate(mediarules.ToBinding(rule))
	envelope := &pipeline.PacketEnvelope{Data: append([]byte(nil), packet.Data()...), LinkType: layers.LinkTypeRaw, CaptureTime: now, Source: pipeline.SourceProvenance{NodeID: "local", InterfaceName: "left", ObservationDomainKnown: true, ObservationDomain: 1}, LearnedCaptureEvidence: &evidencepb.LearnedCaptureEvidence{Version: 1, Candidates: []*evidencepb.LearnedCandidate{candidate}}}
	r.validateMediaRule = func(w *management.MediaRule, source string, domain uint32, _ gopacket.Packet, at time.Time) bool {
		return permitted && source == "local" && domain == 1 && at.Equal(now) && proto.Equal(w, wire.EncodeRule(rule))
	}
	permitted = true
	require.True(t, r.ValidateLearnedProof(envelope))
	for _, change := range []func(*pipeline.PacketEnvelope){
		func(e *pipeline.PacketEnvelope) { e.CaptureTime = e.CaptureTime.Add(time.Second) },
		func(e *pipeline.PacketEnvelope) { e.Source.NodeID = "other" },
		func(e *pipeline.PacketEnvelope) { e.Source.ObservationDomain = 2 },
		func(e *pipeline.PacketEnvelope) { e.Source.ObservationDomainKnown = false },
		func(e *pipeline.PacketEnvelope) { e.LearnedCaptureEvidence.Candidates[0].SubjectIncarnation = "reused" },
		func(e *pipeline.PacketEnvelope) { e.CaptureSelectionProof = []byte("contradictory field16") },
	} {
		changed := &pipeline.PacketEnvelope{
			Data:                   envelope.Data,
			LinkType:               envelope.LinkType,
			CaptureTime:            envelope.CaptureTime,
			Source:                 envelope.Source,
			LearnedCaptureEvidence: proto.Clone(envelope.LearnedCaptureEvidence).(*evidencepb.LearnedCaptureEvidence),
		}
		change(changed)
		require.False(t, r.ValidateLearnedProof(changed))
	}
	permitted = false
	require.False(t, r.ValidateLearnedProof(envelope), "current protected policy eligibility remains required")

}

func TestVoIPTapRejectsGenericTCPAtActualLocalSubscription(t *testing.T) {
	adapter := core.Adapter{ID: "diagnostic", Version: 1, Validate: func(b core.Binding) error {
		if string(b.Context) != "diagnostic-v1" {
			return core.ErrInvalid
		}
		return nil
	}, Authorize: func(core.Binding) error { return nil }}
	dir := filepath.Join(t.TempDir(), "managed")
	require.NoError(t, os.Mkdir(dir, 0700))
	p, err := processor.New(processor.Config{ProcessorID: "tap", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(dir, "filters.yaml"), LearnedAdapters: []core.Adapter{adapter}, MediaRules: processor.MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []processor.MediaSourceMapping{{HunterID: "tap-local", Interface: "capture0", Domain: 1, HunterDomain: 1}}}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	now := time.Now()
	binding := core.Binding{ID: "probe", Session: p.LearnedRulesSession(), Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: "device", Incarnation: "one"}, AttributionContext: "diagnostic", Context: []byte("diagnostic-v1"), Scope: []core.Scope{{HunterID: "tap-local", Domain: 1}}, Selectors: []core.Selector{{Domain: 1, Address: netip.MustParseAddr("192.0.2.1"), Port: 443, Protocol: core.TCP}}, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}))
	source, err := newTapMediaRules(p, p.MediaRuleConfiguration(), map[string]mediaadmission.DomainID{"capture0": 1}, nil)
	require.ErrorIs(t, err, core.ErrUnsupported)
	require.Nil(t, source)
	require.True(t, p.LearnedRulesStatus().Ready, "source refusal cannot mutate the authority's committed binding")
}
