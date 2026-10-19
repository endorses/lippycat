//go:build hunter || all

package hunter

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

func mediaRuleHunterFixture(t *testing.T) *Hunter {
	t.Helper()
	h := &Hunter{config: Config{HunterID: "edge", VoIPMode: true, VoIPMediaPolicy: "processor", MediaRules: mediarules.Settings{ProcessorID: "receiver"}, TLSEnabled: true, TLSCertFile: "certificate", TLSKeyFile: "key", VoIPInterfaceDomains: map[string]mediaadmission.DomainID{"other": 1}}}
	require.NoError(t, h.configureMediaRules())
	t.Cleanup(func() { require.NoError(t, h.mediaRules.store.Close()) })
	return h
}
func currentMediaRule() mediarules.Rule {
	now := time.Now()
	return mediarules.Rule{ID: "current", Session: mediarules.Session{ProcessorID: "receiver", Generation: 1}, Revision: 1, Call: mediarules.CallAssociation{CallID: "call", Lifetime: callregistry.Lifetime{Session: 9, Generation: 7}, FromTag: "alice", ToTag: "bob", SelectionRevision: 1, FilterIDs: []string{"selected"}}, Scope: []mediarules.Scope{{HunterID: "edge", Domain: 0}}, Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Addr: netip.MustParseAddr("192.0.2.2"), Port: 45000}, Kind: mediarules.RTP}}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
}
func mediaRuleTestPacket(t *testing.T) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 45000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
func TestHunterMediaRulesConfigurationRequiresAuthorityAndVerifiedTLS(t *testing.T) {
	for _, tt := range []struct {
		name   string
		modify func(*Config)
	}{
		{"missing issuer", func(c *Config) { c.MediaRules.ProcessorID = "" }},
		{"insecure", func(c *Config) { c.TLSEnabled = false }},
		{"skip verification", func(c *Config) { c.TLSSkipVerify = true }},
		{"no client identity", func(c *Config) { c.TLSKeyFile = "" }},
		{"wrong mode", func(c *Config) { c.VoIPMode = false }},
		{"local media", func(c *Config) { c.MediaRules.Enabled = true; c.VoIPMediaPolicy = "local" }},
		{"invalid capacity", func(c *Config) { c.MediaRules.MaxRules = -1 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hunter{config: Config{HunterID: "edge", VoIPMode: true, VoIPMediaPolicy: "processor", MediaRules: mediarules.Settings{ProcessorID: "receiver"}, TLSEnabled: true, TLSCertFile: "certificate", TLSKeyFile: "key"}}
			tt.modify(&h.config)
			require.Error(t, h.configureMediaRules())
			require.Nil(t, h.VoIPMediaResolver())
		})
	}
	local := &Hunter{config: Config{VoIPMode: true}}
	require.NoError(t, local.configureMediaRules())
	require.Nil(t, local.VoIPMediaResolver())
	require.Equal(t, "matched", local.config.VoIPSignallingPolicy)
	require.Equal(t, "local", local.config.VoIPMediaPolicy)
}
func TestHunterMediaResolverRequiresCurrentExactDomainEndpointAndDialog(t *testing.T) {
	h := mediaRuleHunterFixture(t)
	r := h.mediaRules
	packet := mediaRuleTestPacket(t)
	_, matched := r.ResolveMedia(packet, "first")
	require.False(t, matched)
	rule := currentMediaRule()
	control, err := r.store.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, r.store.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	association, matched := r.ResolveMedia(packet, "first")
	require.True(t, matched)
	require.Equal(t, voip.RemoteCallAssociation{CallID: "call", Lifetime: rule.Call.Lifetime, SelectionRevision: rule.Call.SelectionRevision, ProcessorID: rule.Session.ProcessorID, ControlGeneration: rule.Session.Generation, InheritedFilterIDs: []string{"selected"}}, association)
	_, matched = r.ResolveMedia(packet, "other")
	require.False(t, matched)
	event := sharedsip.Event{CallID: "call", FromTag: "alice", ToTag: "bob", Method: "BYE", CSeqMethod: "BYE"}
	_, matched = r.ResolveSignalling(event, packet, "first")
	require.True(t, matched)
	_, matched = r.ResolveSignalling(event, packet, "other")
	require.False(t, matched)
	event.FromTag = "forged"
	_, matched = r.ResolveSignalling(event, packet, "first")
	require.False(t, matched)
	event.FromTag = "alice"
	event.CSeqMethod = "INVITE"
	_, matched = r.ResolveSignalling(event, packet, "first")
	require.False(t, matched)
	require.NoError(t, r.store.ApplyDelta(control, 2, nil, []string{rule.ID}))
	_, matched = r.ResolveMedia(packet, "first")
	require.False(t, matched)
	event.CSeqMethod = "BYE"
	_, matched = r.ResolveSignalling(event, packet, "first")
	require.False(t, matched)
}
func TestHunterMediaIssuerUsesVerifiedSANIdentity(t *testing.T) {
	certificate := &x509.Certificate{DNSNames: []string{"receiver"}, Subject: pkix.Name{CommonName: "legacy-cn"}}
	info := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}}
	require.NoError(t, verifiedMediaIssuer(&peer.Peer{AuthInfo: info}, "receiver"))
	require.Error(t, verifiedMediaIssuer(&peer.Peer{AuthInfo: info}, "legacy-cn"))
	require.Error(t, verifiedMediaIssuer(&peer.Peer{AuthInfo: info}, "forged"))
	info.State.VerifiedChains = nil
	require.Error(t, verifiedMediaIssuer(&peer.Peer{AuthInfo: info}, "receiver"))
	require.Error(t, verifiedMediaIssuer(nil, "receiver"))
}
func TestProcessorMediaRejectsIndependentIPSelectors(t *testing.T) {
	selected := &management.Filter{Id: "broad", Type: management.FilterType_FILTER_IP_ADDRESS, Enabled: true, Pattern: "192.0.2.0/24"}
	require.Error(t, validateProcessorMediaFilters([]*management.Filter{selected}))
	selected.Enabled = false
	require.NoError(t, validateProcessorMediaFilters([]*management.Filter{selected}))
	selected.Enabled = true
	selected.Type = management.FilterType_FILTER_SIP_USER
	require.NoError(t, validateProcessorMediaFilters([]*management.Filter{selected}))
}

func TestRemoteRuleRequiresCurrentInstalledCaptureRevision(t *testing.T) {
	h := mediaRuleHunterFixture(t)
	runtime := h.mediaRules
	current := uint64(7)
	runtime.capturePolicyCurrent = func(revision uint64) bool { return revision == current }
	rule := currentMediaRule()
	rule.Call.CapturePolicyRevision = 7
	control, err := runtime.store.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, runtime.store.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	packet := mediaRuleTestPacket(t)
	association, ok := runtime.ResolveMedia(packet, "first")
	require.True(t, ok)
	require.Equal(t, uint64(7), association.CapturePolicyRevision)
	current = 8
	_, ok = runtime.ResolveMedia(packet, "first")
	require.False(t, ok, "old remote rule cannot regain authority under a newer signed policy")
	event := sharedsip.Event{CallID: "call", FromTag: "alice", ToTag: "bob", Method: "BYE", CSeqMethod: "BYE"}
	_, ok = runtime.ResolveSignalling(event, packet, "first")
	require.False(t, ok)
	rule.Revision = 2
	rule.Call.CapturePolicyRevision = 8
	require.NoError(t, runtime.store.ApplySnapshot(control, 2, []mediarules.Rule{rule}))
	refreshed, ok := runtime.ResolveMedia(packet, "first")
	require.True(t, ok)
	require.False(t, association.SameSelection(refreshed), "pending old callback retains its original revision proof")
}

func TestHunterGrantResolverRequiresTypedPermissionAndPreservesExactProof(t *testing.T) {
	h := mediaRuleHunterFixture(t)
	r := h.mediaRules
	rule := currentMediaRule()
	rule.Call.FilterIDs = nil
	rule.Call.CapturePolicyRevision = 7
	rule.Call.SelectionGrants = []mediarules.SelectionRef{{ID: "opaque", Revision: 3}}
	rule.CaptureSignature = []byte("trusted-signature")
	control, err := r.store.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, r.store.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	packet := mediaRuleTestPacket(t)
	_, ok := r.ResolveMedia(packet, "first")
	require.False(t, ok, "rule alone is insufficient")
	permitted := true
	r.captureMediaRuleAllowed = func(w *management.MediaRule, p gopacket.Packet, domain uint32, at time.Time) bool {
		return permitted && proto.Equal(w, wire.EncodeRule(rule)) && p == packet && domain == 0
	}
	association, ok := r.ResolveMedia(packet, "first")
	require.True(t, ok)
	require.Equal(t, []string{"opaque"}, association.InheritedFilterIDs)
	decoded := &management.MediaRule{}
	require.NoError(t, proto.Unmarshal(association.CaptureSelectionProof, decoded))
	require.True(t, proto.Equal(wire.EncodeRule(rule), decoded))
	_, ok = r.ResolveSignalling(sharedsip.Event{CallID: "call", FromTag: "alice", ToTag: "bob", Method: "BYE", CSeqMethod: "BYE"}, packet, "first")
	require.False(t, ok, "media grant cannot select SIP")
	permitted = false
	_, ok = r.ResolveMedia(packet, "first")
	require.False(t, ok, "revoked permission wins over installed endpoints")
}

func TestVoIPSourceRejectsGenericTCPBeforeInstallation(t *testing.T) {
	adapter := core.Adapter{ID: "diagnostic", Version: 1, Validate: func(b core.Binding) error {
		if string(b.Context) != "diagnostic-v1" {
			return core.ErrInvalid
		}
		return nil
	}, Authorize: func(core.Binding) error { return nil }}
	h := &Hunter{config: Config{HunterID: "edge", VoIPMode: true, VoIPMediaPolicy: "processor", MediaRules: mediarules.Settings{ProcessorID: "receiver"}, TLSEnabled: true, TLSCertFile: "certificate", TLSKeyFile: "key", LearnedAdapters: []core.Adapter{adapter}}}
	require.NoError(t, h.configureMediaRules())
	t.Cleanup(func() { require.NoError(t, h.mediaRules.store.Close()) })
	session := core.Session{ProcessorID: "receiver", Generation: 1}
	control, err := h.mediaRules.store.StartSession("receiver", session)
	require.NoError(t, err)
	now := time.Now()
	binding := core.Binding{ID: "probe", Session: session, Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: "device", Incarnation: "one"}, AttributionContext: "diagnostic", Context: []byte("diagnostic-v1"), Scope: []core.Scope{{HunterID: "edge", Domain: 0}}, Selectors: []core.Selector{{Address: netip.MustParseAddr("192.0.2.1"), Port: 443, Protocol: core.TCP}}, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	require.ErrorIs(t, h.mediaRules.store.Core().ApplySnapshot(control, 1, []core.Binding{binding}), core.ErrUnsupported)
	require.False(t, h.mediaRules.store.Status().Ready)
	require.Empty(t, h.mediaRules.store.Core().ActiveRules())
}

func TestVoIPRuntimeFactoryBoundsTypedEvidenceCandidates(t *testing.T) {
	adapter := core.Adapter{ID: "diagnostic", Version: 1, Validate: func(core.Binding) error { return nil }, Authorize: func(core.Binding) error { return nil }}
	h := &Hunter{config: Config{HunterID: "edge", Interfaces: []string{"capture0"}, VoIPMode: true, VoIPMediaPolicy: "processor", MediaRules: mediarules.Settings{ProcessorID: "receiver"}, TLSEnabled: true, TLSCertFile: "certificate", TLSKeyFile: "key", LearnedAdapters: []core.Adapter{adapter}}}
	require.NoError(t, h.configureMediaRules())
	t.Cleanup(func() { require.NoError(t, h.mediaRules.store.Close()) })
	session := core.Session{ProcessorID: "receiver", Generation: 1}
	control, err := h.mediaRules.store.StartSession("receiver", session)
	require.NoError(t, err)
	now := time.Now()
	var bindings []core.Binding
	for i := 0; i <= learnedwire.DefaultEvidenceLimits.MaxCandidates; i++ {
		bindings = append(bindings, core.Binding{ID: fmt.Sprintf("diagnostic-%d", i), Session: session, Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: fmt.Sprintf("subject-%d", i), Incarnation: "one"}, AttributionContext: "diagnostic", Scope: []core.Scope{{HunterID: "edge", Domain: 0}}, Selectors: []core.Selector{{Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP}}, NotBefore: now, ExpiresAt: now.Add(time.Minute)})
	}
	require.NoError(t, h.mediaRules.store.Core().ApplySnapshot(control, 1, bindings[:learnedwire.DefaultEvidenceLimits.MaxCandidates]))
	complete := h.mediaRules.runtime.Match(mediaRuleTestPacket(t), "capture0")
	require.False(t, complete.Overflow)
	require.Len(t, complete.Bindings, learnedwire.DefaultEvidenceLimits.MaxCandidates)
	require.NoError(t, h.mediaRules.store.Core().ApplySnapshot(control, 2, bindings))
	result := h.mediaRules.runtime.Match(mediaRuleTestPacket(t), "capture0")
	require.True(t, result.Overflow)
	require.Empty(t, result.Bindings, "a truncated candidate set cannot be forwarded as complete evidence")
	require.EqualValues(t, 1, h.mediaRules.store.Core().Status().CandidateOverflows)
}
