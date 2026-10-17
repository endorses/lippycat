//go:build linux

package admissionintegration

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/admissionadapter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

type remoteRuleClock struct {
	mu      sync.Mutex
	wall    time.Time
	elapsed time.Duration
}

func (c *remoteRuleClock) Now() time.Time         { c.mu.Lock(); defer c.mu.Unlock(); return c.wall }
func (c *remoteRuleClock) Elapsed() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.elapsed }
func (c *remoteRuleClock) advance(d time.Duration) {
	c.mu.Lock()
	c.wall = c.wall.Add(d)
	c.elapsed += d
	c.mu.Unlock()
}

type remoteRuleSocket struct {
	domain         mediaadmission.DomainID
	name           string
	left, right    netlink.Link
	handle, sender *pcap.Handle
	attachment     *preparedFilter
	programFD      int
	programID      uint32
}

func remoteRuleLink(t *testing.T, index int) *remoteRuleSocket {
	t.Helper()
	leftName, rightName := fmt.Sprintf("ra%d%d", os.Getpid(), index), fmt.Sprintf("rb%d%d", os.Getpid(), index)
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: leftName}, PeerName: rightName}))
	left, err := netlink.LinkByName(leftName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, netlink.LinkDel(left)) })
	right, err := netlink.LinkByName(rightName)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(left))
	require.NoError(t, netlink.LinkSetUp(right))
	return &remoteRuleSocket{domain: mediaadmission.DomainID(index), name: leftName, left: left, right: right}
}
func (s *remoteRuleSocket) activate(t *testing.T, session *Session) {
	t.Helper()
	iface := pcaptypes.CreateLiveInterface(s.name)
	require.NoError(t, iface.(interface{ ConfigureSocketAdmission() error }).ConfigureSocketAdmission())
	require.NoError(t, iface.SetHandle())
	handle, err := iface.Handle()
	require.NoError(t, err)
	s.handle = handle
	attachment, err := session.Installer().Prepare(t.Context(), handle, s.name, "udp and not port 53")
	require.NoError(t, err)
	s.attachment = attachment.(*preparedFilter)
	require.NoError(t, attachment.Activate())
	s.programFD = s.attachment.program.FD()
	info, err := s.attachment.program.Info()
	require.NoError(t, err)
	id, available := info.ID()
	require.True(t, available, "kernel must expose loaded program identity")
	s.programID = uint32(id)
	sender, err := pcap.OpenLive(s.right.Attrs().Name, 65535, false, 50*time.Millisecond)
	require.NoError(t, err)
	s.sender = sender
	t.Cleanup(func() { sender.Close(); handle.Close(); require.NoError(t, attachment.Close()) })
}
func (s *remoteRuleSocket) frame(t *testing.T, port uint16, marker string) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: s.right.Attrs().HardwareAddr, DstMAC: s.left.Attrs().HardwareAddr, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1").AsSlice(), DstIP: netip.MustParseAddr("192.0.2.2").AsSlice()}
	udp := &layers.UDP{SrcPort: 4000, DstPort: layers.UDPPort(port)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	payload := append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)))
	return buf.Bytes()
}
func (s *remoteRuleSocket) assertPacket(t *testing.T, port uint16, marker string, want bool) {
	t.Helper()
	require.NoError(t, s.sender.WritePacketData(s.frame(t, port, marker)))
	deadline := time.Now().Add(450 * time.Millisecond)
	found := false
	for time.Now().Before(deadline) {
		packet, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		require.NoError(t, err)
		if bytes.Contains(packet, []byte(marker)) {
			found = true
			break
		}
	}
	require.Equal(t, want, found, "domain %d marker %s", s.domain, marker)
	require.Equal(t, s.programFD, s.attachment.program.FD(), "rule updates must retain the capture attachment")
	info, err := s.attachment.program.Info()
	require.NoError(t, err)
	id, available := info.ID()
	require.True(t, available)
	require.Equal(t, s.programID, uint32(id), "rule updates must retain the loaded kernel program")
}

// This crosses the actual Store -> Projection -> Controller -> BPF map -> live
// socket boundary. Only rule time is simulated; packet admission and map reads
// use the kernel. The existing isolated Docker runner explicitly enables it.
func TestLiveRemoteRulesUpdateSharedMapsWithoutCaptureRestart(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: requires privileged isolated Linux network; set LIPPYCAT_EBPF_TEST=1")
	}
	ctx := t.Context()
	first, second := remoteRuleLink(t, 1), remoteRuleLink(t, 2)
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.FailurePolicy = mediaadmission.FailureClosed
	cfg.EndpointCapacity = 16
	cfg.OwnerCapacity = 8
	cfg.MaxEndpointsPerOwner = 4
	cfg.ShadowEvidenceCapacity = 8
	cfg.RetryInterval = time.Hour
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{first.name: 1, second.name: 2}
	session, err := NewSession(ctx, cfg, SessionOptions{SIPPorts: []uint16{5060}, UDPOnly: true})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	first.activate(t, session)
	second.activate(t, session)
	projection, err := admissionadapter.New(ctx, session.Controller, []mediaadmission.DomainID{1, 2}, nil)
	require.NoError(t, err)
	clock := &remoteRuleClock{wall: time.Now()}
	store, err := mediarules.New(mediarules.Config{ProcessorID: "processor", HunterID: "hunter", Domains: []mediaadmission.DomainID{1, 2}, MaxRules: 8, MaxBytes: 32768, MaxEndpoints: 16, MaxEndpointsPerRule: 4, MaxSubscribers: 1, SubscriptionBuffer: 2, MaxLifetime: time.Minute, Clock: clock, Observer: projection})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	issuing := mediarules.Session{ProcessorID: "processor", Generation: 1}
	control, err := store.StartSession("processor", issuing)
	require.NoError(t, err)
	rule := func(id string, domain mediaadmission.DomainID, port uint16, generation uint64, revision mediarules.Revision) mediarules.Rule {
		return mediarules.Rule{ID: id, Session: issuing, Revision: revision, Call: mediarules.CallAssociation{Lifetime: callregistry.Lifetime{Session: 77, Generation: generation}, CallID: "call-" + id, SelectionRevision: uint64(revision), FilterIDs: []string{"configured-filter"}}, Scope: []mediarules.Scope{{HunterID: "hunter", Domain: domain}}, Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Domain: domain, Addr: netip.MustParseAddr("192.0.2.2"), Port: port}, Kind: mediarules.RTP}}, NotBefore: clock.Now(), ExpiresAt: clock.Now().Add(10 * time.Second)}
	}
	assertProjection := func(owners1, owners2 int, keys1, keys2 []mediaadmission.EndpointKey) {
		t.Helper()
		require.NoError(t, projection.Error())
		require.True(t, projection.Ready(store.Status().Sequence))
		backend := session.installer.(*Installer).backend
		for domain, want := range map[mediaadmission.DomainID][]mediaadmission.EndpointKey{1: keys1, 2: keys2} {
			got, err := backend.ListEndpoints(ctx, domain)
			require.NoError(t, err)
			require.ElementsMatch(t, want, got)
		}
		for _, scope := range session.Controller.Status() {
			switch scope.Domain {
			case 1:
				require.Equal(t, owners1, scope.Owners)
			case 2:
				require.Equal(t, owners2, scope.Owners)
			}
		}
	}
	a := rule("a", 1, 5000, 1, 1)
	key1 := a.Endpoints[0].Key
	require.NoError(t, store.ApplySnapshot(control, 1, []mediarules.Rule{a}))
	assertProjection(1, 0, []mediaadmission.EndpointKey{key1}, nil)
	first.assertPacket(t, 5000, "snapshot-selected", true)
	second.assertPacket(t, 5000, "foreign-domain", false)
	b, d := rule("b", 1, 5000, 2, 2), rule("d", 2, 6000, 3, 2)
	key2 := d.Endpoints[0].Key
	require.NoError(t, store.ApplyDelta(control, 2, []mediarules.Rule{b, d}, nil))
	assertProjection(2, 1, []mediaadmission.EndpointKey{key1}, []mediaadmission.EndpointKey{key2})
	require.True(t, store.Resolve(key1, key1).Ambiguous, "shared endpoints do not invent one call owner")
	require.NoError(t, store.ApplyDelta(control, 3, nil, []string{"a"}))
	assertProjection(1, 1, []mediaadmission.EndpointKey{key1}, []mediaadmission.EndpointKey{key2})
	resolved := store.Resolve(key1, key1)
	require.True(t, resolved.Resolved)
	require.Equal(t, b.Call.Lifetime, resolved.Call.Lifetime)
	first.assertPacket(t, 5000, "shared-owner-survives", true)
	second.assertPacket(t, 6000, "second-domain-selected", true)
	first.assertPacket(t, 6000, "second-domain-isolated", false)
	require.NoError(t, store.ApplyDelta(control, 4, nil, []string{"b"}))
	assertProjection(0, 1, nil, []mediaadmission.EndpointKey{key2})
	first.assertPacket(t, 5000, "last-owner-removed", false)
	// A complete replacement snapshot retires every omitted rule and can reuse a
	// SIP Call-ID only with its newly supplied opaque lifetime.
	reused := rule("a", 1, 5000, 4, 5)
	require.NoError(t, store.ApplySnapshot(control, 5, []mediarules.Rule{reused}))
	assertProjection(1, 0, []mediaadmission.EndpointKey{key1}, nil)
	resolved = store.Resolve(key1, key1)
	require.True(t, resolved.Resolved)
	require.Equal(t, reused.Call.Lifetime, resolved.Call.Lifetime)
	require.NotEqual(t, a.Call.Lifetime, resolved.Call.Lifetime)
	require.ErrorIs(t, store.ApplyDelta(control, 4, nil, []string{"a"}), mediarules.ErrRevision)
	first.assertPacket(t, 5000, "new-lifetime", true)
	second.assertPacket(t, 6000, "snapshot-omission", false)
	// Expiry reaches the real map through the same maintenance Sweep used by the
	// runtime, without waiting on wall time or replacing a capture program.
	clock.advance(11 * time.Second)
	require.NoError(t, store.Sweep())
	assertProjection(0, 0, nil, nil)
	first.assertPacket(t, 5000, "expired-rule", false)
	oldControl := control
	issuing.Generation = 2
	control, err = store.StartSession("processor", issuing)
	require.NoError(t, err)
	require.False(t, projection.Ready(store.Status().Sequence))
	require.ErrorIs(t, store.ApplySnapshot(oldControl, 6, []mediarules.Rule{reused}), mediarules.ErrSession)
	current := rule("a", 1, 5000, 5, 1)
	require.NoError(t, store.ApplySnapshot(control, 1, []mediarules.Rule{current}))
	assertProjection(1, 0, []mediaadmission.EndpointKey{key1}, nil)
	first.assertPacket(t, 5000, "new-control-session", true)
	// Explicit capture restrictions continue to apply after every dynamic change.
	require.ErrorContains(t, first.handle.SetBPFFilter("udp"), "cannot replace")
	require.NoError(t, store.Close())
	first.assertPacket(t, 5000, "closed-control-store", false)
}
