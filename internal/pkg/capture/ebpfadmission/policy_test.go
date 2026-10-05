//go:build linux

package ebpfadmission

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

func fixture(t *testing.T, src, dst string, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: netip.MustParseAddr(src).AsSlice(), DstIP: netip.MustParseAddr(dst).AsSlice()}
	u := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	require.NoError(t, u.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, u, gopacket.Payload(payload)))
	return buf.Bytes()
}
func rawFilter(t *testing.T, expression string) []bpf.RawInstruction {
	t.Helper()
	instructions, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, expression)
	require.NoError(t, err)
	raw := make([]bpf.RawInstruction, len(instructions))
	for i, v := range instructions {
		raw[i] = bpf.RawInstruction{Op: v.Code, Jt: v.Jt, Jf: v.Jf, K: v.K}
	}
	return raw
}
func TestEmbeddedPolicyAndTranslation(t *testing.T) {
	spec, err := loadAdmission()
	require.NoError(t, err)
	require.Equal(t, ebpf.SocketFilter, spec.Programs["admit"].Type)
	for _, expr := range []string{"udp", "ip and udp port 4000", "(ip or ip6) and not port 53", "vlan and udp", "len > 100", "ip[6:2] & 0x3fff != 0"} {
		t.Run(expr, func(t *testing.T) { _, err := Translate(rawFilter(t, expr)); require.NoError(t, err) })
	}
}
func TestEndpointPacking(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		k, err := mediaadmission.NewEndpoint(2, netip.MustParseAddr(ip), 4000)
		require.NoError(t, err)
		packed, err := pack(k)
		require.NoError(t, err)
		require.Equal(t, k, unpack(packed))
	}
}

// LIPPYCAT_EBPF_TEST is deliberate opt-in: an unavailable privilege is a skip,
// never evidence that the kernel policy was exercised. In the integration job
// setting this variable makes load/test errors fatal.
func TestKernelDecisions(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("requires privileged Linux BPF test environment; set LIPPYCAT_EBPF_TEST=1")
	}
	b, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 2, EvidenceBytes: 4096, ShadowSampleEvery: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	ctx := context.Background()
	packet := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	p, err := b.NewProgram(0, 65535, 1, rawFilter(t, "udp and not port 53"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	check := func(packet []byte, want uint32) {
		t.Helper()
		got, _, err := p.Test(testRunFrame(packet))
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	check(packet, 0)
	endpoint, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.2"), 5000)
	require.NoError(t, err)
	require.NoError(t, b.PutEndpoint(ctx, endpoint))
	check(packet, 65535)
	require.NoError(t, b.DeleteEndpoint(ctx, endpoint))
	check(packet, 0)
	require.NoError(t, b.SetControl(ctx, 0, mediaadmission.Control{Mode: mediaadmission.KernelOpen, Generation: 7}))
	check(packet, 65535)
	restricted := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 53, []byte{0x80, 0})
	check(restricted, 0)
	reader, err := b.DecisionReader()
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	reader.SetDeadline(time.Now().Add(time.Second))
	require.NoError(t, b.SetControl(ctx, 0, mediaadmission.Control{Mode: mediaadmission.KernelShadow, Generation: 8}))
	check(packet, 65535)
	check(restricted, 0)
	record, err := reader.Read()
	require.NoError(t, err)
	decision, err := DecodeDecision(record.RawSample)
	require.NoError(t, err)
	require.Equal(t, uint64(8), decision.Generation)
	require.Equal(t, uint32(0), decision.Reason)
	counts, err := b.Counters(0)
	require.NoError(t, err)
	require.GreaterOrEqual(t, counts[12], uint64(2))
	require.NoError(t, b.SetControl(ctx, 0, mediaadmission.Control{Mode: mediaadmission.KernelEnforce, Generation: 9}))
	check(fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, []byte("INVITE sip:user")), 65535)
	require.NoError(t, b.ReplaceSelectors(ctx, 0, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, false))
	check(packet, 65535)
	require.NoError(t, b.ReplaceSelectors(ctx, 0, nil, false))
	check(packet, 0)
	require.NoError(t, b.ReplaceSelectors(ctx, 0, nil, true))
	check(packet, 65535)
	require.NoError(t, b.ReplaceSelectors(ctx, 0, nil, false))
	fragment := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
	check(fragment, 65535)
	// A selected endpoint in another domain cannot admit this packet.
	other, err := mediaadmission.NewEndpoint(1, endpoint.Addr, endpoint.Port)
	require.NoError(t, err)
	require.NoError(t, b.PutEndpoint(ctx, other))
	check(packet, 0)
}
func TestKernelPredicateEquivalence(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("privileged BPF equivalence test not exercised")
	}
	b, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 1, EvidenceBytes: 4096})
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close()) }()
	require.NoError(t, b.ReplaceSelectors(context.Background(), 0, nil, true))
	packets := predicateFixtures(t)
	for _, expr := range []string{"udp", "udp dst port 5000", "src host 192.0.2.1 and not dst port 53", "ip or ip6", "ip6 and udp", "len > 100", "vlan and udp", "vlan and vlan and udp", "ip[6:2] & 0x3fff != 0", "ip6[6] == 44", "udp port 4789", "ip proto 50 or ip6 proto 50"} {
		t.Run(expr, func(t *testing.T) {
			p, err := b.NewProgram(0, 96, 1, rawFilter(t, expr))
			require.NoError(t, err)
			defer func() { require.NoError(t, p.Close()) }()
			classic, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, expr)
			require.NoError(t, err)
			for _, mode := range []mediaadmission.KernelMode{mediaadmission.KernelEnforce, mediaadmission.KernelShadow, mediaadmission.KernelOpen} {
				require.NoError(t, b.SetControl(context.Background(), 0, mediaadmission.Control{Mode: mode}))
				for name, packet := range packets {
					t.Run(fmt.Sprintf("%d/%s", mode, name), func(t *testing.T) {
						got, _, err := p.Test(testRunFrame(packet))
						require.NoError(t, err)
						want := classic.Matches(gopacket.CaptureInfo{CaptureLength: len(packet), Length: len(packet)}, packet)
						require.Equal(t, want, got != 0)
						if want {
							require.Equal(t, uint32(96), got)
						}
					})
				}
			}
		})
	}
}

func predicateFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
	plain := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, media)
	vlan := append([]byte(nil), plain[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 7)
	vlan = append(vlan, plain[12:]...)
	qinq := append([]byte(nil), vlan[:12]...)
	qinq = append(qinq, 0x88, 0xa8, 0, 9)
	qinq = append(qinq, vlan[12:]...)
	ip6 := make([]byte, 74)
	copy(ip6, plain[:14])
	ip6[12], ip6[13] = 0x86, 0xdd
	ip6[14] = 0x60
	ip6[19], ip6[20], ip6[21] = 20, 17, 64
	src, dst := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
	copy(ip6[22:38], src[:])
	copy(ip6[38:54], dst[:])
	copy(ip6[54:], plain[34:54])
	ip6hop := append([]byte(nil), ip6[:54]...)
	ip6hop[20] = 0
	ip6hop[19] = 28
	ip6hop = append(ip6hop, 17, 0, 0, 0, 0, 0, 0, 0)
	ip6hop = append(ip6hop, ip6[54:]...)
	ip6frag := append([]byte(nil), ip6[:54]...)
	ip6frag[20] = 44
	ip6frag[19] = 28
	ip6frag = append(ip6frag, 17, 0, 0, 8, 0, 0, 0, 1)
	ip6frag = append(ip6frag, ip6[54:]...)
	first := append([]byte(nil), plain...)
	binary.BigEndian.PutUint16(first[20:22], 0x2000)
	later := append([]byte(nil), plain...)
	binary.BigEndian.PutUint16(later[20:22], 1)
	esp := append([]byte(nil), plain...)
	esp[23] = 50
	vxlan := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 4789, append([]byte{8, 0, 0, 0, 0, 0, 1, 0}, esp...))
	// VLAN-offloaded view is the Ethernet/IP byte sequence after hardware tag
	// stripping. Metadata-sensitive VLAN expressions are rejected by installer;
	// this fixture claims byte-view equivalence, not synthetic skb metadata.
	return map[string][]byte{"ipv4": plain, "dns": fixture(t, "192.0.2.1", "192.0.2.2", 4000, 53, media), "ipv6": ip6, "ipv6-hop": ip6hop, "ipv6-fragment": ip6frag, "ipv4-first-fragment": first, "ipv4-later-fragment": later, "vlan": vlan, "qinq": qinq, "vlan-stripped-view": append([]byte(nil), plain...), "esp": esp, "vxlan-esp": vxlan, "truncated-ethernet": plain[:3], "truncated-ip": plain[:22], "truncated-udp": plain[:38]}
}

func TestTranslateRejectsVLANAncillary(t *testing.T) {
	raw, err := bpf.Assemble([]bpf.Instruction{bpf.LoadExtension{Num: bpf.ExtVLANTagPresent}, bpf.RetA{}})
	require.NoError(t, err)
	_, err = Translate(raw)
	require.Error(t, err)
}

// bpf_prog_test_run_skb removes one Ethernet header for SOCKET_FILTER (unlike
// an actual SOCK_RAW AF_PACKET receive). A disposable outer header makes its
// skb data equal the real capture socket bytes; live socket tests are separate.
func testRunFrame(packet []byte) []byte {
	outer := make([]byte, 14, len(packet)+14)
	outer[12], outer[13] = 0x88, 0xb5
	return append(outer, packet...)
}

func TestKernelCompatibility(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("privileged compatibility tests not exercised")
	}
	b, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 1, EvidenceBytes: 4096, ESPEnabled: true})
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close()) }()
	p, err := b.NewProgram(0, 96, 1, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Close()) }()
	media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
	packet := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, media)
	vlan := append([]byte(nil), packet[:12]...)
	vlan = append(vlan, 0x81, 0, 0, 7)
	vlan = append(vlan, packet[12:]...)
	ip6 := make([]byte, 14+40+8+12)
	copy(ip6, packet[:14])
	ip6[12], ip6[13] = 0x86, 0xdd
	ip6[14] = 0x60
	ip6[18], ip6[19], ip6[20], ip6[21] = 0, 20, 17, 64
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(ip6[22:38], src[:])
	copy(ip6[38:54], dst[:])
	copy(ip6[54:], packet[34:54])
	frag := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(frag[20:22], 1)
	ip6frag := append([]byte(nil), ip6...)
	ip6frag[20] = 44
	esp := append([]byte(nil), packet...)
	esp[23] = 50
	vxlan := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 4789, append([]byte{8, 0, 0, 0, 0, 0, 1, 0}, esp...))
	for _, tc := range []struct {
		name   string
		packet []byte
		want   uint32
	}{{"ipv4-unselected", packet, 0}, {"vlan-unselected", vlan, 0}, {"ipv6-unselected", ip6, 0}, {"noninitial-fragment", frag, 96}, {"ipv6-fragment", ip6frag, 96}, {"esp-null", esp, 96}, {"vxlan-containing-esp", vxlan, 96}, {"truncated", packet[:15], 96}, {"short-udp", fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, []byte{0x80, 0}), 96}} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := p.Test(testRunFrame(tc.packet))
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
	ep, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("2001:db8::1"), 4000)
	require.NoError(t, err)
	require.NoError(t, b.PutEndpoint(context.Background(), ep))
	got, _, err := p.Test(testRunFrame(ip6))
	require.NoError(t, err)
	require.Equal(t, uint32(96), got)
	require.NoError(t, b.DeleteEndpoint(context.Background(), ep))
	require.NoError(t, b.ReplaceSelectors(context.Background(), 0, []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, false))
	got, _, err = p.Test(testRunFrame(ip6))
	require.NoError(t, err)
	require.Equal(t, uint32(96), got)
}

func TestKernelControlSurvivesEndpointCapacity(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("privileged capacity test not exercised")
	}
	b, err := NewBackend(Options{EndpointCapacity: 1, SelectorCapacity: 1, Domains: 1, EvidenceBytes: 4096})
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close()) }()
	a, _ := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.1"), 4000)
	c, _ := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.2"), 4000)
	require.NoError(t, b.PutEndpoint(context.Background(), a))
	require.Error(t, b.PutEndpoint(context.Background(), c))
	require.NoError(t, b.SetControl(context.Background(), 0, mediaadmission.Control{Mode: mediaadmission.KernelOpen, Generation: 42}))
	p, err := b.NewProgram(0, 65535, 1, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Close()) }()
	packet := fixture(t, "192.0.2.3", "192.0.2.4", 5000, 6000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	got, _, err := p.Test(testRunFrame(packet))
	require.NoError(t, err)
	require.Equal(t, uint32(65535), got)
}

func TestKernelExplicitProtocolConstraints(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("privileged explicit policy test not exercised")
	}
	b, err := NewBackend(Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 1, EvidenceBytes: 4096, SIPPorts: []uint16{5060, 5080}, RTPPortRanges: []PortRange{{Start: 4000, End: 4999}}, UDPOnly: true})
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close()) }()
	p, err := b.NewProgram(0, 65535, 1, rawFilter(t, "src host 192.0.2.1"))
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Close()) }()
	media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
	for _, mode := range []mediaadmission.KernelMode{mediaadmission.KernelEnforce, mediaadmission.KernelOpen, mediaadmission.KernelShadow} {
		require.NoError(t, b.SetControl(context.Background(), 0, mediaadmission.Control{Mode: mode}))
		require.NoError(t, b.ReplaceSelectors(context.Background(), 0, nil, true))
		for _, tc := range []struct {
			port    uint16
			payload []byte
			want    uint32
		}{{5060, []byte("INVITE sip:user"), 65535}, {5080, []byte("INVITE sip:user"), 65535}, {5090, []byte("INVITE sip:user"), 0}, {4100, media, 65535}, {4100, []byte("ordinary UDP"), 0}, {6000, media, 0}} {
			packet := fixture(t, "192.0.2.1", "192.0.2.2", 7000, tc.port, tc.payload)
			got, _, err := p.Test(testRunFrame(packet))
			require.NoError(t, err)
			require.Equal(t, tc.want, got, "mode=%d port=%d", mode, tc.port)
		}

		// IP selectors admit candidates independently of call endpoints. The
		// configured failure-open/shadow modes retain the explicit port predicate,
		// even when the selector itself misses; userspace still applies selection.
		for _, selector := range []struct {
			prefix string
			match  bool
		}{
			{"192.0.2.2/32", true}, {"198.51.100.0/24", false},
		} {
			require.NoError(t, b.ReplaceSelectors(context.Background(), 0, []netip.Prefix{netip.MustParsePrefix(selector.prefix)}, false))
			for _, port := range []uint16{4100, 6000} {
				packet := fixture(t, "192.0.2.1", "192.0.2.2", 7000, port, media)
				got, _, err := p.Test(testRunFrame(packet))
				require.NoError(t, err)
				want := uint32(0)
				if port == 4100 && (selector.match || mode != mediaadmission.KernelEnforce) {
					want = 65535
				}
				require.Equal(t, want, got, "mode=%d selector-match=%t port=%d", mode, selector.match, port)
			}
		}
		// UDP-only remains explicit even when ESP compatibility is otherwise enabled.
		esp := fixture(t, "192.0.2.1", "192.0.2.2", 4000, 5000, media)
		esp[23] = 50
		got, _, err := p.Test(testRunFrame(esp))
		require.NoError(t, err)
		require.Zero(t, got)
	}
}
