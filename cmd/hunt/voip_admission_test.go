//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type hunterAdmissionMap struct {
	mu      sync.Mutex
	entries map[mediaadmission.EndpointKey]struct{}
}

func (m *hunterAdmissionMap) PutEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[k] = struct{}{}
	return nil
}
func (m *hunterAdmissionMap) DeleteEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, k)
	return nil
}
func (m *hunterAdmissionMap) ListEndpoints(_ context.Context, d mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mediaadmission.EndpointKey
	for k := range m.entries {
		if k.Domain == d {
			out = append(out, k)
		}
	}
	return out, nil
}
func (*hunterAdmissionMap) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

type admissionForwarder struct{}

func (admissionForwarder) ForwardPacketWithMetadata(gopacket.Packet, *data.PacketMetadata, string, layers.LinkType) error {
	return nil
}

type admissionMatch struct{ selected bool }

func (f *admissionMatch) MatchPacket(gopacket.Packet) bool { return f.selected }
func (f *admissionMatch) MatchPacketWithIDs(p gopacket.Packet) (bool, []string) {
	if f.MatchPacket(p) {
		return true, []string{"selected"}
	}
	return false, nil
}

func admissionMessage(body string) []byte {
	return []byte(fmt.Sprintf("INVITE sip:bob@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-example\r\nFrom: <sip:alice@example.test>;tag=a\r\nTo: <sip:bob@example.test>;tag=b\r\nCall-ID: shared-id\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
}
func admissionUDPPacket(t *testing.T, name string, payload []byte) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return capture.PacketInfo{Packet: packet, Interface: name, LinkType: layers.LinkTypeRaw}
}
func TestAdmissionHunterDomainsAndLateSelection(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"other": 1}
	backend := &hunterAdmissionMap{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, backend)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
	router, err := newAdmissionHunterRouter(t.Context(), admissionForwarder{}, session, []string{"signal, media", "other"}, *voip.DefaultConfig())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close()) })
	require.Len(t, router.domains, 2)
	filter := &admissionMatch{}
	router.SetApplicationFilter(filter)
	sdp := "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 4000 RTP/AVP 0\r\na=rtcp-mux\r\n"
	router.ProcessPacket(admissionUDPPacket(t, "signal", admissionMessage(sdp)))
	require.Empty(t, backend.entries, "unselected SDP must not admit media")
	filter.selected = true
	router.ProcessPacket(admissionUDPPacket(t, "media", admissionMessage("")))
	want, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.2"), 4000)
	require.NoError(t, err)
	require.Contains(t, backend.entries, want, "same-domain interface can select retained SDP")
	require.Empty(t, router.domains[1].tracker.AdmissionRegistry().ActiveCalls())
	// Equal Call-ID/addresses in a separate domain must own separate registry
	// lifetimes and map membership, including synthesized TCP provenance.
	nf := gopacket.NewFlow(layers.EndpointIPv4, net.ParseIP("192.0.2.1").To4(), net.ParseIP("192.0.2.2").To4())
	tf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x13, 0xc4}, []byte{0x13, 0xc4})
	require.True(t, router.domains[1].tcp.HandleSIPMessageAt(admissionMessage(sdp), "shared-id", "192.0.2.1:5060", "192.0.2.2:5060", nf, tf, time.Now()))
	second := want
	second.Domain = 1
	require.Contains(t, backend.entries, second)
	router.domains[0].tracker.Shutdown()
	require.NotContains(t, backend.entries, want)
	require.Contains(t, backend.entries, second, "one domain teardown removed another domain")
}
