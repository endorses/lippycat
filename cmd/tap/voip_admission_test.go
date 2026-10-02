//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"net"
	"sync"
	"testing"
	"time"
)

type tapAdmissionMaps struct {
	mu   sync.Mutex
	keys map[mediaadmission.EndpointKey]bool
}

func (b *tapAdmissionMaps) PutEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[k] = true
	return nil
}
func (b *tapAdmissionMaps) DeleteEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.keys, k)
	return nil
}
func (b *tapAdmissionMaps) ListEndpoints(_ context.Context, d mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []mediaadmission.EndpointKey
	for k := range b.keys {
		if k.Domain == d {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
func (*tapAdmissionMaps) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

type tapAdmissionFilter struct{}

func (tapAdmissionFilter) MatchPacket(gopacket.Packet) bool { return true }
func (tapAdmissionFilter) MatchPacketWithIDs(gopacket.Packet) (bool, []string) {
	return true, []string{"identity"}
}
func tapAdmissionPacket(t *testing.T, iface string, payload []byte, media bool) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	if media {
		udp.SrcPort = 10000
		udp.DstPort = 20000
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return capture.PacketInfo{Packet: packet, Interface: iface}
}
func TestTapAdmissionRoutingUDPAndTCPHaveIsolatedOwners(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"right": 1}
	maps := &tapAdmissionMaps{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	require.NoError(t, err)
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
	defer func() { require.NoError(t, session.Close()) }()
	pc := voipprocessor.DefaultConfig()
	pc.ApplicationFilter = tapAdmissionFilter{}
	pc.NeedFilterIDs = true
	routing, err := newTapVoIPRouting(pc, *voip.GetConfig(), 1, session, 10*time.Millisecond, []string{"left", "right"})
	require.NoError(t, err)
	defer routing.Close()
	require.NotSame(t, routing.engines[0], routing.engines[1])
	body := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"
	message := []byte(fmt.Sprintf("INVITE sip:b@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKsame\r\nFrom: <sip:a@example.invalid>;tag=a\r\nTo: <sip:b@example.invalid>\r\nCall-ID: same-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	udp := routing.adapter.ProcessPacketInfo(tapAdmissionPacket(t, "left", message, false))
	require.NotNil(t, udp)
	require.True(t, udp.IsVoIPPacket())
	mediaPayload := []byte{0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
	require.Equal(t, callregistry.MediaUnresolved, routing.adapter.ProcessPacketInfo(tapAdmissionPacket(t, "right", mediaPayload, true)).GetMediaResolution().Status)
	nf := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
	tf := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x13, 0xc4}, []byte{0x13, 0xc4})
	require.True(t, routing.handlers[1].HandleSIPMessage(message, "same-call", "192.0.2.1:5060", "192.0.2.2:5060", nf, tf))
	select {
	case injected := <-routing.injection:
		require.Equal(t, "right", injected.PacketInfo.Interface)
		require.NotZero(t, injected.CallLifetime.Session)
		require.NotEqual(t, udp.GetCallLifetime(), injected.CallLifetime)
		require.Equal(t, "same-call", injected.Metadata.GetSip().CallId)
	case <-time.After(time.Second):
		t.Fatal("TCP injection missing")
	}
	for _, iface := range []string{"left", "right"} {
		result := routing.adapter.ProcessPacketInfo(tapAdmissionPacket(t, iface, mediaPayload, true))
		require.Equal(t, callregistry.MediaResolved, result.GetMediaResolution().Status)
		require.Equal(t, "same-call", result.GetCallID())
		keys, err := maps.ListEndpoints(context.Background(), cfg.DomainForInterface(iface))
		require.NoError(t, err)
		require.Len(t, keys, 2)
	}
}
