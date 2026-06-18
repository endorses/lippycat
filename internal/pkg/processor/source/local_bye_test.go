package source

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// inviteOnlyFilter matches only INVITE requests (and returns a filter ID for
// them), mimicking an identity-based filter (e.g. P-Asserted-Identity) that is
// present in the INVITE but not in in-dialog requests like BYE.
type inviteOnlyFilter struct{}

func (f *inviteOnlyFilter) MatchPacket(packet gopacket.Packet) bool {
	matched, _ := f.MatchPacketWithIDs(packet)
	return matched
}

func (f *inviteOnlyFilter) MatchPacketWithIDs(packet gopacket.Packet) (bool, []string) {
	if app := packet.ApplicationLayer(); app != nil {
		if bytes.HasPrefix(app.Payload(), []byte("INVITE ")) {
			return true, []string{"filter-1"}
		}
	}
	if tl := packet.TransportLayer(); tl != nil {
		if bytes.HasPrefix(tl.LayerPayload(), []byte("INVITE ")) {
			return true, []string{"filter-1"}
		}
	}
	return false, nil
}

func buildUDPSIPPacket(t *testing.T, payload string) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      net.ParseIP("2a03:9ec0::1"),
		DstIP:      net.ParseIP("2a03:9ec0::2"),
	}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip6))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload([]byte(payload))))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	return capture.PacketInfo{LinkType: layers.LinkTypeEthernet, Packet: pkt, Interface: "test"}
}

// TestLocalSource_ForwardsInDialogBYEForMatchedCall verifies that a BYE for an
// already-matched call is forwarded even when the BYE itself does not match the
// application filter. Without this, the call's termination is dropped and the
// call is shown as "Active" forever in the remote TUI.
func TestLocalSource_ForwardsInDialogBYEForMatchedCall(t *testing.T) {
	const callID = "test-call-end-abc123"

	invite := "INVITE sip:+4915215940608@ims.example SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2a03:9ec0::1]:5060\r\n" +
		"From: <sip:+4915215940608@ims.example>;tag=aaa\r\n" +
		"To: <tel:01630071100>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"P-Asserted-Identity: <sip:+4915215940608@ims.example>\r\n\r\n"
	// BYE in the same dialog, WITHOUT the matched identity (no P-Asserted-Identity,
	// tags/direction swapped) so it does not directly match the filter.
	bye := "BYE sip:+4915215940608@ims.example SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP [2a03:9ec0::2]:5060\r\n" +
		"From: <tel:01630071100>;tag=bbb\r\n" +
		"To: <sip:+4915215940608@ims.example>;tag=aaa\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 2 BYE\r\n\r\n"

	cfg := DefaultLocalSourceConfig()
	cfg.BatchTimeout = 15 * time.Millisecond
	s := NewLocalSource(cfg)
	s.voipProcessor = voipprocessor.NewSourceAdapter(voipprocessor.New(voipprocessor.DefaultConfig()))
	s.appFilter = &inviteOnlyFilter{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.ctx = ctx
	s.packetBuffer = capture.NewPacketBuffer(ctx, 100)

	s.wg.Add(1)
	go s.batchingLoop()

	require.True(t, s.packetBuffer.Send(buildUDPSIPPacket(t, invite)))
	require.True(t, s.packetBuffer.Send(buildUDPSIPPacket(t, bye)))

	// Collect forwarded packets for our call.
	methods := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(methods) < 2 {
		select {
		case batch := <-s.Batches():
			for _, p := range batch.Packets {
				if p.Metadata != nil && p.Metadata.Sip != nil && p.Metadata.Sip.CallId == callID {
					methods[p.Metadata.Sip.Method] = true
				}
			}
		case <-deadline:
			t.Fatalf("timed out; forwarded methods so far: %v", methods)
		}
	}

	require.True(t, methods["INVITE"], "INVITE should be forwarded (direct filter match)")
	require.True(t, methods["BYE"], "BYE should be forwarded for the matched call via the CallID cache")
}
