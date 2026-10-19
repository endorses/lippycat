//go:build (processor || tap || all) && li && linux

package processor

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// session is test ground truth, intentionally absent from the SIP message.
// Arrival order is slice order; at is capture time and need not increase.
type identitySyntheticSIP struct {
	session, id, from, to, branch, toTag, start string
	src, dst                                    string
	at                                          time.Time
	cseq                                        uint64
}

func identitySyntheticLeg(session, id string, hop int, at time.Time) identitySyntheticSIP {
	return identitySyntheticSIP{session: session, id: id, from: "sip:12025550101@example.test", to: "sip:12025550102@example.test", branch: "z9hG4bK-" + id, src: fmt.Sprintf("192.0.2.%d", hop+1), dst: fmt.Sprintf("192.0.2.%d", hop+2), at: at, cseq: 1}
}

func (f identitySyntheticSIP) raw() []byte {
	start := f.start
	if start == "" {
		start = "INVITE " + f.to + " SIP/2.0"
	}
	toTag := ""
	if f.toTag != "" {
		toTag = ";tag=" + f.toTag
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP %s:5060;branch=%s\r\nFrom: <%s>;tag=from-%s\r\nTo: <%s>%s\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\nContent-Length: 0\r\n\r\n", start, f.src, f.branch, f.from, f.id, f.to, toTag, f.id, f.cseq))
}

type identityParsedTCP struct {
	raw   []byte
	event sip.Event
}

type identityTCPHandler struct{ parsed chan identityParsedTCP }

func (h *identityTCPHandler) HandleSIPMessage(raw []byte, _ string, _, _ string, _, _ gopacket.Flow) bool {
	event, err := sip.Parse(raw, sip.ParseOptions{})
	if err != nil {
		return false
	}
	h.parsed <- identityParsedTCP{append([]byte(nil), raw...), event}
	return true
}

func (h *identityTCPHandler) HandleParsedSIPMessage(raw []byte, event sip.Event, _, _ string, _, _ gopacket.Flow) bool {
	h.parsed <- identityParsedTCP{append([]byte(nil), raw...), event}
	return true
}

func identityTransportParse(t *testing.T, f identitySyntheticSIP, transport string) *types.PacketDisplay {
	t.Helper()
	raw := f.raw()
	var event sip.Event
	var err error
	if transport == "tcp-segmented" {
		handler := &identityTCPHandler{parsed: make(chan identityParsedTCP, 1)}
		factory := voip.NewSipStreamFactory(t.Context(), handler)
		assembler := capture.NewTCPAssembler(factory)
		t.Cleanup(func() { assembler.FlushAll(); require.NoError(t, factory.Shutdown()) })
		feed := func(seq uint32, syn bool, payload []byte) {
			t.Helper()
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(f.src).To4(), DstIP: net.ParseIP(f.dst).To4()}
			tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: seq, SYN: syn, ACK: !syn}
			require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
			buffer := gopacket.NewSerializeBuffer()
			require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
			packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
			require.Nil(t, packet.ErrorLayer())
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), packet.Layer(layers.LayerTypeTCP).(*layers.TCP), f.at)
		}
		feed(100, true, nil)
		cut := len(raw) / 2
		feed(101, false, raw[:cut])
		feed(101+uint32(cut), false, raw[cut:])
		select {
		case result := <-handler.parsed:
			require.Equal(t, raw, result.raw)
			event = result.event
			require.Equal(t, f.at, event.Timestamp, "TCP framing preserves capture time")
		case <-time.After(5 * time.Second):
			t.Fatal("synthetic segmented TCP SIP did not reach production parser")
		}
	} else {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(f.src).To4(), DstIP: net.ParseIP(f.dst).To4()}
		udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, udp, gopacket.Payload(raw)))
		payload := append([]byte(nil), buffer.Bytes()...)
		if transport == "udp-fragmented" {
			defrag := capture.NewIPv4Defragmenter()
			cut := len(payload) / 2 / 8 * 8
			var complete *layers.IPv4
			// Reverse fragment arrival to exercise the supported defragmenter;
			// the SIP transaction's timestamp is independent of fragment order.
			for _, part := range []struct{ start, end int }{{cut, len(payload)}, {0, cut}} {
				fragment := *ip
				fragment.Id, fragment.FragOffset = 17, uint16(part.start/8)
				if part.end < len(payload) {
					fragment.Flags = layers.IPv4MoreFragments
				}
				frame := gopacket.NewSerializeBuffer()
				require.NoError(t, gopacket.SerializeLayers(frame, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &fragment, gopacket.Payload(payload[part.start:part.end])))
				packet := gopacket.NewPacket(frame.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
				complete, err = defrag.DefragIPv4WithTimestamp(packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4), f.at)
				require.NoError(t, err)
			}
			require.NotNil(t, complete)
			payload = complete.Payload
			require.EqualValues(t, 1, defrag.Snapshot().CompletedDatagrams)
		}
		packet := gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.Default)
		require.Nil(t, packet.ErrorLayer())
		raw = packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Payload
		require.Equal(t, f.raw(), raw)
		event, err = sip.Parse(raw, sip.ParseOptions{Timestamp: f.at, SourceIP: f.src, DestinationIP: f.dst, SourcePort: 5060, DestinationPort: 5060})
		require.NoError(t, err)
	}
	// The processor's metadata conversion verifies RawSIP against the actual
	// transport message, exactly as for locally captured or forwarded packets.
	frame := liTestSIPFrame(t, raw, transport == "tcp-segmented")
	metadata := sipMetadataForLI(&data.CapturedPacket{Data: frame, LinkType: uint32(layers.LinkTypeEthernet), Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{
		CallId: event.CallID, Method: event.Method, CseqMethod: event.CSeqMethod, CseqNumber: event.CSeqNumber, ViaBranch: event.ViaBranch,
		ResponseCode: uint32(event.ResponseCode), FromUri: event.From, ToUri: event.To, FromTag: event.FromTag, ToTag: event.ToTag,
	}}})
	require.Equal(t, raw, metadata.RawSIP)
	require.Equal(t, f.id, metadata.CallID)
	require.Equal(t, f.cseq, metadata.CSeqNumber)
	require.Equal(t, f.branch, metadata.ViaBranch)
	require.Equal(t, f.toTag, metadata.ToTag)
	return &types.PacketDisplay{SrcIP: f.src, DstIP: f.dst, Timestamp: f.at, Protocol: "SIP", VoIPData: metadata}
}

func identityFixtureCorrelator(t *testing.T, profiles ...li.CorrelationIdentityProfile) (*li.CallCorrelator, []li.CallCorrelationTask) {
	t.Helper()
	cfg := li.DefaultCallCorrelationConfig()
	cfg.AddressChaining, cfg.DecisionHorizon = true, time.Nanosecond
	cfg.IdentityProfiles = profiles
	c, err := li.NewCallCorrelator(cfg, time.Minute, nil)
	require.NoError(t, err)
	require.False(t, c.Stats().Blind)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	t.Logf("effective configuration: identity_profiles=%+v R1=true R2=false rewritten=false address_window=%s", profiles, cfg.AddressWindow)
	return c, []li.CallCorrelationTask{{XID: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Generation: 1}}
}

func TestProcessorCorrelationSyntheticNormalizedParserChain(t *testing.T) {
	profile := li.CorrelationIdentityProfile{
		Name: "example-global", Namespace: "example-tenant", SIPHosts: []string{"edge.example.test", "core.example.test"},
		AllowNumericSIP: true, AllowBareGlobal: true, InternationalPrefixes: []string{"00"},
	}
	for _, transport := range []string{"udp", "udp-fragmented", "tcp-segmented"} {
		t.Run(transport, func(t *testing.T) {
			c, tasks := identityFixtureCorrelator(t, profile)
			at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			forms := []string{"sip:+12025550102@edge.example.test", "sip:0012025550102@core.example.test", "sip:12025550102@edge.example.test"}
			var first li.CallCorrelationDecision
			for hop, form := range forms {
				f := identitySyntheticLeg("normalized-session", fmt.Sprintf("normalized-leg-%d", hop), hop, at.Add(time.Duration(hop)*time.Millisecond))
				f.to = form
				decision := c.Resolve(identityTransportParse(t, f, transport), tasks)
				if hop == 0 {
					first = decision
				} else {
					require.Equal(t, "R1", decision.Rule)
					require.Equal(t, first.CorrelationID, decision.CorrelationID, "configured forms in constructed session %s", f.session)
				}
			}
		})
	}
}

func TestProcessorCorrelationSyntheticParserChains(t *testing.T) {
	for _, transport := range []string{"udp", "udp-fragmented", "tcp-segmented"} {
		for _, legs := range []int{2, 4} {
			t.Run(fmt.Sprintf("%s/%d-legs", transport, legs), func(t *testing.T) {
				c, tasks := identityFixtureCorrelator(t)
				at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
				var first li.CallCorrelationDecision
				for hop := range legs {
					f := identitySyntheticLeg("constructed-session", fmt.Sprintf("synthetic-leg-%d", hop), hop, at.Add(time.Duration(hop)*time.Millisecond))
					packet := identityTransportParse(t, f, transport)
					decision := c.Resolve(packet, tasks)
					if hop == 0 {
						first = decision
					} else {
						require.Equal(t, "R1", decision.Rule)
						require.Equal(t, first.CorrelationID, decision.CorrelationID, "constructed session %s", f.session)
					}
					require.Equal(t, decision, c.Resolve(packet, tasks), "retransmission keeps the selected ID")
				}
			})
		}
	}
}

func TestProcessorCorrelationSyntheticTransactionForms(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	initial := identitySyntheticLeg("session-a", "transaction-forms", 0, at)
	initial.cseq = 0 // zero is a valid initial INVITE transaction number
	response := initial
	response.start, response.src, response.dst = "SIP/2.0 100 Trying", initial.dst, initial.src
	response.at = at.Add(-time.Millisecond)
	fork := response
	fork.start, fork.toTag = "SIP/2.0 180 Ringing", "fork-a"
	reinvite := initial
	reinvite.cseq, reinvite.branch, reinvite.toTag = 1, "z9hG4bK-reinvite", "confirmed"
	for _, transport := range []string{"udp", "udp-fragmented", "tcp-segmented"} {
		t.Run(transport, func(t *testing.T) {
			// Response-only and response-before-request fixture construction is
			// explicit. Reordering policy is tested separately at reservation.
			for _, f := range []identitySyntheticSIP{response, initial, initial, fork, reinvite} {
				p := identityTransportParse(t, f, transport)
				require.Equal(t, f.at, p.Timestamp)
				require.Equal(t, f.src, p.SrcIP)
				require.Equal(t, f.dst, p.DstIP)
			}
		})
	}
}
