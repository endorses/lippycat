//go:build (processor || tap || all) && li

package processor

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Handover topology from docs/research/li-payload-direction-unresolved-for-rtp.md:
// the target's handset (ue) sits behind an IMS media gateway (gw) whose address
// is what the target's SDP advertises; the remote party is on the network side
// (core). The gateway preserves SSRC across both legs.
const (
	dirUEAddr   = "2001:db8:a::1"
	dirUEPort   = "49120"
	dirGWAddr   = "2001:db8:b::2"
	dirGWPort   = "40696"
	dirCoreAddr = "2001:db8:c::8c"
	dirCorePort = "35448"

	dirCallID    = "li-direction-test@example.invalid"
	dirTargetURI = "sip:+15551230000@ims.example.invalid"
	dirRemoteURI = "sip:+15559990000@ims.example.invalid"
)

var dirTarget = li.TargetIdentity{Type: li.TargetTypeTELURI, Value: "tel:+15551230000"}

func dirSDP(addr, port string) string {
	return fmt.Sprintf("v=0\r\no=- 1 1 IN IP6 %s\r\nc=IN IP6 %s\r\nm=audio %s RTP/AVP 104\r\n", addr, addr, port)
}

// dirSIPPacket builds a SIP packet carrying SDP, as the packet pipeline would
// hand it to the LI layer: metadata fields plus the raw packet bytes.
func dirSIPPacket(startLine string, status int, from, to, toTag, sdp string) *types.PacketDisplay {
	raw := startLine + "\r\nCall-ID: " + dirCallID + "\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n" + sdp
	method := ""
	if status == 0 {
		method = "INVITE"
	}
	toHeader := "<" + to + ">"
	if toTag != "" {
		toHeader += ";tag=" + toTag
	}
	return &types.PacketDisplay{
		SrcIP: dirGWAddr, SrcPort: "5060", DstIP: dirCoreAddr, DstPort: "5060",
		Protocol: "SIP",
		RawData:  []byte(raw),
		VoIPData: &types.VoIPMetadata{
			CallID: dirCallID, Method: method, CSeqMethod: "INVITE", Status: status,
			From: "<" + from + ">;tag=abc", To: toHeader, FromTag: "abc", ToTag: toTag,
		},
	}
}

func dirRTPPacket(ssrc uint32, srcIP, srcPort, dstIP, dstPort string) *types.PacketDisplay {
	return &types.PacketDisplay{
		SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
		Protocol: "RTP",
		RawData:  make([]byte, 172), // RTP header + AMR-WB payload
		VoIPData: &types.VoIPMetadata{
			CallID: dirCallID, IsRTP: true, SSRC: ssrc, PayloadType: 104, SequenceNum: 1,
		},
	}
}

// newLIProcessor creates a processor with LI enabled and one single-target task
// active, returning the LI filter ID that packets must report as matched.
func newLIProcessor(t *testing.T, deliveryType li.DeliveryType) (*Processor, uuid.UUID, string) {
	t.Helper()

	p, err := New(Config{
		ProcessorID: "test-li-direction",
		ListenAddr:  "localhost:0",
		MaxHunters:  1,
		LIEnabled:   true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := p.Shutdown(); err != nil {
			t.Logf("processor shutdown: %v", err)
		}
	})
	require.NotNil(t, p.liManager, "LI manager should be initialized")
	require.NotNil(t, liMediaDirection, "media direction resolver should be initialized")

	// A task needs a destination even though no delivery client is configured
	// here: PDUs are encoded and their direction stamped regardless.
	did := uuid.New()
	require.NoError(t, p.liManager.CreateDestination(&li.Destination{
		DID: did, Address: "mdf.example.invalid", Port: 9999,
		X2Enabled: true, X3Enabled: true,
	}))

	xid := uuid.New()
	require.NoError(t, p.liManager.ActivateTask(&li.InterceptTask{
		XID:            xid,
		Targets:        []li.TargetIdentity{dirTarget},
		DestinationIDs: []uuid.UUID{did},
		DeliveryType:   deliveryType,
	}))

	return p, xid, fmt.Sprintf("li-%s-0", xid.String())
}

// feedIncomingCallSignalling replays the signalling of a call to the target: the
// remote party offers its own address, the target answers with the gateway's.
func feedIncomingCallSignalling(p *Processor, filterID string) {
	p.processLIPacket(
		dirSIPPacket("INVITE "+dirTargetURI+" SIP/2.0", 0, dirRemoteURI, dirTargetURI, "", dirSDP(dirCoreAddr, dirCorePort)),
		[]string{filterID})
	p.processLIPacket(
		dirSIPPacket("SIP/2.0 200 OK", 200, dirRemoteURI, dirTargetURI, "xyz", dirSDP(dirGWAddr, dirGWPort)),
		[]string{filterID})
}

// TestProcessLIPacket_ResolvesMediaDirection verifies the processor's LI path
// learns the target's media endpoints from signalling and labels both legs of
// each RTP stream — the regression that left every CC PDU indeterminate.
func TestProcessLIPacket_ResolvesMediaDirection(t *testing.T) {
	p, xid, filterID := newLIProcessor(t, li.DeliveryX2andX3)

	before := p.getLIEncodingStats()
	feedIncomingCallSignalling(p, filterID)

	const ssrcToTarget = uint32(0x002a016b)
	const ssrcFromTarget = uint32(0x15f7e400)

	// Network-side leg first (both endpoints known from SDP), then the
	// access-side leg of the same SSRC, whose far end is in no SDP.
	packets := []*types.PacketDisplay{
		dirRTPPacket(ssrcToTarget, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort),
		dirRTPPacket(ssrcToTarget, dirGWAddr, dirGWPort, dirUEAddr, dirUEPort),
		dirRTPPacket(ssrcFromTarget, dirGWAddr, dirGWPort, dirCoreAddr, dirCorePort),
		dirRTPPacket(ssrcFromTarget, dirUEAddr, dirUEPort, dirGWAddr, dirGWPort),
	}
	for _, pkt := range packets {
		p.processLIPacket(pkt, []string{filterID})
	}

	after := p.getLIEncodingStats()
	assert.Equal(t, uint64(4), after.X3Encoded-before.X3Encoded, "all four RTP packets encoded as CC")
	assert.Equal(t, uint64(2), after.DirectionResolvedMedia-before.DirectionResolvedMedia,
		"one direction resolution per SSRC")
	assert.Equal(t, uint64(0), after.DirectionUnknownRTP-before.DirectionUnknownRTP,
		"no RTP packet should be left without a direction")

	// The direction the encoder stamped on each PDU comes from this resolver
	// state, which the processor built while handling the packets above.
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		liMediaDirection.PayloadDirection(xid, dirTarget, packets[0]))
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		liMediaDirection.PayloadDirection(xid, dirTarget, packets[1]),
		"access-side leg must inherit the SSRC verdict, not be inverted")
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		liMediaDirection.PayloadDirection(xid, dirTarget, packets[2]))
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		liMediaDirection.PayloadDirection(xid, dirTarget, packets[3]))
}

// TestProcessLIPacket_X3OnlyTaskLearnsFromSignalling verifies signalling is
// observed even when no IRI is delivered: an X3-only task delivers no X2, but
// its media direction still depends on the SIP it never hands over.
func TestProcessLIPacket_X3OnlyTaskLearnsFromSignalling(t *testing.T) {
	p, xid, filterID := newLIProcessor(t, li.DeliveryX3Only)

	before := p.getLIEncodingStats()
	feedIncomingCallSignalling(p, filterID)

	networkLeg := dirRTPPacket(0x002a016b, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
	p.processLIPacket(networkLeg, []string{filterID})

	after := p.getLIEncodingStats()
	assert.Equal(t, uint64(0), after.X2Encoded-before.X2Encoded, "X3-only task delivers no IRI")
	assert.Equal(t, uint64(1), after.DirectionResolvedMedia-before.DirectionResolvedMedia)
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		liMediaDirection.PayloadDirection(xid, dirTarget, networkLeg))
}

// TestProcessLIPacket_UnobservedSignallingStaysUnknown verifies the resolver
// still declines when the evidence is absent (task activated mid-call).
func TestProcessLIPacket_UnobservedSignallingStaysUnknown(t *testing.T) {
	p, xid, filterID := newLIProcessor(t, li.DeliveryX2andX3)

	before := p.getLIEncodingStats()
	networkLeg := dirRTPPacket(0x002a016b, dirCoreAddr, dirCorePort, dirGWAddr, dirGWPort)
	p.processLIPacket(networkLeg, []string{filterID})

	after := p.getLIEncodingStats()
	assert.Equal(t, uint64(1), after.X3Encoded-before.X3Encoded, "media is still delivered")
	assert.Equal(t, uint64(0), after.DirectionResolvedMedia-before.DirectionResolvedMedia)
	assert.Equal(t, uint64(1), after.DirectionUnknownRTP-before.DirectionUnknownRTP)
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		liMediaDirection.PayloadDirection(xid, dirTarget, networkLeg))
}
