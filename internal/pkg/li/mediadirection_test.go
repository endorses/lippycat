//go:build li

package li

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Topology from docs/research/li-payload-direction-unresolved-for-rtp.md, with
// the documentation addresses made parseable:
//
//	ue   - the target's handset, behind the access gateway. Never appears in any
//	       SDP the network captures.
//	gw   - the IMS media gateway. This is the address in the target's SDP.
//	core - the remote party, on the network side.
//
// Media is relayed by the gateway, which preserves SSRC across both legs:
//
//	network-side leg: core <-> gw
//	access-side leg:  gw   <-> ue
const (
	ueAddr   = "2001:db8:a::1"
	uePort   = "49120"
	gwAddr   = "2001:db8:b::2"
	gwPort   = "40696"
	coreAddr = "2001:db8:c::8c"
	corePort = "35448"

	// ssrcToTarget carries audio arriving at the target, ssrcFromTarget audio
	// leaving it (SSRC values as observed in the handover).
	ssrcToTarget   = uint32(0x002a016b)
	ssrcFromTarget = uint32(0x15f7e400)

	testCallID = "call-a@example.invalid"
)

// msisdnTarget is the intercept target: an MSISDN, i.e. an identity target with
// no per-packet presence in RTP.
var msisdnTarget = TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551230000"}

const (
	targetURI = "sip:+15551230000@ims.example.invalid"
	remoteURI = "sip:+15559990000@ims.example.invalid"
)

// sdpBody builds an SDP body advertising one audio stream.
func sdpBody(addr, port string) string {
	return fmt.Sprintf("v=0\r\no=- 1 1 IN IP6 %s\r\nc=IN IP6 %s\r\nm=audio %s RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
		addr, addr, port)
}

// inviteRequest builds an initial INVITE carrying the caller's offer.
func inviteRequest(callID, from, to, sdp string) *types.PacketDisplay {
	msg := "INVITE " + to + " SIP/2.0\r\nCall-ID: " + callID +
		"\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n" + sdp
	return &types.PacketDisplay{
		VoIPData: &types.VoIPMetadata{
			CallID: callID, Method: "INVITE", CSeqMethod: "INVITE",
			From: "<" + from + ">;tag=abc", To: "<" + to + ">",
			FromTag: "abc", RawSIP: []byte(msg),
		},
	}
}

// inviteOK builds a 200 OK to INVITE carrying the callee's answer.
func inviteOK(callID, from, to, sdp string) *types.PacketDisplay {
	msg := "SIP/2.0 200 OK\r\nCall-ID: " + callID +
		"\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n" + sdp
	return &types.PacketDisplay{
		VoIPData: &types.VoIPMetadata{
			CallID: callID, CSeqMethod: "INVITE", Status: 200,
			From: "<" + from + ">;tag=abc", To: "<" + to + ">;tag=xyz",
			FromTag: "abc", ToTag: "xyz", RawSIP: []byte(msg),
		},
	}
}

// reInvite builds a re-INVITE (in-dialog, To-tag present) with an offer.
func reInvite(callID, from, to, sdp string) *types.PacketDisplay {
	msg := "INVITE " + to + " SIP/2.0\r\nCall-ID: " + callID +
		"\r\nCSeq: 2 INVITE\r\nContent-Type: application/sdp\r\n\r\n" + sdp
	return &types.PacketDisplay{
		VoIPData: &types.VoIPMetadata{
			CallID: callID, Method: "INVITE", CSeqMethod: "INVITE",
			From: "<" + from + ">;tag=abc", To: "<" + to + ">;tag=xyz",
			FromTag: "abc", ToTag: "xyz", RawSIP: []byte(msg),
		},
	}
}

// rtpPkt builds an RTP packet on one leg of a media stream.
func rtpPkt(callID string, ssrc uint32, srcIP, srcPort, dstIP, dstPort string) *types.PacketDisplay {
	return &types.PacketDisplay{
		SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
		VoIPData: &types.VoIPMetadata{
			CallID: callID, IsRTP: true, SSRC: ssrc, PayloadType: 104,
		},
	}
}

// newTestResolver creates a resolver with the background sweeper disabled so
// tests drive eviction deterministically.
func newTestResolver(t *testing.T, cfg MediaDirectionConfig) *MediaDirectionResolver {
	t.Helper()
	cfg.SweepInterval = -1
	r := NewMediaDirectionResolver(cfg)
	t.Cleanup(r.Close)
	return r
}

// observeIncomingCall replays the signalling of a call to the target: the remote
// party offers its own media address, the target answers with the gateway's.
func observeIncomingCall(r *MediaDirectionResolver, xid uuid.UUID, callID string) {
	r.ObserveSIP(xid, msisdnTarget, inviteRequest(callID, remoteURI, targetURI, sdpBody(coreAddr, corePort)))
	r.ObserveSIP(xid, msisdnTarget, inviteOK(callID, remoteURI, targetURI, sdpBody(gwAddr, gwPort)))
}

func TestMediaDirection_IncomingCallBothLegs(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()
	observeIncomingCall(r, xid, testCallID)

	// Network-side leg: both endpoints appear in the call's SDP, so this is
	// where the direction is derived.
	networkToTarget := rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, networkToTarget))

	// Access-side leg of the same SSRC: the far end (the handset) is in no SDP,
	// and the target's SDP address is the *source* here. Matching per packet
	// would label this fromTarget; the SSRC verdict keeps it correct.
	accessToTarget := rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, accessToTarget))

	// The other SSRC, the target's own audio.
	networkFromTarget := rtpPkt(testCallID, ssrcFromTarget, gwAddr, gwPort, coreAddr, corePort)
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, networkFromTarget))

	accessFromTarget := rtpPkt(testCallID, ssrcFromTarget, ueAddr, uePort, gwAddr, gwPort)
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, accessFromTarget))

	stats := r.Stats()
	assert.Equal(t, uint64(2), stats.ResolvedFromMedia, "one resolution per SSRC")
	assert.Equal(t, uint64(0), stats.UnknownRTP)
	assert.Equal(t, 1, stats.CallsTracked)
}

func TestMediaDirection_OutgoingCall(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()

	// Target places the call: its offer carries the gateway address.
	r.ObserveSIP(xid, msisdnTarget, inviteRequest(testCallID, targetURI, remoteURI, sdpBody(gwAddr, gwPort)))
	r.ObserveSIP(xid, msisdnTarget, inviteOK(testCallID, targetURI, remoteURI, sdpBody(coreAddr, corePort)))

	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcFromTarget, gwAddr, gwPort, coreAddr, corePort)))
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcFromTarget, ueAddr, uePort, gwAddr, gwPort)))

	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)))
}

func TestMediaDirection_AccessLegBeforeNetworkLeg(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()
	observeIncomingCall(r, xid, testCallID)

	// An access-side packet arriving before any network-side packet of the same
	// SSRC has no derivable direction — declining is correct, guessing is not.
	accessFirst := rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		r.PayloadDirection(xid, msisdnTarget, accessFirst))

	// Once the network-side leg is seen, the verdict applies to both legs.
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, accessFirst))

	assert.Equal(t, uint64(1), r.Stats().UnknownRTP)
}

func TestMediaDirection_NoEvidence(t *testing.T) {
	xid := uuid.New()

	t.Run("no signalling observed", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
		assert.Equal(t, 0, r.Stats().CallsTracked, "RTP alone must not create state")
	})

	t.Run("RTP without Call-ID", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		observeIncomingCall(r, xid, testCallID)
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt("", ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	})

	t.Run("signalling without SDP", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		r.ObserveSIP(xid, msisdnTarget, inviteRequest(testCallID, remoteURI, targetURI, ""))
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	})

	t.Run("target matches neither From nor To", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		other := TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15550000001"}
		r.ObserveSIP(xid, other, inviteRequest(testCallID, remoteURI, targetURI, sdpBody(coreAddr, corePort)))
		r.ObserveSIP(xid, other, inviteOK(testCallID, remoteURI, targetURI, sdpBody(gwAddr, gwPort)))
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, other, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	})

	t.Run("only one side advertised media", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		r.ObserveSIP(xid, msisdnTarget, inviteRequest(testCallID, remoteURI, targetURI, sdpBody(coreAddr, corePort)))
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	})
}

func TestMediaDirection_SSRCScopedPerCallAndTask(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()

	// Two concurrent calls that happen to reuse an SSRC, in opposite roles.
	const callB = "call-b@example.invalid"
	observeIncomingCall(r, xid, testCallID)
	// In call B the target is the caller, so the same SSRC flows the other way.
	r.ObserveSIP(xid, msisdnTarget, inviteRequest(callB, targetURI, remoteURI, sdpBody(gwAddr, "40800")))
	r.ObserveSIP(xid, msisdnTarget, inviteOK(callB, targetURI, remoteURI, sdpBody(coreAddr, "35500")))

	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(callB, ssrcToTarget, gwAddr, "40800", coreAddr, "35500")))

	// A second task intercepting the same call keeps its own state.
	otherXID := uuid.New()
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		r.PayloadDirection(otherXID, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)))
	assert.Equal(t, 2, r.Stats().CallsTracked)
}

func TestMediaDirection_SymmetricRTPPortRewrite(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()
	observeIncomingCall(r, xid, testCallID)

	// Media arrives from a different port than signalled (NAT / symmetric RTP).
	// Both addresses are still known, so the direction is still evidence-based.
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, "35999", gwAddr, "41999")))
}

func TestMediaDirection_ReInvite(t *testing.T) {
	xid := uuid.New()

	t.Run("known address, new port is attributed to its owner", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		observeIncomingCall(r, xid, testCallID)
		// Target side re-negotiates onto a new port on the same gateway.
		r.ObserveSIP(xid, msisdnTarget, reInvite(testCallID, remoteURI, targetURI, sdpBody(gwAddr, "40900")))
		assert.Equal(t, x2x3.PayloadDirectionToTarget,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, 0x11223344, coreAddr, corePort, gwAddr, "40900")))
	})

	t.Run("unknown address is not attributed", func(t *testing.T) {
		r := newTestResolver(t, MediaDirectionConfig{})
		observeIncomingCall(r, xid, testCallID)
		const thirdParty = "2001:db8:d::7"
		r.ObserveSIP(xid, msisdnTarget, reInvite(testCallID, remoteURI, targetURI, sdpBody(thirdParty, "40950")))
		// Neither party owns that address, so it must not become evidence.
		assert.Equal(t, x2x3.PayloadDirectionUnknown,
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, 0x55667788, coreAddr, corePort, thirdParty, "40950")))
	})
}

func TestMediaDirection_IPTargetsUnaffected(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()
	ipTarget := TargetIdentity{Type: TargetTypeIPv6Address, Value: ueAddr}

	pkt := rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)
	assert.Equal(t, PayloadDirectionForTarget(ipTarget, pkt), r.PayloadDirection(xid, ipTarget, pkt))
	assert.Equal(t, x2x3.PayloadDirectionToTarget, r.PayloadDirection(xid, ipTarget, pkt))

	// IP targets resolve per packet, so no media state is needed for them.
	r.ObserveSIP(xid, ipTarget, inviteRequest(testCallID, remoteURI, targetURI, sdpBody(coreAddr, corePort)))
	assert.Equal(t, 0, r.Stats().CallsTracked)
}

func TestMediaDirection_SIPPacketsUseIdentityMatching(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()

	// SIP packets keep resolving from their own From/To identity.
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, inviteRequest(testCallID, remoteURI, targetURI, "")))
	assert.Equal(t, x2x3.PayloadDirectionFromTarget,
		r.PayloadDirection(xid, msisdnTarget, inviteRequest(testCallID, targetURI, remoteURI, "")))
}

func TestMediaDirection_Eviction(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{TTL: time.Minute})
	xid := uuid.New()
	observeIncomingCall(r, xid, testCallID)
	require.Equal(t, 1, r.Stats().CallsTracked)

	assert.Equal(t, 0, r.sweep(time.Now()), "state in use must not be evicted")
	assert.Equal(t, 1, r.sweep(time.Now().Add(2*time.Minute)), "idle state must be evicted")
	assert.Equal(t, 0, r.Stats().CallsTracked)

	// After eviction the call's media is Unknown again rather than misattributed.
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
}

func TestMediaDirection_MaxCallsCap(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{MaxCalls: 1, TTL: time.Hour})
	xid := uuid.New()

	observeIncomingCall(r, xid, testCallID)
	observeIncomingCall(r, xid, "call-overflow@example.invalid")

	assert.Equal(t, 1, r.Stats().CallsTracked)
	assert.Positive(t, r.Stats().CallsDropped)
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt("call-overflow@example.invalid", ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	// The tracked call is unaffected.
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
}

func TestMediaDirection_NilResolver(t *testing.T) {
	var r *MediaDirectionResolver
	assert.Equal(t, x2x3.PayloadDirectionUnknown,
		r.PayloadDirection(uuid.New(), msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	r.ObserveSIP(uuid.New(), msisdnTarget, inviteRequest(testCallID, remoteURI, targetURI, ""))
	assert.Equal(t, MediaDirectionStats{}, r.Stats())
	r.Close()
}

func TestMediaDirection_ConcurrentAccess(t *testing.T) {
	r := newTestResolver(t, MediaDirectionConfig{})
	xid := uuid.New()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		callID := fmt.Sprintf("call-%d@example.invalid", i)
		wg.Add(3)
		go func() {
			defer wg.Done()
			observeIncomingCall(r, xid, callID)
		}()
		go func() {
			defer wg.Done()
			r.PayloadDirection(xid, msisdnTarget, rtpPkt(callID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort))
		}()
		go func() {
			defer wg.Done()
			r.sweep(time.Now())
		}()
	}
	wg.Wait()

	// Whatever the interleaving, replaying the signalling then the media must
	// still produce a direction.
	observeIncomingCall(r, xid, testCallID)
	assert.Equal(t, x2x3.PayloadDirectionToTarget,
		r.PayloadDirection(xid, msisdnTarget, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
}
