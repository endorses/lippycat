//go:build li

package li

import (
	"fmt"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func cseqWirePacket(p *types.PacketDisplay, cseqHeaders []string, body string) *types.PacketDisplay {
	first := p.VoIPData.Method + " sip:b@example.test SIP/2.0"
	if p.VoIPData.Status > 0 {
		first = fmt.Sprintf("SIP/2.0 %d Response", p.VoIPData.Status)
	}
	raw := first + "\r\nCall-ID: " + p.VoIPData.CallID + "\r\nFrom: " + p.VoIPData.From + "\r\nTo: " + p.VoIPData.To + "\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=" + p.VoIPData.ViaBranch + "\r\n"
	for _, value := range cseqHeaders {
		raw += "CSeq: " + value + "\r\n"
	}
	raw += "X-Session: shared-session\r\n"
	if body != "" {
		raw += "Content-Type: application/sdp\r\n"
	}
	raw += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	p.VoIPData.RawSIP = []byte(raw)
	return p
}

func TestCallCorrelationCSeqZeroInitialAndResponse(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprintf("response-%t", response), func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			c, now := newContractCorrelator(t, cfg, nil)
			anchor := contractResolve(c, cseqWirePacket(contractInvite("anchor", 0, *now), []string{"1 INVITE"}, ""))
			zero := contractInvite("zero", 4, *now)
			zero.VoIPData.CSeqNumber = 0
			if response {
				zero.VoIPData.Method = "RESPONSE"
				zero.VoIPData.Status = 180
				zero.VoIPData.CSeqMethod = "INVITE"
				zero.VoIPData.ToTag = "early"
			}
			cseqWirePacket(zero, []string{"0 INVITE"}, "")
			tx, eligible := correlationTx(zero)
			require.True(t, eligible, "explicit zero is a valid SIP transaction sequence")
			require.NotEmpty(t, tx)
			d := contractResolve(c, zero)
			require.Equal(t, anchor.CorrelationID, d.CorrelationID)
			require.Equal(t, "H", d.Rule)
		})
	}
}

func TestCallCorrelationCSeqZeroMetadataHeaderPresence(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	c, now := newContractCorrelator(t, cfg, nil)
	anchor := contractResolve(c, contractInvite("anchor", 0, *now))
	p := contractInvite("zero-header", 1, *now)
	p.VoIPData.CSeqNumber = 0
	p.VoIPData.Headers = map[string]string{"cSeQ": "0 INVITE"}
	d := contractResolve(c, p)
	require.Equal(t, anchor.CorrelationID, d.CorrelationID)
	require.Equal(t, "R1", d.Rule)
	absent := contractInvite("zero-absent", 1, *now)
	absent.VoIPData.CSeqNumber = 0
	d = contractResolve(c, absent)
	require.NotEqual(t, anchor.CorrelationID, d.CorrelationID)
	require.Equal(t, "not_eligible", d.Reason)
}

func TestCallCorrelationCSeqMalformedOrMissingCannotAdopt(t *testing.T) {
	for name, headers := range map[string][]string{
		"missing": nil, "negative": {"-1 INVITE"}, "nonnumeric": {"word INVITE"}, "missing method": {"0"}, "request method mismatch": {"0 BYE"}, "31bit overflow": {"2147483648 INVITE"}, "64bit overflow": {"18446744073709551616 INVITE"}, "conflicting duplicate": {"0 INVITE", "1 INVITE"}, "conflicting method duplicate": {"0 INVITE", "0 BYE"}, "extra fields": {"0 INVITE unexpected"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"X-Session"}
			c, now := newContractCorrelator(t, cfg, nil)
			anchor := contractResolve(c, cseqWirePacket(contractInvite("anchor", 0, *now), []string{"1 INVITE"}, ""))
			malformed := contractInvite("malformed", 4, *now)
			malformed.VoIPData.CSeqNumber = 0
			cseqWirePacket(malformed, headers, "")
			_, eligible := correlationTx(malformed)
			require.False(t, eligible)
			d := contractResolve(c, malformed)
			require.NotEqual(t, anchor.CorrelationID, d.CorrelationID)
			require.Empty(t, d.Rule)
		})
	}
	// The largest valid 31-bit value is permitted; conflicting metadata cannot
	// repair malformed authoritative raw CSeq fields.
	_, now := newContractCorrelator(t, DefaultCallCorrelationConfig(), nil)
	max := contractInvite("max", 0, *now)
	max.VoIPData.CSeqNumber = 2147483647
	cseqWirePacket(max, []string{"2147483647 INVITE"}, "")
	_, eligible := correlationTx(max)
	require.True(t, eligible)
	bad := contractInvite("metadata-repair", 0, *now)
	cseqWirePacket(bad, []string{"bad INVITE"}, "")
	_, eligible = correlationTx(bad)
	require.False(t, eligible)
}

func TestCallCorrelationCSeqZeroDelayedOfferACK(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	c, now := newContractCorrelator(t, cfg, nil)
	initial := contractInvite("zero-delayed", 0, *now)
	initial.VoIPData.CSeqNumber = 0
	cseqWirePacket(initial, []string{"0 INVITE"}, "")
	first := c.Resolve(initial, []CallCorrelationTask{correlationTaskX})
	tx, eligible := correlationTx(initial)
	require.True(t, eligible)
	response := roleResponse(initial, roleSDPBody("111"))
	cseqWirePacket(response, []string{"0 INVITE"}, roleSDPBody("111"))
	require.Equal(t, first, c.Resolve(response, []CallCorrelationTask{correlationTaskX}))
	require.True(t, c.transactions[tx].delayedOffer)
	candidate := c.transactions[tx].candidate
	require.Len(t, candidate.originKeys, 1)
	ack := roleACK(initial, roleSDPBody("222"))
	cseqWirePacket(ack, []string{"0 ACK"}, roleSDPBody("222"))
	require.True(t, strings.Contains(string(ack.VoIPData.RawSIP), "CSeq: 0 ACK\r\n"))
	require.Equal(t, first, c.Resolve(ack, []CallCorrelationTask{correlationTaskX}))
	require.Len(t, candidate.originKeys, 2)
	require.Equal(t, sdpOriginAnswer, candidate.originKeys[1].Role)
}
