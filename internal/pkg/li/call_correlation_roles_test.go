//go:build li

package li

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func roleSDPBody(id string) string {
	return "v=0\r\no=- " + id + " 1 IN IP4 198.51.100.1\r\ns=call\r\nt=0 0\r\n"
}
func roleRawPacket(contentType, body string, length int) *types.PacketDisplay {
	raw := fmt.Sprintf("INVITE sip:test@example.invalid SIP/2.0\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, length, body)
	return &types.PacketDisplay{VoIPData: &types.VoIPMetadata{RawSIP: []byte(raw)}}
}
func TestCorrelationSDPBodyFramingAndType(t *testing.T) {
	body := roleSDPBody("111")
	pkt := roleRawPacket("application/sdp", body, len(body))
	got, ok := correlationSDPBody(pkt)
	require.True(t, ok)
	require.Equal(t, body, got)
	pkt.VoIPData.RawSIP = append(pkt.VoIPData.RawSIP, []byte("INVITE sip:next@example.invalid SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n"+roleSDPBody("222"))...)
	got, ok = correlationSDPBody(pkt)
	require.True(t, ok)
	require.Equal(t, body, got)
	pkt = roleRawPacket("Application/SDP; charset=utf-8", strings.ReplaceAll(body, "\r\n", "\n"), len(strings.ReplaceAll(body, "\r\n", "\n")))
	pkt.VoIPData.RawSIP = []byte(strings.ReplaceAll(string(pkt.VoIPData.RawSIP), "\r\n", "\n"))
	_, ok = correlationSDPBody(pkt)
	require.True(t, ok)
	for _, test := range []struct {
		contentType, body string
		length            int
	}{
		{"text/plain", body, len(body)}, {"", body, len(body)}, {"application/sdp", body, len(body) + 1}, {"application/sdp", body, 0},
		{"application/sdp", "INVITE sip:next@example.invalid SIP/2.0\r\n\r\n" + body, len(body) + 49},
	} {
		_, ok = correlationSDPBody(roleRawPacket(test.contentType, test.body, test.length))
		require.False(t, ok)
	}
	pkt = roleRawPacket("application/sdp", body, len(body))
	pkt.VoIPData.RawSIP = []byte(strings.Replace(string(pkt.VoIPData.RawSIP), "Content-Length:", "Content-Type: text/plain\r\nContent-Length:", 1))
	_, ok = correlationSDPBody(pkt)
	require.False(t, ok)
	pkt = roleRawPacket("application/sdp", "", 0)
	pkt.VoIPData.RawSIP = append(pkt.VoIPData.RawSIP, []byte("INVITE sip:next@example.invalid SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n"+body)...)
	_, ok = correlationSDPBody(pkt)
	require.False(t, ok)
	legacy := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{Body: body}}
	_, ok = correlationSDPBody(legacy)
	require.True(t, ok)
	legacy.VoIPData.ContentType = "text/plain"
	_, ok = correlationSDPBody(legacy)
	require.False(t, ok)
	legacy.VoIPData.RawSIP = []byte("bad")
	legacy.VoIPData.ContentType = "application/sdp"
	_, ok = correlationSDPBody(legacy)
	require.False(t, ok, "raw cannot fall back to legacy body")
}
func roleResponse(p *types.PacketDisplay, body string) *types.PacketDisplay {
	clone := *p
	metadata := *p.VoIPData
	clone.VoIPData = &metadata
	metadata.Status = 200
	metadata.Method = "RESPONSE"
	metadata.CSeqMethod = "INVITE"
	metadata.Body = body
	metadata.ToTag = "to"
	return &clone
}
func roleACK(p *types.PacketDisplay, body string) *types.PacketDisplay {
	clone := *p
	metadata := *p.VoIPData
	clone.VoIPData = &metadata
	metadata.Status = 0
	metadata.Method = "ACK"
	metadata.CSeqMethod = "ACK"
	metadata.ViaBranch = "z9hG4bK-ack-new"
	metadata.Body = body
	metadata.ToTag = "to"
	return &clone
}
func TestCorrelationSDPInitialRetransmissionLearnsOffer(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	c, now := newContractCorrelator(t, cfg, nil)
	initial := contractInvite("a", 0, *now)
	first := c.Resolve(initial, []CallCorrelationTask{correlationTaskX})
	initial.VoIPData.Body = roleSDPBody("111")
	require.Equal(t, first, c.Resolve(initial, []CallCorrelationTask{correlationTaskX}))
	tx, _ := correlationTx(initial)
	require.True(t, c.transactions[tx].offer)
	candidate := c.transactions[tx].candidate
	require.Len(t, candidate.originKeys, 1)
	require.Equal(t, sdpOriginOffer, candidate.originKeys[0].Role)
	c.Resolve(roleResponse(initial, roleSDPBody("222")), []CallCorrelationTask{correlationTaskX})
	require.Len(t, candidate.originKeys, 2)
	require.Equal(t, sdpOriginAnswer, candidate.originKeys[1].Role)
	// Retransmission and later different origin cannot leak per-role indexes.
	c.Resolve(roleResponse(initial, roleSDPBody("333")), []CallCorrelationTask{correlationTaskX})
	require.Len(t, candidate.originKeys, 2)
}
func TestCorrelationSDPDelayedOfferACKAndUnknownRole(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	c, now := newContractCorrelator(t, cfg, nil)
	initial := contractInvite("a", 0, *now)
	first := c.Resolve(initial, []CallCorrelationTask{correlationTaskX})
	tx, _ := correlationTx(initial)
	response := roleResponse(initial, roleSDPBody("111"))
	require.Equal(t, first, c.Resolve(response, []CallCorrelationTask{correlationTaskX}))
	require.True(t, c.transactions[tx].delayedOffer)
	require.False(t, c.transactions[tx].offer)
	candidate := c.transactions[tx].candidate
	require.Len(t, candidate.originKeys, 1)
	require.Equal(t, sdpOriginOffer, candidate.originKeys[0].Role)
	ack := roleACK(initial, roleSDPBody("222"))
	require.Equal(t, first, c.Resolve(ack, []CallCorrelationTask{correlationTaskX}))
	require.Len(t, candidate.originKeys, 2)
	require.Equal(t, sdpOriginAnswer, candidate.originKeys[1].Role)
	entry := c.history.entries[candidate.originKeys[1]]
	last := entry.lastSeen
	*now = now.Add(time.Second)
	c.Resolve(ack, []CallCorrelationTask{correlationTaskX})
	require.Equal(t, last, entry.lastSeen)
	unknown := roleResponse(contractInvite("unknown", 0, *now), roleSDPBody("333"))
	c.Resolve(unknown, []CallCorrelationTask{correlationTaskX})
	unknownTx, _ := correlationTx(unknown)
	require.False(t, c.transactions[unknownTx].requestSeen)
	c.Resolve(unknown, []CallCorrelationTask{correlationTaskX})
	require.Empty(t, c.transactions[unknownTx].candidate.originKeys)
}
func TestCorrelationSDPACKAmbiguityAndExpiredCandidate(t *testing.T) {
	cfg := DefaultCallCorrelationConfig()
	cfg.SDPOriginMatching = true
	c, now := newContractCorrelator(t, cfg, nil)
	initial := contractInvite("a", 0, *now)
	c.Resolve(initial, []CallCorrelationTask{correlationTaskX})
	tx, _ := correlationTx(initial)
	c.Resolve(roleResponse(initial, roleSDPBody("111")), []CallCorrelationTask{correlationTaskX})
	tcopy := c.transactions[tx]
	ambiguousTx := strings.Replace(tx, initial.VoIPData.ViaBranch, "other-branch", 1)
	c.transactions[ambiguousTx] = tcopy
	ack := roleACK(initial, roleSDPBody("222"))
	c.Resolve(ack, []CallCorrelationTask{correlationTaskX})
	require.Len(t, tcopy.candidate.originKeys, 1)
	delete(c.transactions, ambiguousTx)
	c.removeCandidate(tcopy.candidate)
	c.Resolve(ack, []CallCorrelationTask{correlationTaskX})
	require.Empty(t, c.originIndex, "retained transaction cannot resurrect an expired candidate index")
}
