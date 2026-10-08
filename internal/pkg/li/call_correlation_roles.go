//go:build li

package li

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// correlationSDPBody reads exactly the SIP parser's framed body. Explicit
// non-SDP content never supplies origin evidence. Legacy producers may omit
// Content-Type alongside Body; raw signaling must explicitly identify SDP.
func correlationSDPBody(pkt *types.PacketDisplay) (string, bool) {
	if pkt == nil || pkt.VoIPData == nil {
		return "", false
	}
	metadata := pkt.VoIPData
	if len(metadata.RawSIP) > 0 {
		raw := metadata.RawSIP
		if len(raw) > sip.MaxMessageSize || (!bytes.Contains(raw, []byte("\r\n\r\n")) && !bytes.Contains(raw, []byte("\n\n"))) {
			return "", false
		}
		headers, invalid := correlationHeaders(pkt)
		if invalid {
			return "", false
		}
		values := append(append([]string(nil), headers["content-type"]...), headers["c"]...)
		contentType, present, conflict := oneCorrelationHeader(values)
		if conflict || !present || !correlationIsSDPType(contentType) {
			return "", false
		}
		parsed, err := sip.Parse(raw, sip.ParseOptions{})
		if err != nil {
			return "", false
		}
		body := string(parsed.Body)
		// With no Content-Length, a packet is still a valid datagram boundary. It
		// must start as SDP, never as a pipelined subsequent SIP message.
		if !strings.HasPrefix(body, "v=0\r\n") && !strings.HasPrefix(body, "v=0\n") {
			return "", false
		}
		for _, line := range strings.Split(body, "\n") {
			if sip.IsStartLine(strings.TrimSuffix(line, "\r")) {
				return "", false
			}
		}
		return body, body != ""
	}
	contentType := metadata.ContentType
	if contentType == "" {
		for name, value := range metadata.Headers {
			if strings.EqualFold(name, "content-type") || strings.EqualFold(name, "c") {
				if contentType != "" && contentType != value {
					return "", false
				}
				contentType = value
			}
		}
	}
	if contentType != "" && !correlationIsSDPType(contentType) {
		return "", false
	}
	if len(metadata.Body) == 0 || len(metadata.Body) > correlationSDPMaxBody {
		return "", false
	}
	return metadata.Body, true
}
func correlationIsSDPType(value string) bool {
	mediaType, _, _ := strings.Cut(value, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/sdp")
}

// observeRoleOrigin gathers independent reuse evidence even when this
// transaction cannot add a matching index. A candidate owns at most one
// retained index entry for each established role.
func (c *CallCorrelator) observeRoleOrigin(v *correlationCandidate, origin sdpOrigin, role sdpOriginRole, now time.Time) {
	if !c.history.Observe(origin, role, v.transaction, v.started, now, v.headers) {
		c.stats.SDP["unusable"]++
	}
	if c.candidates[v.transaction] != v || role == sdpOriginUnknown {
		return
	}
	key := sdpOriginHistoryKey{Origin: origin, Role: role}
	for _, old := range v.originKeys {
		if old.Role == role {
			return
		}
	}
	if c.originIndex[key] == nil {
		c.originIndex[key] = map[string]*correlationCandidate{}
	}
	c.originIndex[key][v.transaction] = v
	v.originKeys = append(v.originKeys, key)
}

// delayedAnswerTransaction allows ACK's new branch only with one retained,
// observed initial request carrying a delayed offer. Unknown or fork-ambiguous
// associations cannot supply S evidence. This never changes a leg's decision.
func (c *CallCorrelator) delayedAnswerTransaction(pkt *types.PacketDisplay) (string, correlationTransaction, bool) {
	if pkt == nil || pkt.VoIPData == nil {
		return "", correlationTransaction{}, false
	}
	v := pkt.VoIPData
	if v.Status != 0 || v.Method != "ACK" || v.CallID == "" || v.FromTag == "" {
		return "", correlationTransaction{}, false
	}
	number, method, valid := correlationCSeq(pkt)
	if !valid || method != "ACK" {
		return "", correlationTransaction{}, false
	}
	prefix := v.CallID + "\x00" + v.FromTag + "\x00"
	suffix := fmt.Sprintf("\x00%d", number)
	found := ""
	var result correlationTransaction
	for key, t := range c.transactions {
		if !t.requestSeen || !t.delayedOffer || t.candidate == nil || !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
			continue
		}
		if found != "" {
			return "", correlationTransaction{}, false
		}
		found = key
		result = t
	}
	return found, result, found != ""
}
