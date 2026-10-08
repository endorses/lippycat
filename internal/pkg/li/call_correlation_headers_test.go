//go:build li

package li

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func correlationHeaderTestPacket(start, fields string) *types.PacketDisplay {
	return &types.PacketDisplay{VoIPData: &types.VoIPMetadata{RawSIP: []byte(start + "\r\n" + fields + "\r\n\r\n")}}
}
func TestCorrelationSessionHeadersCustomAndRepeats(t *testing.T) {
	pkt := correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "X-Session:  AbC; foo=Mixed  \r\nx-session: AbC; foo=Mixed")
	keys, invalid := correlationSessionKeys(pkt, []string{"X-SESSION"})
	require.False(t, invalid)
	require.Equal(t, map[string]string{"x-session": "AbC; foo=Mixed"}, keys)
	pkt.VoIPData.Headers = map[string]string{"X-Session": "different"}
	keys, invalid = correlationSessionKeys(pkt, []string{"x-session"})
	require.False(t, invalid)
	require.Equal(t, "AbC; foo=Mixed", keys["x-session"])
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "X-Session: AbC\r\nx-session: abc")
	_, invalid = correlationSessionKeys(pkt, []string{"X-Session"})
	require.True(t, invalid)
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "X-Session:  \r\nOther: nope")
	keys, invalid = correlationSessionKeys(pkt, []string{"X-Session"})
	require.False(t, invalid)
	require.Empty(t, keys)
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "X-Session: AbC;\r\n foo=Mixed")
	keys, invalid = correlationSessionKeys(pkt, []string{"X-Session"})
	require.False(t, invalid)
	require.Equal(t, "AbC; foo=Mixed", keys["x-session"])
}
func TestCorrelationSessionIDInitiator(t *testing.T) {
	local := "1234567890abcdef1234567890ABCDEF"
	remote := "fedcba0987654321fedcba0987654321"
	tests := []struct {
		start, value, want string
		invalid            bool
	}{
		{"INVITE sip:test@example.invalid SIP/2.0", local, strings.ToLower(local), false},
		{"INVITE sip:test@example.invalid SIP/2.0", local + ";remote=" + remote, strings.ToLower(local), false},
		{"SIP/2.0 200 OK", local + ";remote=" + remote, remote, false},
		{"SIP/2.0 200 OK", local, "", false},
		{"SIP/2.0 200 OK", local + ";remote=" + strings.Repeat("0", 32), "", false},
		{"INVITE sip:test@example.invalid SIP/2.0", strings.Repeat("0", 32), "", false},
		{"INVITE sip:test@example.invalid SIP/2.0", "1234", "", false},
		{"SIP/2.0 200 OK", local + ";remote=broken", "", false},
		{"SIP/2.0 200 OK", local + ";remote=" + remote + ";remote=" + remote, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.value+tt.start[:6], func(t *testing.T) {
			pkt := correlationHeaderTestPacket(tt.start, "Session-ID: "+tt.value)
			keys, invalid := correlationSessionKeys(pkt, []string{"session-id"})
			require.Equal(t, tt.invalid, invalid)
			require.Equal(t, tt.want, keys["session-id"])
		})
	}
}
func TestCorrelationICID(t *testing.T) {
	tests := []struct {
		value, want string
		invalid     bool
	}{
		{"icid-value=AbC;icid-generated-at=192.0.2.1", "AbC", false},
		{`ICID-VALUE="A;b\"C";orig-ioi=example.invalid`, `A;b"C`, false},
		{"orig-ioi=example.invalid", "", false},
		{"icid-value=", "", false},
		{`icid-value="unclosed`, "", false},
		{"icid-value=a;icid-value=b", "", true},
		{"icid-value=a;icid-value=a", "a", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			pkt := correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "P-Charging-Vector: "+tt.value)
			keys, invalid := correlationSessionKeys(pkt, []string{"P-Charging-Vector"})
			require.Equal(t, tt.invalid, invalid)
			require.Equal(t, tt.want, keys["p-charging-vector"])
		})
	}
}
func TestCorrelationParentAgreement(t *testing.T) {
	tests := []struct {
		fields, want     string
		present, invalid bool
	}{
		{"Other: x", "", false, false},
		{"X-Parent: Call@Example.invalid", "Call@Example.invalid", true, false},
		{"X-Parent:  Call@Example.invalid \r\nx-parent: Call@Example.invalid\r\nX-Original: Call@Example.invalid", "Call@Example.invalid", true, false},
		{"X-Parent: Call@Example.invalid\r\nX-Original: call@Example.invalid", "", true, true},
		{"X-Parent: \r\nOther: x", "", true, true},
		{"X-Parent: parent;tag=x", "", true, true},
		{"X-Parent: parent,other", "", true, true},
		{"X-Parent: parent other", "", true, true},
		{"X-Parent: parent@@host", "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.fields, func(t *testing.T) {
			pkt := correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", tt.fields)
			got, present, invalid := correlationParent(pkt, []string{"X-Parent", "X-Original"})
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.present, present)
			require.Equal(t, tt.invalid, invalid)
		})
	}
}
func TestCorrelationHeaderBoundsAndFallback(t *testing.T) {
	pkt := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{Headers: map[string]string{"X-ID": "ABC", "x-id": "abc"}}}
	_, invalid := correlationSessionKeys(pkt, []string{"X-ID"})
	require.True(t, invalid)
	pkt.VoIPData.Headers = map[string]string{"Session-ID": "1234567890abcdef1234567890abcdef;remote=fedcba0987654321fedcba0987654321"}
	pkt.VoIPData.Status = 200
	keys, invalid := correlationSessionKeys(pkt, []string{"Session-ID"})
	require.False(t, invalid)
	require.Equal(t, "fedcba0987654321fedcba0987654321", keys["session-id"])
	pkt.VoIPData.RawSIP = []byte("INVITE sip:test@example.invalid SIP/2.0\r\nX-ID: a")
	_, invalid = correlationSessionKeys(pkt, []string{"X-ID"})
	require.True(t, invalid)
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "X-ID: "+strings.Repeat("a", correlationHeaderValueLimit+1))
	_, invalid = correlationSessionKeys(pkt, []string{"X-ID"})
	require.True(t, invalid)
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", strings.Repeat("Other: a\r\n", correlationHeaderCountLimit)+"X-ID: a")
	_, invalid = correlationSessionKeys(pkt, []string{"X-ID"})
	require.True(t, invalid)
	_, invalid = correlationSessionKeys(pkt, nil)
	require.False(t, invalid)
}

func TestCorrelationSessionIDGenericParameters(t *testing.T) {
	local := "1234567890abcdef1234567890abcdef"
	remote := "fedcba0987654321fedcba0987654321"
	for _, generic := range []string{`;flag`, `;mode=token`, `;host=example.invalid.`, `;host=[2001:db8::1]`, `;note="quoted;separator=ok"`, `;note="escaped\";and\\slash"`, `;empty=""`, ";note=\"café\""} {
		t.Run(generic, func(t *testing.T) {
			for _, response := range []bool{false, true} {
				start, want := "INVITE sip:test@example.invalid SIP/2.0", local
				if response {
					start, want = "SIP/2.0 200 OK", remote
				}
				pkt := correlationHeaderTestPacket(start, "Session-ID: "+local+generic+";remote="+remote)
				keys, conflict := correlationSessionKeys(pkt, []string{"Session-ID"})
				require.False(t, conflict)
				require.Equal(t, want, keys["session-id"])
			}
		})
	}
	for _, generic := range []string{`;bad=`, `;bad=two words`, `;bad="unterminated`, `;bad="embedded"quote"`, `;bad=[not:ipv6]`, `;bad@name=value`, `;`} {
		pkt := correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "Session-ID: "+local+generic)
		keys, conflict := correlationSessionKeys(pkt, []string{"Session-ID"})
		require.False(t, conflict, generic)
		require.Empty(t, keys, generic)
	}
}

func TestCorrelationSessionHeaderUnusableAndAmbiguous(t *testing.T) {
	const local = "1234567890abcdef1234567890abcdef"
	for _, fields := range []string{
		"Session-ID: " + local + ";remote=" + local + ";REMOTE=" + local,
		"Session-ID: " + local + ";remote=bad;remote=" + local,
		"Session-ID: bad\r\nSession-ID: bad",
		"Session-ID: " + local + "\r\nSession-ID: broken",
		"Session-ID: " + local + ";a=1\r\nSession-ID: " + local + ";a=2",
	} {
		_, conflict := correlationSessionKeys(correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", fields), []string{"session-id"})
		require.True(t, conflict, fields)
	}
	pkt := correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "Session-ID: broken\r\nX-Trusted: Exact;Case=Preserved")
	keys, conflict := correlationSessionKeys(pkt, []string{"session-id", "x-trusted"})
	require.False(t, conflict)
	require.Equal(t, map[string]string{"x-trusted": "Exact;Case=Preserved"}, keys)
	pkt = correlationHeaderTestPacket("INVITE sip:test@example.invalid SIP/2.0", "Session-ID: "+local+";flag\r\nSession-ID: "+local+";flag")
	keys, conflict = correlationSessionKeys(pkt, []string{"session-id"})
	require.False(t, conflict)
	require.Equal(t, local, keys["session-id"])
}

func TestCorrelationUnusableTrustedHeaderAllowsWeakFallback(t *testing.T) {
	for _, rule := range []string{"S", "R1", "R2"} {
		t.Run(rule, func(t *testing.T) {
			cfg := DefaultCallCorrelationConfig()
			cfg.SessionHeaders = []string{"Session-ID", "P-Charging-Vector"}
			cfg.SDPOriginMatching = rule == "S"
			cfg.AddressChaining = rule == "R1"
			cfg.NumberChaining = rule == "R2"
			c, now := newContractCorrelator(t, cfg, nil)
			a := contractInvite("header-root", 0, *now)
			b := contractInvite("header-child", 1, now.Add(time.Millisecond))
			if rule == "R2" {
				a.SrcIP, a.DstIP, b.SrcIP, b.DstIP = "", "", "", ""
			}
			if rule == "S" {
				contractSDP(a, "551")
				contractSDP(b, "551")
			}
			root := contractResolve(c, a)
			contractHeader(b, "Session-ID", "malformed")
			contractHeader(b, "P-Charging-Vector", "icid-value=")
			child := contractResolve(c, b)
			require.Equal(t, root.CorrelationID, child.CorrelationID)
			require.Equal(t, rule, child.Rule)
		})
	}
}
