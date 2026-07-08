//go:build li

package li

import (
	"net/netip"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// PayloadDirectionForTarget determines the ETSI TS 103 221-2 Payload Direction of
// a captured packet relative to a single intercept target.
//
// Lawful interception product must never carry a guessed direction, so this
// returns x2x3.PayloadDirectionUnknown whenever the direction cannot be
// established unambiguously — the target identity present on both sides, on
// neither side, or not determinable from the available packet metadata (for
// example an RTP packet targeted by SIP URI, which carries no SIP identity).
func PayloadDirectionForTarget(target TargetIdentity, pkt *types.PacketDisplay) x2x3.PayloadDirection {
	if pkt == nil {
		return x2x3.PayloadDirectionUnknown
	}

	switch target.Type {
	case TargetTypeIPv4Address, TargetTypeIPv6Address, TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		return ipDirection(target, pkt)
	case TargetTypeSIPURI, TargetTypeNAI, TargetTypeUsername, TargetTypeTELURI:
		return sipIdentityDirection(target, pkt)
	default:
		// IMSI/IMEI and any future types: no per-packet direction available here.
		return x2x3.PayloadDirectionUnknown
	}
}

// ipDirection resolves direction for IP-address / CIDR targets by matching the
// packet's source and destination addresses against the target.
func ipDirection(target TargetIdentity, pkt *types.PacketDisplay) x2x3.PayloadDirection {
	srcHit := ipMatchesTarget(pkt.SrcIP, target)
	dstHit := ipMatchesTarget(pkt.DstIP, target)
	switch {
	case srcHit && !dstHit:
		return x2x3.PayloadDirectionFromTarget
	case dstHit && !srcHit:
		return x2x3.PayloadDirectionToTarget
	default:
		return x2x3.PayloadDirectionUnknown
	}
}

// ipMatchesTarget reports whether an IP string belongs to the target (exact
// address for *Address targets, prefix containment for *CIDR targets).
func ipMatchesTarget(ipStr string, target TargetIdentity) bool {
	if ipStr == "" {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	switch target.Type {
	case TargetTypeIPv4Address, TargetTypeIPv6Address:
		t, err := netip.ParseAddr(strings.TrimSpace(target.Value))
		return err == nil && t == addr
	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		p, err := netip.ParsePrefix(strings.TrimSpace(target.Value))
		return err == nil && p.Contains(addr)
	}
	return false
}

// sipIdentityDirection resolves direction for SIP-identity targets (SIP URI,
// NAI, username, tel URI) by matching the target against the packet's SIP From
// and To identities. Requires SIP metadata; RTP packets have none, so they
// resolve to Unknown.
func sipIdentityDirection(target TargetIdentity, pkt *types.PacketDisplay) x2x3.PayloadDirection {
	voip := pkt.VoIPData
	if voip == nil || (voip.From == "" && voip.To == "") {
		return x2x3.PayloadDirectionUnknown
	}
	fromHit := sipIdentityMatches(target, voip.From)
	toHit := sipIdentityMatches(target, voip.To)
	switch {
	case fromHit && !toHit:
		return x2x3.PayloadDirectionFromTarget
	case toHit && !fromHit:
		return x2x3.PayloadDirectionToTarget
	default:
		return x2x3.PayloadDirectionUnknown
	}
}

// sipIdentityMatches reports whether the target identity equals the identity in
// a SIP From/To header. Comparison is exact (after normalization) to avoid
// mislabelling — e.g. a "555" target must not match "5551234".
func sipIdentityMatches(target TargetIdentity, header string) bool {
	uri := extractHeaderURI(header)
	if uri == "" {
		return false
	}
	switch target.Type {
	case TargetTypeSIPURI:
		return strings.EqualFold(uri, extractSIPURIPattern(target.Value))
	case TargetTypeNAI:
		return strings.EqualFold(uri, strings.TrimSpace(target.Value))
	case TargetTypeUsername:
		return strings.EqualFold(uriUserPart(uri), strings.TrimSpace(target.Value))
	case TargetTypeTELURI:
		tgt := extractPhonePattern(target.Value)
		return tgt != "" && onlyDigits(uriUserPart(uri)) == tgt
	}
	return false
}

// extractHeaderURI extracts the bare user@host identity from a SIP From/To
// header value, handling an optional display name and angle brackets, the
// sip:/sips:/tel: scheme, URI parameters, and a host port.
func extractHeaderURI(header string) string {
	h := strings.TrimSpace(header)
	if h == "" {
		return ""
	}

	// Prefer the addr-spec inside angle brackets when a display name is present.
	if i := strings.Index(h, "<"); i != -1 {
		if j := strings.Index(h[i:], ">"); j != -1 {
			h = h[i+1 : i+j]
		}
	}

	// Strip the URI scheme.
	lower := strings.ToLower(h)
	switch {
	case strings.HasPrefix(lower, "sips:"):
		h = h[5:]
	case strings.HasPrefix(lower, "sip:"):
		h = h[4:]
	case strings.HasPrefix(lower, "tel:"):
		h = h[4:]
	}

	// Strip URI/header parameters.
	if i := strings.IndexAny(h, ";?"); i != -1 {
		h = h[:i]
	}

	// Strip a host port (host:port), but not an IPv6 host which has >1 colon.
	if at := strings.Index(h, "@"); at != -1 {
		host := h[at+1:]
		if c := strings.LastIndex(host, ":"); c != -1 && strings.Count(host, ":") == 1 {
			h = h[:at+1] + host[:c]
		}
	}

	return strings.TrimSpace(h)
}

// uriUserPart returns the user portion (before '@') of a user@host identity.
func uriUserPart(uri string) string {
	if at := strings.Index(uri, "@"); at != -1 {
		return uri[:at]
	}
	return uri
}

// onlyDigits returns the ASCII digits of s (matching extractPhonePattern's form).
func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
