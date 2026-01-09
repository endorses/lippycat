//go:build processor || tap || all

package processor

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
)

// BPF filter patterns for parsing expressions
var (
	portPattern = regexp.MustCompile(`^(?:(src|dst)\s+)?port\s+(\d+)$`)
	hostPattern = regexp.MustCompile(`^(?:(src|dst)\s+)?host\s+([\d\.]+)$`)
	netPattern  = regexp.MustCompile(`^(?:(src|dst)\s+)?net\s+([\d\.\/]+)$`)
)

// BPFFilter represents a compiled BPF filter for server-side packet filtering.
// This is a simplified BPF implementation that operates on packet metadata
// rather than raw packet bytes, suitable for post-capture filtering.
type BPFFilter struct {
	expression string
	matchType  string     // "protocol", "port", "host", "net", "and", "or"
	direction  string     // "src", "dst", "" (both)
	value      string     // port number, IP, or network
	ipnet      *net.IPNet // parsed CIDR for network filters

	// For compound filters (and/or)
	left  *BPFFilter
	right *BPFFilter
}

// NewBPFFilter creates a new BPF filter from an expression.
// Returns nil if the expression is empty (no filtering).
func NewBPFFilter(expression string) (*BPFFilter, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil, nil
	}
	return parseBPFExpression(expression)
}

// parseBPFExpression parses a BPF expression into a filter.
func parseBPFExpression(expr string) (*BPFFilter, error) {
	expr = strings.TrimSpace(expr)
	lowerExpr := strings.ToLower(expr)

	// Handle "and" compound expressions
	if idx := findOperatorIndex(lowerExpr, " and "); idx != -1 {
		left, err := parseBPFExpression(expr[:idx])
		if err != nil {
			return nil, err
		}
		right, err := parseBPFExpression(expr[idx+5:])
		if err != nil {
			return nil, err
		}
		return &BPFFilter{
			expression: expr,
			matchType:  "and",
			left:       left,
			right:      right,
		}, nil
	}

	// Handle "or" compound expressions
	if idx := findOperatorIndex(lowerExpr, " or "); idx != -1 {
		left, err := parseBPFExpression(expr[:idx])
		if err != nil {
			return nil, err
		}
		right, err := parseBPFExpression(expr[idx+4:])
		if err != nil {
			return nil, err
		}
		return &BPFFilter{
			expression: expr,
			matchType:  "or",
			left:       left,
			right:      right,
		}, nil
	}

	// Protocol filters
	switch lowerExpr {
	case "tcp", "udp", "icmp":
		return &BPFFilter{
			expression: expr,
			matchType:  "protocol",
			value:      strings.ToUpper(lowerExpr),
		}, nil
	}

	// Port filters
	if matches := portPattern.FindStringSubmatch(lowerExpr); len(matches) > 0 {
		return &BPFFilter{
			expression: expr,
			matchType:  "port",
			direction:  matches[1],
			value:      matches[2],
		}, nil
	}

	// Host filters
	if matches := hostPattern.FindStringSubmatch(lowerExpr); len(matches) > 0 {
		return &BPFFilter{
			expression: expr,
			matchType:  "host",
			direction:  matches[1],
			value:      matches[2],
		}, nil
	}

	// Network filters
	if matches := netPattern.FindStringSubmatch(lowerExpr); len(matches) > 0 {
		f := &BPFFilter{
			expression: expr,
			matchType:  "net",
			direction:  matches[1],
			value:      matches[2],
		}
		// Pre-parse CIDR if applicable
		if strings.Contains(f.value, "/") {
			_, ipnet, err := net.ParseCIDR(f.value)
			if err == nil {
				f.ipnet = ipnet
			}
		}
		return f, nil
	}

	return nil, fmt.Errorf("unsupported BPF expression: %s", expr)
}

// findOperatorIndex finds the index of an operator, respecting parentheses.
func findOperatorIndex(expr, op string) int {
	depth := 0
	for i := 0; i <= len(expr)-len(op); i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && strings.HasPrefix(expr[i:], op) {
			return i
		}
	}
	return -1
}

// Match checks if a packet matches the BPF filter.
func (f *BPFFilter) Match(pkt *data.CapturedPacket) bool {
	if f == nil {
		return true // nil filter matches everything
	}

	meta := pkt.GetMetadata()
	if meta == nil {
		// No metadata - can't filter, allow through
		return true
	}

	switch f.matchType {
	case "and":
		return f.left.Match(pkt) && f.right.Match(pkt)

	case "or":
		return f.left.Match(pkt) || f.right.Match(pkt)

	case "protocol":
		return strings.EqualFold(meta.Transport, f.value)

	case "port":
		switch f.direction {
		case "src":
			return strconv.FormatUint(uint64(meta.SrcPort), 10) == f.value
		case "dst":
			return strconv.FormatUint(uint64(meta.DstPort), 10) == f.value
		default:
			srcPort := strconv.FormatUint(uint64(meta.SrcPort), 10)
			dstPort := strconv.FormatUint(uint64(meta.DstPort), 10)
			return srcPort == f.value || dstPort == f.value
		}

	case "host":
		switch f.direction {
		case "src":
			return meta.SrcIp == f.value
		case "dst":
			return meta.DstIp == f.value
		default:
			return meta.SrcIp == f.value || meta.DstIp == f.value
		}

	case "net":
		if f.ipnet != nil {
			switch f.direction {
			case "src":
				return ipInCIDR(meta.SrcIp, f.ipnet)
			case "dst":
				return ipInCIDR(meta.DstIp, f.ipnet)
			default:
				return ipInCIDR(meta.SrcIp, f.ipnet) || ipInCIDR(meta.DstIp, f.ipnet)
			}
		}
		// Fallback to substring match
		switch f.direction {
		case "src":
			return strings.Contains(meta.SrcIp, f.value)
		case "dst":
			return strings.Contains(meta.DstIp, f.value)
		default:
			return strings.Contains(meta.SrcIp, f.value) || strings.Contains(meta.DstIp, f.value)
		}
	}

	// Unknown filter type - allow through
	return true
}

// FilterBatch filters a packet batch, returning only matching packets.
// Returns a new batch with only matching packets, or nil if all packets are filtered out.
func (f *BPFFilter) FilterBatch(batch *data.PacketBatch) *data.PacketBatch {
	if f == nil || batch == nil {
		return batch
	}

	filtered := make([]*data.CapturedPacket, 0, len(batch.Packets))
	for _, pkt := range batch.Packets {
		if f.Match(pkt) {
			filtered = append(filtered, pkt)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	// Return new batch with filtered packets
	return &data.PacketBatch{
		HunterId:    batch.HunterId,
		Sequence:    batch.Sequence,
		TimestampNs: batch.TimestampNs,
		Packets:     filtered,
		Stats:       batch.Stats,
	}
}

// Expression returns the original BPF expression.
func (f *BPFFilter) Expression() string {
	if f == nil {
		return ""
	}
	return f.expression
}

// ipInCIDR checks if an IP is in a CIDR range.
func ipInCIDR(ip string, ipnet *net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return ipnet.Contains(parsedIP)
}
