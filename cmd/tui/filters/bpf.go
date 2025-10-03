package filters

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/endorses/lippycat/cmd/tui/components"
)

var (
	// Regex patterns for common BPF expressions
	portRegex = regexp.MustCompile(`^(?:(src|dst)\s+)?port\s+(\d+)$`)
	hostRegex = regexp.MustCompile(`^(?:(src|dst)\s+)?host\s+([\d\.]+)$`)
	netRegex  = regexp.MustCompile(`^(?:(src|dst)\s+)?net\s+([\d\.\/]+)$`)
)

// BPFFilter filters based on BPF (Berkeley Packet Filter) syntax
type BPFFilter struct {
	expression string

	// Pre-parsed fields for fast matching
	matchType  string // "protocol", "port", "host", "net", "unknown"
	protocol   string // for protocol filters
	direction  string // "src", "dst", "" (both)
	value      string // port number, IP, or network
	ipnet      *net.IPNet // parsed CIDR for network filters
}

// NewBPFFilter creates a new BPF filter
// Note: For TUI post-capture filtering, we do simple field matching
// Real BPF compilation would be used at capture time
func NewBPFFilter(expression string) (*BPFFilter, error) {
	// Validate it looks like a BPF expression
	if expression == "" {
		return nil, fmt.Errorf("empty BPF expression")
	}

	f := &BPFFilter{
		expression: expression,
		matchType:  "unknown",
	}

	// Pre-parse the expression for faster matching
	expr := strings.ToLower(expression)

	// Protocol filters
	if expr == "tcp" || expr == "udp" || expr == "icmp" {
		f.matchType = "protocol"
		f.protocol = strings.ToUpper(expr)
		return f, nil
	}

	// Port filters
	if matches := portRegex.FindStringSubmatch(expression); len(matches) > 0 {
		f.matchType = "port"
		f.direction = matches[1]
		f.value = matches[2]
		return f, nil
	}

	// Host filters
	if matches := hostRegex.FindStringSubmatch(expression); len(matches) > 0 {
		f.matchType = "host"
		f.direction = matches[1]
		f.value = matches[2]
		return f, nil
	}

	// Net filters
	if matches := netRegex.FindStringSubmatch(expression); len(matches) > 0 {
		f.matchType = "net"
		f.direction = matches[1]
		f.value = matches[2]

		// Pre-parse CIDR if applicable
		if strings.Contains(f.value, "/") {
			_, ipnet, err := net.ParseCIDR(f.value)
			if err == nil {
				f.ipnet = ipnet
			}
		}
		return f, nil
	}

	return f, nil
}

// Match checks if the packet matches the BPF filter
// Optimized: uses pre-parsed fields to avoid regex matching on every packet
func (f *BPFFilter) Match(packet components.PacketDisplay) bool {
	// Use pre-parsed matchType for fast dispatch
	switch f.matchType {
	case "protocol":
		return packet.Protocol == f.protocol

	case "port":
		switch f.direction {
		case "src":
			return packet.SrcPort == f.value
		case "dst":
			return packet.DstPort == f.value
		default:
			return packet.SrcPort == f.value || packet.DstPort == f.value
		}

	case "host":
		switch f.direction {
		case "src":
			return strings.Contains(packet.SrcIP, f.value)
		case "dst":
			return strings.Contains(packet.DstIP, f.value)
		default:
			return strings.Contains(packet.SrcIP, f.value) || strings.Contains(packet.DstIP, f.value)
		}

	case "net":
		// Use pre-parsed CIDR if available
		if f.ipnet != nil {
			switch f.direction {
			case "src":
				return ipInCIDR(packet.SrcIP, f.ipnet)
			case "dst":
				return ipInCIDR(packet.DstIP, f.ipnet)
			default:
				return ipInCIDR(packet.SrcIP, f.ipnet) || ipInCIDR(packet.DstIP, f.ipnet)
			}
		}
		// Fallback to substring match
		switch f.direction {
		case "src":
			return strings.Contains(packet.SrcIP, f.value)
		case "dst":
			return strings.Contains(packet.DstIP, f.value)
		default:
			return strings.Contains(packet.SrcIP, f.value) || strings.Contains(packet.DstIP, f.value)
		}

	default:
		// For complex BPF expressions, we can't match post-capture
		// Return true to show all packets
		return true
	}
}

// String returns the BPF expression
func (f *BPFFilter) String() string {
	return f.expression
}

// Type returns the filter type
func (f *BPFFilter) Type() string {
	return "bpf"
}

// GetExpression returns the BPF expression for use in live capture
func (f *BPFFilter) GetExpression() string {
	return f.expression
}

// ipInCIDR checks if an IP is in a CIDR range (using pre-parsed net.IPNet)
func ipInCIDR(ip string, ipnet *net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return ipnet.Contains(parsedIP)
}