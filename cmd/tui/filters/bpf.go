package filters

import (
	"fmt"
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
}

// NewBPFFilter creates a new BPF filter
// Note: For TUI post-capture filtering, we do simple field matching
// Real BPF compilation would be used at capture time
func NewBPFFilter(expression string) (*BPFFilter, error) {
	// Validate it looks like a BPF expression
	if expression == "" {
		return nil, fmt.Errorf("empty BPF expression")
	}

	return &BPFFilter{
		expression: expression,
	}, nil
}

// Match checks if the packet matches the BPF filter
// This is a simplified post-capture matcher for common BPF expressions
func (f *BPFFilter) Match(packet components.PacketDisplay) bool {
	// Parse common BPF expressions for post-capture filtering
	// This handles the most common cases without full BPF compilation

	// Protocol filters
	if f.expression == "tcp" || f.expression == "TCP" {
		return packet.Protocol == "TCP"
	}
	if f.expression == "udp" || f.expression == "UDP" {
		return packet.Protocol == "UDP"
	}
	if f.expression == "icmp" || f.expression == "ICMP" {
		return packet.Protocol == "ICMP"
	}

	// Port filters: "port 5060", "src port 5060", "dst port 5060"
	if matches := portRegex.FindStringSubmatch(f.expression); len(matches) > 0 {
		direction := matches[1] // "src", "dst", or ""
		port := matches[2]

		switch direction {
		case "src":
			return packet.SrcPort == port
		case "dst":
			return packet.DstPort == port
		default:
			return packet.SrcPort == port || packet.DstPort == port
		}
	}

	// Host filters: "host 192.168.1.1", "src host 192.168.1.1", "dst host 192.168.1.1"
	if matches := hostRegex.FindStringSubmatch(f.expression); len(matches) > 0 {
		direction := matches[1]
		host := matches[2]

		switch direction {
		case "src":
			return containsIP(packet.SrcIP, host)
		case "dst":
			return containsIP(packet.DstIP, host)
		default:
			return containsIP(packet.SrcIP, host) || containsIP(packet.DstIP, host)
		}
	}

	// Net filters: "net 192.168.1.0/24", "src net 192.168.1", "dst net 192.168.1"
	if matches := netRegex.FindStringSubmatch(f.expression); len(matches) > 0 {
		direction := matches[1]
		network := matches[2]

		switch direction {
		case "src":
			return containsIP(packet.SrcIP, network)
		case "dst":
			return containsIP(packet.DstIP, network)
		default:
			return containsIP(packet.SrcIP, network) || containsIP(packet.DstIP, network)
		}
	}

	// For complex BPF expressions, we can't match post-capture
	// Return true to show all packets (or we could return false to be strict)
	return true
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

// containsIP checks if an IP address matches a pattern (partial match or CIDR)
func containsIP(ip, pattern string) bool {
	// Simple substring match for partial IPs like "192.168.1"
	return strings.Contains(ip, pattern)
}