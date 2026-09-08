package radius

import (
	"fmt"
	"strings"
)

// CaptureBPF preserves both directions of supported service traffic. IPv6 UDP
// extension chains require protocol-chain matching: classic port predicates do
// not walk those headers, so userspace performs the final IPv6 port validation.
func CaptureBPF(ports ...uint16) string {
	seen := map[uint16]bool{}
	var terms []string
	for _, port := range append([]uint16{1812, 1813}, ports...) {
		if port == 0 || seen[port] {
			continue
		}
		seen[port] = true
		terms = append(terms, fmt.Sprintf("udp port %d", port))
	}
	return "(" + strings.Join(terms, " or ") + " or (ip6 protochain 17))"
}
