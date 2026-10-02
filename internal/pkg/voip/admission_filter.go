package voip

import (
	"fmt"
	"strings"
)

// AdmissionPortRange is an explicitly configured constraint, never a generated
// default RTP heuristic. The kernel applies it before diagnostic/failure bypass.
type AdmissionPortRange struct{ Start, End uint16 }
type AdmissionFilter struct {
	Expression    string
	SIPPorts      []uint16
	RTPPortRanges []AdmissionPortRange
	UDPOnly       bool
}

// BuildAdmissionFilter separates the user's classic predicate from protocol
// constraints that require parsed transport offsets. The eBPF backend MUST receive
// all fields: using Expression alone would discard explicit user restrictions.
// In particular, no implicit 10000-32768 range is added for selected endpoints.
func BuildAdmissionFilter(config VoIPFilterConfig) (AdmissionFilter, error) {
	result := AdmissionFilter{Expression: strings.TrimSpace(config.BaseFilter), UDPOnly: config.UDPOnly}
	seen := make(map[int]bool)
	for _, p := range config.SIPPorts {
		if err := validatePort(p); err != nil {
			return AdmissionFilter{}, fmt.Errorf("SIP capture constraint: %w", err)
		}
		if !seen[p] {
			result.SIPPorts = append(result.SIPPorts, uint16(p))
			seen[p] = true
		}
	}
	for _, r := range config.RTPPortRanges {
		if err := validatePortRange(r.Start, r.End); err != nil {
			return AdmissionFilter{}, fmt.Errorf("RTP capture constraint: %w", err)
		}
		result.RTPPortRanges = append(result.RTPPortRanges, AdmissionPortRange{Start: uint16(r.Start), End: uint16(r.End)})
	}
	return result, nil
}
