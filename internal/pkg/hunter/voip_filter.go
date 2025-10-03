package hunter

import (
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VoIPFilter handles GPU-accelerated VoIP packet filtering
type VoIPFilter struct {
	gpuAccel     *voip.GPUAccelerator
	config       *voip.GPUConfig
	sipUsers     []string
	phoneNumbers []string
	patterns     []voip.GPUPattern
	mu           sync.RWMutex
	enabled      bool
}

// NewVoIPFilter creates a new VoIP filter with optional GPU acceleration
func NewVoIPFilter(config *voip.GPUConfig) (*VoIPFilter, error) {
	vf := &VoIPFilter{
		config:       config,
		sipUsers:     make([]string, 0),
		phoneNumbers: make([]string, 0),
		patterns:     make([]voip.GPUPattern, 0),
		enabled:      config != nil && config.Enabled,
	}

	// Initialize GPU accelerator if enabled
	if vf.enabled {
		gpuAccel, err := voip.NewGPUAccelerator(config)
		if err != nil {
			logger.Warn("Failed to initialize GPU accelerator for VoIP filtering, falling back to CPU", "error", err)
			vf.enabled = false
		} else {
			vf.gpuAccel = gpuAccel
		}
	}

	return vf, nil
}

// UpdateFilters updates the filter list from processor
func (vf *VoIPFilter) UpdateFilters(filters []*management.Filter) {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	// Clear existing
	vf.sipUsers = vf.sipUsers[:0]
	vf.phoneNumbers = vf.phoneNumbers[:0]
	vf.patterns = vf.patterns[:0]

	// Build new filter lists
	for _, filter := range filters {
		switch filter.Type {
		case management.FilterType_FILTER_SIP_USER:
			vf.sipUsers = append(vf.sipUsers, filter.Pattern)
			// Create GPU pattern for SIP user matching
			vf.patterns = append(vf.patterns, voip.GPUPattern{
				ID:            len(vf.patterns),
				Pattern:       []byte(filter.Pattern),
				PatternLen:    len(filter.Pattern),
				Type:          voip.PatternTypeContains,
				CaseSensitive: false,
			})

		case management.FilterType_FILTER_PHONE_NUMBER:
			vf.phoneNumbers = append(vf.phoneNumbers, filter.Pattern)
			// Create GPU pattern for phone number matching
			vf.patterns = append(vf.patterns, voip.GPUPattern{
				ID:            len(vf.patterns),
				Pattern:       []byte(filter.Pattern),
				PatternLen:    len(filter.Pattern),
				Type:          voip.PatternTypeContains,
				CaseSensitive: false,
			})
		}
	}

	logger.Info("Updated VoIP filters",
		"sip_users", len(vf.sipUsers),
		"phone_numbers", len(vf.phoneNumbers),
		"gpu_enabled", vf.enabled)
}

// MatchPacket checks if a packet matches any of the filters
func (vf *VoIPFilter) MatchPacket(packet gopacket.Packet) bool {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	// If no filters, match everything
	if len(vf.sipUsers) == 0 && len(vf.phoneNumbers) == 0 {
		return true
	}

	// Check if this is a SIP or RTP packet
	if !vf.isVoIPPacket(packet) {
		return false
	}

	// Get payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false
	}

	payload := appLayer.Payload()

	// Use GPU if enabled and we have patterns
	if vf.enabled && vf.gpuAccel != nil && len(vf.patterns) > 0 {
		return vf.matchWithGPU([]byte(payload))
	}

	// CPU fallback
	return vf.matchWithCPU(string(payload))
}

// MatchBatch checks multiple packets using GPU acceleration
func (vf *VoIPFilter) MatchBatch(packets []gopacket.Packet) []bool {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	results := make([]bool, len(packets))

	// If no filters, match everything
	if len(vf.sipUsers) == 0 && len(vf.phoneNumbers) == 0 {
		for i := range results {
			results[i] = true
		}
		return results
	}

	// Extract VoIP packets and payloads
	voipPackets := make([][]byte, 0, len(packets))
	voipIndices := make([]int, 0, len(packets))

	for i, packet := range packets {
		if vf.isVoIPPacket(packet) {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				voipPackets = append(voipPackets, appLayer.Payload())
				voipIndices = append(voipIndices, i)
			}
		}
	}

	// If we have GPU and multiple packets, use batch processing
	if vf.enabled && vf.gpuAccel != nil && len(voipPackets) > 1 && len(vf.patterns) > 0 {
		gpuResults, err := vf.gpuAccel.ProcessBatch(voipPackets, vf.patterns)
		if err == nil {
			// Map GPU results back to packet indices
			matchedPackets := make(map[int]bool)
			for _, result := range gpuResults {
				if result.Matched && result.PacketIndex < len(voipIndices) {
					matchedPackets[voipIndices[result.PacketIndex]] = true
				}
			}

			for i := range results {
				results[i] = matchedPackets[i]
			}
			return results
		}
		// GPU failed, fall back to CPU
	}

	// CPU fallback
	for _, idx := range voipIndices {
		packet := packets[idx]
		results[idx] = vf.MatchPacket(packet)
	}

	return results
}

// matchWithGPU uses GPU acceleration for pattern matching
func (vf *VoIPFilter) matchWithGPU(payload []byte) bool {
	if vf.gpuAccel == nil || len(vf.patterns) == 0 {
		return false
	}

	// Process single packet as batch of 1
	results, err := vf.gpuAccel.ProcessBatch([][]byte{payload}, vf.patterns)
	if err != nil {
		// Fall back to CPU on error
		return vf.matchWithCPU(string(payload))
	}

	// Check if any pattern matched
	for _, result := range results {
		if result.Matched && result.PacketIndex == 0 {
			return true
		}
	}

	return false
}

// matchWithCPU uses CPU for pattern matching (fallback)
func (vf *VoIPFilter) matchWithCPU(payload string) bool {
	payloadLower := strings.ToLower(payload)

	// Check SIP users
	for _, user := range vf.sipUsers {
		if strings.Contains(payloadLower, strings.ToLower(user)) {
			return true
		}
	}

	// Check phone numbers
	for _, number := range vf.phoneNumbers {
		if strings.Contains(payloadLower, number) {
			return true
		}
	}

	return false
}

// isVoIPPacket checks if a packet is SIP or RTP
func (vf *VoIPFilter) isVoIPPacket(packet gopacket.Packet) bool {
	// Check for UDP layer (both SIP and RTP use UDP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return false
	}

	// SIP uses port 5060
	if udp.SrcPort == 5060 || udp.DstPort == 5060 {
		return true
	}

	// RTP typically uses ports 10000-20000
	srcPort := int(udp.SrcPort)
	dstPort := int(udp.DstPort)
	if (srcPort >= 10000 && srcPort <= 20000) || (dstPort >= 10000 && dstPort <= 20000) {
		return true
	}

	return false
}

// Close cleans up GPU resources
func (vf *VoIPFilter) Close() {
	if vf.gpuAccel != nil {
		// GPU cleanup would happen here
		logger.Info("VoIP filter closed")
	}
}
