//go:build hunter || all

package capture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Manager handles packet capture lifecycle
type Manager struct {
	// Configuration
	interfaces []string
	baseFilter string
	bufferSize int

	// Packet buffer (shared with forwarding)
	packetBuffer *capture.PacketBuffer

	// Capture lifecycle
	captureCtx    context.Context
	captureCancel context.CancelFunc
	mainCtx       context.Context // Main hunter context (for buffer lifetime)
}

// Config contains capture manager configuration
type Config struct {
	Interfaces []string // Network interfaces to capture on
	BaseFilter string   // Base BPF filter
	BufferSize int      // Packet buffer size
}

// New creates a new capture manager
func New(config Config, mainCtx context.Context) *Manager {
	return &Manager{
		interfaces: config.Interfaces,
		baseFilter: config.BaseFilter,
		bufferSize: config.BufferSize,
		mainCtx:    mainCtx,
	}
}

// GetPacketBuffer returns the packet buffer channel for reading packets
func (m *Manager) GetPacketBuffer() *capture.PacketBuffer {
	return m.packetBuffer
}

// Start begins packet capture with the given BPF filter
func (m *Manager) Start(dynamicFilters []*management.Filter) error {
	// Build combined BPF filter
	bpfFilter := m.buildCombinedBPFFilter(dynamicFilters)

	logger.Info("Starting packet capture",
		"interfaces", m.interfaces,
		"filter", bpfFilter)

	// Create capture context
	m.captureCtx, m.captureCancel = context.WithCancel(m.mainCtx)

	// Create packet buffer ONLY on first start
	// Don't recreate on restart - forwardPackets() is already reading from it
	// IMPORTANT: Use mainCtx (not captureCtx) so buffer survives capture restarts
	if m.packetBuffer == nil {
		m.packetBuffer = capture.NewPacketBuffer(m.mainCtx, m.bufferSize)
	}

	// Create PCAP interfaces
	var devices []pcaptypes.PcapInterface
	for _, iface := range m.interfaces {
		for _, device := range strings.Split(iface, ",") {
			devices = append(devices, pcaptypes.CreateLiveInterface(device))
		}
	}

	// Start capture in background
	go func() {
		// Use InitWithBuffer to avoid double-buffering. We pass m.packetBuffer
		// directly so capture goroutines write to it, eliminating the intermediate
		// copy that was causing packet drops. The forwarding manager reads directly
		// from this buffer.
		//
		// By passing nil as the processor, we indicate that we own the buffer and
		// will read from it externally (via the forwarding manager).
		capture.InitWithBuffer(m.captureCtx, devices, bpfFilter, m.packetBuffer, nil, nil)
	}()

	logger.Info("Packet capture started", "interfaces", m.interfaces)
	return nil
}

// Restart stops and restarts packet capture with updated filters
func (m *Manager) Restart(dynamicFilters []*management.Filter) error {
	logger.Info("Restarting packet capture to apply filter changes")

	// Cancel current capture
	if m.captureCancel != nil {
		m.captureCancel()
	}

	// Wait a moment for capture to clean up
	time.Sleep(100 * time.Millisecond)

	// Start new capture with updated filters
	return m.Start(dynamicFilters)
}

// Stop stops packet capture
func (m *Manager) Stop() {
	if m.captureCancel != nil {
		m.captureCancel()
	}
}

// buildCombinedBPFFilter builds a combined BPF filter from config and dynamic filters
func (m *Manager) buildCombinedBPFFilter(filters []*management.Filter) string {
	var dynamicFilters []string

	// Collect dynamic BPF filters (only enabled ones)
	for _, filter := range filters {
		if !filter.Enabled {
			continue
		}

		// Only BPF type filters are applied directly
		// Other filter types (SIP user, phone, IP, etc.) would need different handling
		if filter.Type == management.FilterType_FILTER_BPF {
			if filter.Pattern != "" {
				dynamicFilters = append(dynamicFilters, fmt.Sprintf("(%s)", filter.Pattern))
			}
		}
	}

	// Build final filter
	var finalFilter string

	if len(dynamicFilters) == 0 {
		// No dynamic filters - use base config filter only
		finalFilter = m.baseFilter
	} else {
		// Combine dynamic filters with OR (capture matching ANY dynamic filter)
		dynamicPart := strings.Join(dynamicFilters, " or ")

		if m.baseFilter != "" {
			// Combine with base filter using AND
			// Logic: (dynamic filters) AND (base exclusions)
			// Example: (port 443) and (not port 50051 and not port 50052)
			finalFilter = fmt.Sprintf("(%s) and (%s)", dynamicPart, m.baseFilter)
		} else {
			// No base filter - just use dynamic filters
			finalFilter = dynamicPart
		}
	}

	return finalFilter
}
