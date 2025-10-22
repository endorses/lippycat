//go:build hunter || all

package capture

import (
	"context"
	"fmt"
	"net"
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
	interfaces    []string
	baseFilter    string
	bufferSize    int
	processorAddr string // Processor address (for automatic port exclusion)

	// Packet buffer (shared with forwarding)
	packetBuffer *capture.PacketBuffer

	// Capture lifecycle
	captureCtx    context.Context
	captureCancel context.CancelFunc
	captureDone   chan struct{}   // Signals when capture goroutines have exited
	mainCtx       context.Context // Main hunter context (for buffer lifetime)
}

// Config contains capture manager configuration
type Config struct {
	Interfaces    []string // Network interfaces to capture on
	BaseFilter    string   // Base BPF filter
	BufferSize    int      // Packet buffer size
	ProcessorAddr string   // Processor address (for automatic port exclusion)
}

// New creates a new capture manager
func New(config Config, mainCtx context.Context) *Manager {
	return &Manager{
		interfaces:    config.Interfaces,
		baseFilter:    config.BaseFilter,
		bufferSize:    config.BufferSize,
		processorAddr: config.ProcessorAddr,
		mainCtx:       mainCtx,
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

	// Create done channel to signal when capture goroutines exit
	m.captureDone = make(chan struct{})
	logger.Debug("Created new captureDone channel")

	// Start capture in background
	go func() {
		defer close(m.captureDone) // Signal completion when all capture goroutines exit

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

	// Save references to old capture state BEFORE Start() overwrites them
	oldCaptureDone := m.captureDone
	oldCaptureCancel := m.captureCancel
	logger.Debug("Saved old capture state", "has_done_channel", oldCaptureDone != nil, "has_cancel_func", oldCaptureCancel != nil)

	// Start new capture first (this creates new context and cancel function)
	// We do this BEFORE cancelling the old one so we don't lose the cancel function
	logger.Debug("Starting new capture with updated filters")
	if err := m.Start(dynamicFilters); err != nil {
		return err
	}

	// Now cancel the OLD capture context (after Start() created the new one)
	if oldCaptureCancel != nil {
		logger.Debug("Cancelling old capture context")
		oldCaptureCancel()
	}

	// Wait for old capture goroutines to fully exit
	// This prevents race conditions where both old and new goroutines write to the buffer
	if oldCaptureDone != nil {
		logger.Debug("Waiting for old capture goroutines to exit...")
		select {
		case <-oldCaptureDone:
			logger.Debug("Old capture goroutines exited cleanly")
		case <-time.After(5 * time.Second):
			logger.Warn("Timeout waiting for old capture to stop, proceeding anyway")
		}
	} else {
		logger.Debug("No old capture to wait for (first start)")
	}

	return nil
}

// Stop stops packet capture
func (m *Manager) Stop() {
	if m.captureCancel != nil {
		m.captureCancel()
	}
}

// extractPortFromAddr extracts the port from a "host:port" address string.
// Returns empty string if the address is invalid or has no port.
func extractPortFromAddr(addr string) string {
	if addr == "" {
		return ""
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If parsing fails, log debug message but continue without port exclusion
		logger.Debug("Failed to parse processor address for port extraction", "addr", addr, "error", err)
		return ""
	}

	return port
}

// buildProcessorPortExclusionFilter builds a BPF filter to exclude the processor communication port.
// This prevents the hunter from capturing its own gRPC traffic to the processor.
// Returns empty string if no processor address is configured.
func (m *Manager) buildProcessorPortExclusionFilter() string {
	if m.processorAddr == "" {
		return ""
	}

	port := extractPortFromAddr(m.processorAddr)
	if port == "" {
		return ""
	}

	// Build exclusion filter for the processor port
	// Both data and management gRPC connections use the same port
	return fmt.Sprintf("not port %s", port)
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

	// Build processor port exclusion filter (automatic)
	processorExclusion := m.buildProcessorPortExclusionFilter()

	// Build final filter
	var finalFilter string

	if len(dynamicFilters) == 0 {
		// No dynamic filters - combine base filter with processor exclusion
		if m.baseFilter != "" && processorExclusion != "" {
			// Both base filter and processor exclusion
			finalFilter = fmt.Sprintf("(%s) and (%s)", m.baseFilter, processorExclusion)
		} else if m.baseFilter != "" {
			// Only base filter
			finalFilter = m.baseFilter
		} else if processorExclusion != "" {
			// Only processor exclusion
			finalFilter = processorExclusion
		}
		// else: no filters at all, finalFilter stays empty
	} else {
		// Combine dynamic filters with OR (capture matching ANY dynamic filter)
		dynamicPart := strings.Join(dynamicFilters, " or ")

		// Build combined filter with base filter and processor exclusion
		var exclusionPart string
		if m.baseFilter != "" && processorExclusion != "" {
			exclusionPart = fmt.Sprintf("(%s) and (%s)", m.baseFilter, processorExclusion)
		} else if m.baseFilter != "" {
			exclusionPart = m.baseFilter
		} else if processorExclusion != "" {
			exclusionPart = processorExclusion
		}

		if exclusionPart != "" {
			// Combine with base filter and processor exclusion using AND
			// Logic: (dynamic filters) AND (base exclusions) AND (processor exclusion)
			// Example: (port 443 or port 5060) and (not port 8080) and (not port 50051)
			finalFilter = fmt.Sprintf("(%s) and (%s)", dynamicPart, exclusionPart)
		} else {
			// No base filter or processor exclusion - just use dynamic filters
			finalFilter = dynamicPart
		}
	}

	return finalFilter
}
