//go:build hunter || all

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/bpfutil"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/failover"
	sharedfilter "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket/layers"
)

// Manager handles packet capture lifecycle
type Manager struct {
	lifecycleMu       sync.Mutex
	captureOptions    capture.CaptureOptions
	captureInterfaces func() []pcaptypes.PcapInterface
	radiusPorts       []uint16
	radiusBoundary    atomic.Int64
	// Configuration
	interfaces       []string
	baseFilter       string
	bufferSize       int
	sipBufferSize    int
	processorAddr    string // Legacy processor address (for automatic port exclusion)
	processors       []failover.Endpoint
	processorPeersMu sync.RWMutex
	processorPeers   map[string][]netip.Addr
	resolveProcessor func(context.Context, string) ([]netip.Addr, error)

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
	ReassembleIPFragments bool
	FilterInstaller       capture.FilterInstaller
	// CaptureInterfaces optionally supplies capture devices for embedding/tests.
	CaptureInterfaces func() []pcaptypes.PcapInterface
	RADIUSPorts       []uint16
	Interfaces        []string // Network interfaces to capture on
	BaseFilter        string   // Base BPF filter
	BufferSize        int      // Packet buffer size
	SIPBufferSize     int      // SIP priority buffer size (0 = match BufferSize)
	ProcessorAddr     string   // Processor address (for automatic port exclusion)
	Processors        []failover.Endpoint
	ResolveProcessor  func(context.Context, string) ([]netip.Addr, error)
}

// New creates a new capture manager
func New(config Config, mainCtx context.Context) *Manager {
	m := &Manager{
		captureOptions:    capture.CaptureOptions{ReassembleIPFragments: config.ReassembleIPFragments, FilterInstaller: config.FilterInstaller},
		captureInterfaces: config.CaptureInterfaces,
		radiusPorts:       append([]uint16(nil), config.RADIUSPorts...),
		interfaces:        config.Interfaces,
		baseFilter:        config.BaseFilter,
		bufferSize:        config.BufferSize,
		sipBufferSize:     config.SIPBufferSize,
		processorAddr:     config.ProcessorAddr,
		processors:        append([]failover.Endpoint(nil), config.Processors...),
		mainCtx:           mainCtx,
		processorPeers:    make(map[string][]netip.Addr),
		resolveProcessor:  config.ResolveProcessor,
	}
	if m.resolveProcessor == nil {
		m.resolveProcessor = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	for _, endpoint := range m.processors {
		host, _, err := net.SplitHostPort(endpoint.Address)
		if err != nil {
			continue
		}
		if address, err := netip.ParseAddr(host); err == nil {
			m.processorPeers[endpoint.Address] = []netip.Addr{address.Unmap().WithZone("")}
		}
	}
	return m
}

// GetPacketBuffer returns the packet buffer channel for reading packets
func (m *Manager) GetPacketBuffer() *capture.PacketBuffer {
	return m.packetBuffer
}

func (m *Manager) CaptureActive() bool {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.captureDone == nil {
		return false
	}
	select {
	case <-m.captureDone:
		return false
	default:
		return true
	}
}

// Start begins packet capture with the given BPF filter
func (m *Manager) Start(dynamicFilters []*management.Filter) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.start(dynamicFilters)
}

// PrepareBuffer lets transport/policy setup precede capture without exposing a
// nil packet queue or opening an interface under an unverified shared policy.
func (m *Manager) PrepareBuffer() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.prepareBuffer()
}

func (m *Manager) prepareBuffer() error {
	if m.packetBuffer != nil {
		return nil
	}
	buffer, err := capture.NewPacketBufferWithConfig(m.mainCtx, capture.PacketBufferConfig{RegularCapacity: m.bufferSize, SIPCapacity: m.sipBufferSize})
	if err != nil {
		return fmt.Errorf("create packet buffer: %w", err)
	}
	m.packetBuffer = buffer
	return nil
}

func (m *Manager) start(dynamicFilters []*management.Filter) error {
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
	if err := m.prepareBuffer(); err != nil {
		m.captureCancel()
		m.captureCtx = nil
		m.captureCancel = nil
		return err
	}

	// Create PCAP interfaces
	var devices []pcaptypes.PcapInterface
	for _, iface := range m.interfaces {
		for _, device := range strings.Split(iface, ",") {
			devices = append(devices, pcaptypes.CreateLiveInterface(device))
		}
	}

	if m.captureInterfaces != nil {
		devices = m.captureInterfaces()
	}
	var ready chan error
	if m.captureOptions.FilterInstaller != nil {
		ready = make(chan error, 1)
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
		if ready != nil {
			capture.InitWithBufferReady(m.captureCtx, devices, bpfFilter, m.packetBuffer, func(_ []layers.LinkType, err error) { ready <- err }, m.captureOptions)
		} else {
			capture.InitWithBuffer(m.captureCtx, devices, bpfFilter, m.packetBuffer, nil, nil, m.captureOptions)
		}
	}()

	if ready != nil {
		if err := <-ready; err != nil {
			m.captureCancel()
			<-m.captureDone
			return fmt.Errorf("initialize socket admission capture: %w", err)
		}
	}
	logger.Info("Packet capture started", "interfaces", m.interfaces)
	return nil
}

// Restart stops and restarts packet capture with updated filters
func (m *Manager) Restart(dynamicFilters []*management.Filter) error {
	return m.restart(dynamicFilters, true)
}

func (m *Manager) restart(dynamicFilters []*management.Filter, policyBoundary bool) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.captureDone == nil {
		return nil
	}
	logger.Info("Restarting packet capture to apply filter changes")

	// Save references to old capture state BEFORE Start() overwrites them
	oldCaptureDone := m.captureDone
	oldCaptureCancel := m.captureCancel
	logger.Debug("Saved old capture state", "has_done_channel", oldCaptureDone != nil, "has_cancel_func", oldCaptureCancel != nil)

	// Stop the old generation before opening replacement handles. Its final
	// packets must remain on the old side of the RADIUS capture boundary.
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
			return fmt.Errorf("timeout waiting for old capture to stop")
		}
	} else {
		logger.Debug("No old capture to wait for (first start)")
	}

	// Publish the boundary only after old readers have stopped. Queued packets
	// from their drain cannot seed or inherit association in the new epoch.
	if policyBoundary {
		m.radiusBoundary.Store(time.Now().UnixNano())
	}
	logger.Debug("Starting new capture with updated filters")
	return m.start(dynamicFilters)
}

// ApplyInitialFilters installs the processor's first BPF policy after capture
// has already started. Packets captured before that policy was known are
// discarded so they cannot enter either forwarding mode under the wrong
// capture scope.
func (m *Manager) ApplyInitialFilters(dynamicFilters []*management.Filter) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.captureDone == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(m.mainCtx, 5*time.Second)
	defer cancel()
	if err := m.quiesce(ctx); err != nil {
		return fmt.Errorf("quiesce capture for initial filters: %w", err)
	}
	if m.packetBuffer != nil {
		emptySamples := 0
		for emptySamples < 5 {
			select {
			case _, ok := <-m.packetBuffer.Receive():
				if !ok {
					return errors.New("discard pre-policy packets: packet buffer closed")
				}
				emptySamples = 0
			default:
				emptySamples++
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("discard pre-policy packets: %w", ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	if err := m.start(dynamicFilters); err != nil {
		return fmt.Errorf("start capture with initial filters: %w", err)
	}
	return nil
}

// Stop stops packet capture
func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.captureCancel != nil {
		m.captureCancel()
	}
	if m.captureDone != nil {
		select {
		case <-m.captureDone:
		case <-time.After(5 * time.Second):
			logger.Error("Timed out waiting for packet capture to stop before closing buffer")
			return
		}
	}
	if m.packetBuffer != nil {
		m.packetBuffer.Close()
	}
}

// Quiesce stops the current capture generation and waits until no producer can
// enqueue another packet. The shared PacketBuffer remains open for draining
// across an analysis-policy boundary.
func (m *Manager) Quiesce(ctx context.Context) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.quiesce(ctx)
}

func (m *Manager) quiesce(ctx context.Context) error {
	if m.captureCancel != nil {
		m.captureCancel()
	}
	if m.captureDone == nil {
		return nil
	}
	select {
	case <-m.captureDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// buildProcessorPortExclusionFilter builds a BPF filter to exclude the processor communication port.
// This prevents the hunter from capturing its own gRPC traffic to the processor.
// Returns empty string if no processor address is configured.
func (m *Manager) buildProcessorPortExclusionFilter() string {
	if len(m.processors) > 0 {
		m.processorPeersMu.RLock()
		defer m.processorPeersMu.RUnlock()
		var exclusions []string
		seen := make(map[string]bool)
		for _, endpoint := range m.processors {
			_, port, err := net.SplitHostPort(endpoint.Address)
			if err != nil {
				continue
			}
			for _, host := range m.processorPeers[endpoint.Address] {
				clause := fmt.Sprintf("(tcp and host %s and port %s)", host.String(), port)
				if !seen[clause] {
					exclusions = append(exclusions, clause)
					seen[clause] = true
				}
			}
		}
		if len(exclusions) == 0 {
			return ""
		}
		return "not (" + strings.Join(exclusions, " or ") + ")"
	}
	if m.processorAddr == "" {
		return ""
	}

	port := bpfutil.ExtractPortFromAddr(m.processorAddr)
	if port == "" {
		return ""
	}

	// Build exclusion filter for the processor port
	// Both data and management gRPC connections use the same port
	return fmt.Sprintf("not port %s", port)
}

// PrepareProcessor refreshes scoped communication exclusions before an endpoint
// is contacted. Unreachable DNS candidates cannot leave an unexcluded active
// sender; their setup fails and selection advances to another endpoint.
func (m *Manager) PrepareProcessor(ctx context.Context, endpoint failover.Endpoint, filters []*management.Filter) error {
	if len(m.processors) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(endpoint.Address)
	if err != nil {
		return fmt.Errorf("processor exclusion address: %w", err)
	}
	var addresses []netip.Addr
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = []netip.Addr{address}
	} else {
		addresses, err = m.resolveProcessor(ctx, host)
		if err != nil {
			return fmt.Errorf("resolve processor exclusion for %s: %w", host, err)
		}
	}
	var normalized []netip.Addr
	for _, address := range addresses {
		if address.IsValid() {
			normalized = append(normalized, address.Unmap().WithZone(""))
		}
	}
	if len(normalized) == 0 {
		return fmt.Errorf("processor exclusion for %s resolved no addresses", host)
	}
	m.processorPeersMu.Lock()
	previous := m.processorPeers[endpoint.Address]
	changed := len(previous) != len(normalized)
	if !changed {
		for i := range previous {
			if previous[i] != normalized[i] {
				changed = true
				break
			}
		}
	}
	m.processorPeers[endpoint.Address] = normalized
	m.processorPeersMu.Unlock()
	if changed {
		if err := m.restart(filters, false); err != nil {
			m.processorPeersMu.Lock()
			m.processorPeers[endpoint.Address] = previous
			m.processorPeersMu.Unlock()
			return fmt.Errorf("refresh processor capture exclusions: %w", err)
		}
	}
	return nil
}

// buildCombinedBPFFilter builds a combined BPF filter from config and dynamic filters
func (m *Manager) buildCombinedBPFFilter(filters []*management.Filter) string {
	var dynamicFilters []string
	hasRADIUS := false

	// Collect dynamic BPF filters (only enabled ones)
	for _, filter := range filters {
		if !filter.Enabled {
			continue
		}

		if sharedfilter.IsRADIUSFilter(filter.Type) {
			hasRADIUS = true
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
			// Example: (port 443 or port 5060) and (not port 8080) and (not port 55555)
			finalFilter = fmt.Sprintf("(%s) and (%s)", dynamicPart, exclusionPart)
		} else {
			// No base filter or processor exclusion - just use dynamic filters
			finalFilter = dynamicPart
		}
	}

	if hasRADIUS && finalFilter != "" {
		// Preserve both directions and all competing requests, including configured
		// service ports. Exact RADIUS selection happens only after correlation.
		finalFilter = fmt.Sprintf("(%s) or %s", finalFilter, radius.CaptureBPF(m.radiusPorts...))
	}
	return finalFilter
}

// CaptureBoundary distinguishes queued packets from a previous capture configuration.
func (m *Manager) CaptureBoundary() time.Time {
	n := m.radiusBoundary.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
