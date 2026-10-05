package capture

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"sync"
	"sync/atomic"
)

// Telemetry is a cumulative snapshot of live capture health across all
// interfaces participating in one capture session.
type Telemetry struct {
	// StartupDiscards counts retained frames deliberately drained before activation.
	StartupDiscards           uint64
	MediaAdmission            *mediaadmission.Snapshot
	PacketsReceived           int64
	KernelDrops               int64
	InterfaceDrops            int64
	PacketBufferDrops         int64
	PacketBufferRegularDrops  int64
	PacketBufferSIPDrops      int64
	PacketBufferSIPDemotions  int64
	PacketBufferSIPOrdered    int64
	PacketBufferRegularLength int
	PacketBufferRegularCap    int
	PacketBufferSIPLength     int
	PacketBufferSIPCap        int
	PacketBufferOutputLength  int
	PacketBufferOutputCap     int
	SIPClassified             int64
	SIPFlowPromotions         uint64
	SIPFlowClassifiedSegments uint64
	SIPFlowIdleExpirations    uint64
	SIPFlowCapacityEvictions  uint64
	SIPFlowConnectionCloses   uint64
	SIPFlowActive             int
	// FragmentIngress is cumulative by interface for this capture session.
	FragmentIngress map[string]FragmentIngress
	// IPv4Defrag sums distinct observation domains once, never once per interface.
	IPv4Defrag IPv4DefragSnapshot
}

type FragmentIngress struct {
	IPv4Observed  uint64
	IPv4Attempted uint64
	IPv6Observed  uint64
	IPv6Attempted uint64
}

// TelemetryCallback receives cumulative snapshots. Callbacks must return
// promptly because capture statistics are collected on a background goroutine.
type TelemetryCallback func(Telemetry)

type telemetryCollector struct {
	startupDiscards atomic.Uint64
	admission       mediaadmission.StatusProvider
	mu              sync.Mutex
	callbackMu      sync.Mutex
	interfaces      map[string]interfaceTelemetry
	callback        TelemetryCallback
	fragmentIngress map[string]FragmentIngress
	ipv4            *IPv4Defragmenter
	ipv4Domains     []*IPv4Defragmenter
}

type interfaceTelemetry struct {
	received       int64
	kernelDrops    int64
	interfaceDrops int64
}

func newTelemetryCollector(callback TelemetryCallback) *telemetryCollector {
	return &telemetryCollector{
		interfaces:      make(map[string]interfaceTelemetry),
		fragmentIngress: make(map[string]FragmentIngress),
		callback:        callback,
	}
}

// Startup discard providers report immutable preparation results, independently
// of capture drop counters. Called once per prepared socket.
func (c *telemetryCollector) recordStartupDiscards(attachment PreparedFilter) {
	if c == nil || attachment == nil {
		return
	}
	if stats, ok := attachment.(interface{ StartupDiscards() uint64 }); ok {
		c.startupDiscards.Add(stats.StartupDiscards())
	}
}

func (c *telemetryCollector) observeFragment(name string, ipv4, attempted bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.fragmentIngress[name]
	if ipv4 {
		s.IPv4Observed++
		if attempted {
			s.IPv4Attempted++
		}
	} else {
		s.IPv6Observed++
		if attempted {
			s.IPv6Attempted++
		}
	}
	c.fragmentIngress[name] = s
}

func (c *telemetryCollector) report(interfaceName string, received, kernelDrops, interfaceDrops int64, buffer *PacketBuffer) Telemetry {
	if c == nil {
		return Telemetry{}
	}

	c.callbackMu.Lock()
	defer c.callbackMu.Unlock()

	c.mu.Lock()
	c.interfaces[interfaceName] = interfaceTelemetry{
		received:       received,
		kernelDrops:    kernelDrops,
		interfaceDrops: interfaceDrops,
	}
	var snapshot Telemetry
	snapshot.StartupDiscards = c.startupDiscards.Load()
	for _, stats := range c.interfaces {
		snapshot.PacketsReceived += stats.received
		snapshot.KernelDrops += stats.kernelDrops
		snapshot.InterfaceDrops += stats.interfaceDrops
	}
	if len(c.fragmentIngress) != 0 {
		snapshot.FragmentIngress = make(map[string]FragmentIngress, len(c.fragmentIngress))
		for name, stats := range c.fragmentIngress {
			snapshot.FragmentIngress[name] = stats
		}
	}
	if len(c.ipv4Domains) > 0 {
		snapshot.IPv4Defrag = sumIPv4Defrag(c.ipv4Domains)
	} else if c.ipv4 != nil {
		snapshot.IPv4Defrag = c.ipv4.Snapshot()
	}
	if buffer != nil {
		bufferSnapshot := buffer.Snapshot()
		snapshot.PacketBufferRegularDrops = bufferSnapshot.RegularDropped
		snapshot.PacketBufferSIPDrops = bufferSnapshot.SIPDropped
		snapshot.PacketBufferSIPDemotions = bufferSnapshot.SIPDemoted
		snapshot.PacketBufferSIPOrdered = bufferSnapshot.SIPOrdered
		snapshot.PacketBufferDrops = snapshot.PacketBufferRegularDrops + snapshot.PacketBufferSIPDrops
		snapshot.PacketBufferRegularLength = bufferSnapshot.RegularLength
		snapshot.PacketBufferRegularCap = bufferSnapshot.RegularCapacity
		snapshot.PacketBufferSIPLength = bufferSnapshot.SIPLength
		snapshot.PacketBufferSIPCap = bufferSnapshot.SIPCapacity
		snapshot.PacketBufferOutputLength = bufferSnapshot.OutputLength
		snapshot.PacketBufferOutputCap = bufferSnapshot.OutputCapacity
		snapshot.SIPClassified = bufferSnapshot.SIPClassified
		flowStats, active := buffer.GetSIPFlowClassifierStats()
		snapshot.SIPFlowPromotions = flowStats.Promotions
		snapshot.SIPFlowClassifiedSegments = flowStats.ClassifiedSegments
		snapshot.SIPFlowIdleExpirations = flowStats.IdleExpirations
		snapshot.SIPFlowCapacityEvictions = flowStats.CapacityEvictions
		snapshot.SIPFlowConnectionCloses = flowStats.ConnectionCloses
		snapshot.SIPFlowActive = active
	}
	c.mu.Unlock()
	if c.admission != nil {
		status := c.admission.Status()
		snapshot.MediaAdmission = &status
	}
	if c.callback != nil {
		c.callback(snapshot)
	}
	return snapshot
}
