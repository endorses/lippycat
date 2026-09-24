package capture

import "sync"

// Telemetry is a cumulative snapshot of live capture health across all
// interfaces participating in one capture session.
type Telemetry struct {
	PacketsReceived           int64
	KernelDrops               int64
	InterfaceDrops            int64
	PacketBufferDrops         int64
	PacketBufferRegularDrops  int64
	PacketBufferSIPDrops      int64
	PacketBufferSIPDemotions  int64
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
	// IPv4Defrag is one shared session snapshot, never summed across interfaces.
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
	mu              sync.Mutex
	callbackMu      sync.Mutex
	interfaces      map[string]interfaceTelemetry
	callback        TelemetryCallback
	fragmentIngress map[string]FragmentIngress
	ipv4            *IPv4Defragmenter
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
	if c.ipv4 != nil {
		snapshot.IPv4Defrag = c.ipv4.Snapshot()
	}
	if buffer != nil {
		bufferSnapshot := buffer.Snapshot()
		snapshot.PacketBufferRegularDrops = bufferSnapshot.RegularDropped
		snapshot.PacketBufferSIPDrops = bufferSnapshot.SIPDropped
		snapshot.PacketBufferSIPDemotions = bufferSnapshot.SIPDemoted
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
	if c.callback != nil {
		c.callback(snapshot)
	}
	return snapshot
}
