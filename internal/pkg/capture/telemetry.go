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
	SIPClassified             int64
	SIPFlowPromotions         uint64
	SIPFlowClassifiedSegments uint64
	SIPFlowIdleExpirations    uint64
	SIPFlowCapacityEvictions  uint64
	SIPFlowConnectionCloses   uint64
	SIPFlowActive             int
}

// TelemetryCallback receives cumulative snapshots. Callbacks must return
// promptly because capture statistics are collected on a background goroutine.
type TelemetryCallback func(Telemetry)

type telemetryCollector struct {
	mu         sync.Mutex
	callbackMu sync.Mutex
	interfaces map[string]interfaceTelemetry
	callback   TelemetryCallback
}

type interfaceTelemetry struct {
	received       int64
	kernelDrops    int64
	interfaceDrops int64
}

func newTelemetryCollector(callback TelemetryCallback) *telemetryCollector {
	return &telemetryCollector{
		interfaces: make(map[string]interfaceTelemetry),
		callback:   callback,
	}
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
	if buffer != nil {
		snapshot.PacketBufferRegularDrops = buffer.GetDropped()
		snapshot.PacketBufferSIPDrops = buffer.GetSIPDropped()
		snapshot.PacketBufferDrops = snapshot.PacketBufferRegularDrops + snapshot.PacketBufferSIPDrops
		snapshot.SIPClassified = buffer.GetSIPClassified()
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
