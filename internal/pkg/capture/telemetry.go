package capture

import "sync"

// Telemetry is a cumulative snapshot of live capture health across all
// interfaces participating in one capture session.
type Telemetry struct {
	PacketsReceived   int64
	KernelDrops       int64
	InterfaceDrops    int64
	PacketBufferDrops int64
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

func (c *telemetryCollector) report(interfaceName string, received, kernelDrops, interfaceDrops, bufferDrops int64) Telemetry {
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
	snapshot.PacketBufferDrops = bufferDrops
	c.mu.Unlock()
	if c.callback != nil {
		c.callback(snapshot)
	}
	return snapshot
}
