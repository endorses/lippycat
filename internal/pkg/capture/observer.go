package capture

import "sync"

// PacketObserver receives packets as they enter the CLI capture pipeline. It is
// intended for optional, output-only consumers such as structured protocol logs.
type PacketObserver func(PacketInfo)

var packetObserver struct {
	sync.RWMutex
	fn PacketObserver
}

// SetPacketObserver installs an observer and returns a function which restores
// the previous observer. A lippycat process runs one CLI capture at a time.
func SetPacketObserver(fn PacketObserver) func() {
	packetObserver.Lock()
	previous := packetObserver.fn
	packetObserver.fn = fn
	packetObserver.Unlock()
	return func() {
		packetObserver.Lock()
		packetObserver.fn = previous
		packetObserver.Unlock()
	}
}

func observePacket(info PacketInfo) {
	packetObserver.RLock()
	fn := packetObserver.fn
	packetObserver.RUnlock()
	if fn != nil {
		fn(info)
	}
}
