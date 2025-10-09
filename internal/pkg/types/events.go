package types

import "github.com/endorses/lippycat/api/gen/management"

// EventHandler defines the interface for receiving remote capture events.
// This allows remotecapture to be decoupled from TUI-specific implementations.
type EventHandler interface {
	// OnPacketBatch is called when a batch of packets is received
	OnPacketBatch(packets []PacketDisplay)

	// OnHunterStatus is called when hunter status is updated
	OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus)

	// OnDisconnect is called when connection is lost
	OnDisconnect(address string, err error)
}

// NoopEventHandler is a no-op implementation of EventHandler for testing
type NoopEventHandler struct{}

func (n *NoopEventHandler) OnPacketBatch(packets []PacketDisplay)                      {}
func (n *NoopEventHandler) OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus)    {}
func (n *NoopEventHandler) OnDisconnect(address string, err error)                     {}
