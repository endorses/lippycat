//go:build hunter || processor || tui
// +build hunter processor tui

package voip

import (
	"github.com/google/gopacket"
)

// Stub implementations for builds that don't include file writing
// These should never be called in hunter/processor/tui mode, but need to exist for compilation

func WriteSIP(callID string, packet gopacket.Packet) {
	// No-op stub for non-CLI builds
	// If this gets called, it's a bug - writeVoip should be false in these modes
}

func WriteRTP(callID string, packet gopacket.Packet) {
	// No-op stub for non-CLI builds
	// If this gets called, it's a bug - writeVoip should be false in these modes
}

func CloseWriters() {
	// No-op stub for non-CLI builds
}
