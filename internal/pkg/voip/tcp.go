package voip

// TCP processing entry point for VoIP traffic analysis
//
// This file serves as the main entry point for TCP-based VoIP traffic processing.
// The TCP functionality has been refactored into focused modules:
//
// - tcp_buffer.go:  TCP packet buffering and buffer pool management
// - tcp_metrics.go: Performance metrics and health monitoring
// - tcp_stream.go:  SIP stream processing and CallID detection
// - tcp_factory.go: Stream factory and lifecycle management
// - tcp_config.go:  TCP-specific configuration options
// - tcp_main.go:    Main TCP packet processing entry point
//
// This architectural change improves maintainability by:
// - Separating concerns into focused responsibilities
// - Reducing file size from 1,267 to manageable chunks
// - Making testing and debugging more targeted
// - Improving code readability and navigation

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// HandleTcpPackets is the main entry point for TCP packet processing
// It processes TCP packets and feeds them to the assembler for VoIP analysis
func HandleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	handleTcpPackets(pkt, layer, assembler)
}

// Functions are exported directly from their respective files

// Types are defined in their respective files

// Constants are defined in constants.go and tcp_config.go
