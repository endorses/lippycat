//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket"
)

func TestProtocolInfoAcceptsNilMetadata(t *testing.T) {
	packet := gopacket.NewPacket(nil, gopacket.LayerTypeZero, gopacket.NoCopy)
	protocols := []string{
		"SIP", "RTP", "HTTP", "TLS", "SSH", "DNS", "ARP", "FTP", "SMTP",
		"MySQL", "PostgreSQL", "POP3", "IMAP", "Redis", "MongoDB", "Telnet",
		"WebSocket", "WireGuard", "OpenVPN", "L2TP", "IKEv2", "PPTP", "QUIC",
	}
	for _, protocol := range protocols {
		t.Run(protocol, func(t *testing.T) {
			display := &components.PacketDisplay{}
			result := &signatures.DetectionResult{Protocol: protocol}
			_ = buildProtocolInfo(result, packet, display, nil)
		})
	}
}
