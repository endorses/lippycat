package tui

import (
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
)

// StartPacketBridge creates a bridge between packet capture and TUI
// It converts capture.PacketInfo to PacketMsg for the TUI
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program) {
	for pktInfo := range packetChan {
		packet := convertPacket(pktInfo)
		program.Send(PacketMsg{Packet: packet})
	}
}

// convertPacket converts a gopacket.Packet to PacketDisplay
func convertPacket(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet
	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     "unknown",
		DstIP:     "unknown",
		SrcPort:   "",
		DstPort:   "",
		Protocol:  "unknown",
		Length:    pkt.Metadata().Length,
		Info:      "",
	}

	// Extract network layer info
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
		case *layers.IPv6:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
		}
	}

	// Extract transport layer info
	if transLayer := pkt.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			display.Protocol = "TCP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
			display.Info = fmt.Sprintf("%s → %s [%s]",
				display.SrcPort, display.DstPort, tcpFlags(trans))

		case *layers.UDP:
			display.Protocol = "UDP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
			display.Info = fmt.Sprintf("%s → %s", display.SrcPort, display.DstPort)
		}
	}

	// Extract application layer info
	if appLayer := pkt.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()

		// Try to detect SIP
		if len(payload) > 4 {
			payloadStr := string(payload[:min(100, len(payload))])
			if isSIP(payloadStr) {
				display.Protocol = "SIP"
				display.Info = extractSIPInfo(payloadStr)
			} else if isDNS(payload) {
				display.Protocol = "DNS"
				display.Info = "DNS Query/Response"
			}
		}
	}

	return display
}

// tcpFlags returns a string representation of TCP flags
func tcpFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	if flags == "" {
		return "NONE"
	}
	return flags[:len(flags)-1] // Remove trailing space
}

// isSIP checks if the payload looks like SIP
func isSIP(payload string) bool {
	sipMethods := []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "SIP/2.0"}
	for _, method := range sipMethods {
		if len(payload) >= len(method) && payload[:len(method)] == method {
			return true
		}
	}
	return false
}

// extractSIPInfo extracts basic info from SIP message
func extractSIPInfo(payload string) string {
	lines := splitLines(payload)
	if len(lines) > 0 {
		// Return first line (request/response line)
		firstLine := lines[0]
		if len(firstLine) > 60 {
			return firstLine[:60] + "..."
		}
		return firstLine
	}
	return "SIP message"
}

// isDNS checks if the payload might be DNS
func isDNS(payload []byte) bool {
	// Basic DNS check: minimum length and valid flags
	return len(payload) > 12
}

// splitLines splits a string by newlines
func splitLines(s string) []string {
	var lines []string
	var line string
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
		} else {
			line += string(c)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
