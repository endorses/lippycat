package detector_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/link"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/network"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

// TestComprehensivePcapDetection tests all protocols through generated PCAP files
func TestComprehensivePcapDetection(t *testing.T) {
	tests := []struct {
		name             string
		pcapFile         string
		expectedProtocol string
		minPackets       int
	}{
		// Application Protocols
		{name: "HTTP Traffic", pcapFile: "http.pcap", expectedProtocol: "HTTP", minPackets: 1},
		{name: "TLS/HTTPS Traffic", pcapFile: "tls.pcap", expectedProtocol: "TLS", minPackets: 1},
		{name: "SSH Traffic", pcapFile: "ssh.pcap", expectedProtocol: "SSH", minPackets: 1},
		{name: "FTP Traffic", pcapFile: "ftp.pcap", expectedProtocol: "FTP", minPackets: 1},
		{name: "SMTP Traffic", pcapFile: "smtp.pcap", expectedProtocol: "SMTP", minPackets: 1},
		{name: "POP3 Traffic", pcapFile: "pop3.pcap", expectedProtocol: "POP3", minPackets: 1},
		{name: "IMAP Traffic", pcapFile: "imap.pcap", expectedProtocol: "IMAP", minPackets: 1},
		{name: "Telnet Traffic", pcapFile: "telnet.pcap", expectedProtocol: "Telnet", minPackets: 1},
		{name: "WebSocket Traffic", pcapFile: "websocket.pcap", expectedProtocol: "WebSocket", minPackets: 1},

		// Database Protocols
		{name: "MySQL Traffic", pcapFile: "mysql.pcap", expectedProtocol: "MySQL", minPackets: 1},
		{name: "PostgreSQL Traffic", pcapFile: "postgresql.pcap", expectedProtocol: "PostgreSQL", minPackets: 1},
		{name: "MongoDB Traffic", pcapFile: "mongodb.pcap", expectedProtocol: "MongoDB", minPackets: 1},
		{name: "Redis Traffic", pcapFile: "redis.pcap", expectedProtocol: "Redis", minPackets: 1},

		// VoIP Protocols
		{name: "DNS Traffic", pcapFile: "dns.pcap", expectedProtocol: "DNS", minPackets: 1},
		{name: "RTP Traffic", pcapFile: "rtp.pcap", expectedProtocol: "RTP", minPackets: 100},
		{name: "SIP Traffic", pcapFile: "sip.pcap", expectedProtocol: "SIP", minPackets: 1},

		// VPN Protocols
		{name: "WireGuard Traffic", pcapFile: "wireguard.pcap", expectedProtocol: "WireGuard", minPackets: 1},
		{name: "OpenVPN Traffic", pcapFile: "openvpn.pcap", expectedProtocol: "OpenVPN", minPackets: 1},
		{name: "L2TP Traffic", pcapFile: "l2tp.pcap", expectedProtocol: "L2TP", minPackets: 1},
		{name: "IKEv2 Traffic", pcapFile: "ikev2.pcap", expectedProtocol: "IKEv2", minPackets: 1},
		{name: "PPTP Traffic", pcapFile: "pptp.pcap", expectedProtocol: "PPTP", minPackets: 1},

		// Network Protocols
		{name: "ARP Traffic", pcapFile: "arp.pcap", expectedProtocol: "ARP", minPackets: 1},
		{name: "DHCP Traffic", pcapFile: "dhcp.pcap", expectedProtocol: "DHCP", minPackets: 1},
		{name: "ICMP Traffic", pcapFile: "icmp.pcap", expectedProtocol: "ICMP", minPackets: 1},
		{name: "NTP Traffic", pcapFile: "ntp.pcap", expectedProtocol: "NTP", minPackets: 1},
		{name: "SNMP Traffic", pcapFile: "snmp.pcap", expectedProtocol: "SNMP", minPackets: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcapPath := writeDetectorPCAP(t, tt.pcapFile)
			det := createComprehensiveDetector()
			t.Cleanup(det.Shutdown)

			handle, err := pcap.OpenOffline(pcapPath)
			if err != nil {
				t.Fatalf("Failed to open PCAP: %v", err)
			}
			defer handle.Close()

			total := 0
			protocolCounts := make(map[string]int)

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				total++
				require.Nil(t, packet.ErrorLayer(), "Fixture packet %d must decode successfully", total)
				result := det.Detect(packet)
				if result != nil && result.Protocol != "unknown" {
					protocolCounts[result.Protocol]++
				}
			}

			// Every generated packet belongs to the expected protocol.
			count, found := protocolCounts[tt.expectedProtocol]
			require.True(t, found, "Expected %s; total packets: %d, detected: %+v", tt.expectedProtocol, total, protocolCounts)
			assert.Equal(t, total, count, "All fixture packets should be detected as %s", tt.expectedProtocol)

			// Verify minimum packet count
			assert.GreaterOrEqual(t, count, tt.minPackets,
				"Expected at least %d %s packets, got %d", tt.minPackets, tt.expectedProtocol, count)

			t.Logf("✓ %s: %d/%d packets detected", tt.expectedProtocol, count, total)
		})
	}
}

// createComprehensiveDetector creates a detector with all available signatures
func createComprehensiveDetector() *detector.Detector {
	det := detector.New()

	// Application
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())
	det.RegisterSignature(application.NewTLSSignature())
	det.RegisterSignature(application.NewSSHSignature())
	det.RegisterSignature(application.NewFTPSignature())
	det.RegisterSignature(application.NewSMTPSignature())
	det.RegisterSignature(application.NewPOP3Signature())
	det.RegisterSignature(application.NewIMAPSignature())
	det.RegisterSignature(application.NewTelnetSignature())
	det.RegisterSignature(application.NewGRPCSignature())
	det.RegisterSignature(application.NewWebSocketSignature())

	// Database (in application package)
	det.RegisterSignature(application.NewMySQLSignature())
	det.RegisterSignature(application.NewPostgreSQLSignature())
	det.RegisterSignature(application.NewMongoDBSignature())
	det.RegisterSignature(application.NewRedisSignature())

	// Network/Application layer
	det.RegisterSignature(application.NewDHCPSignature())
	det.RegisterSignature(application.NewNTPSignature())
	det.RegisterSignature(application.NewSNMPSignature())

	// VoIP
	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(voip.NewRTPSignature())

	// VPN
	det.RegisterSignature(vpn.NewWireGuardSignature())
	det.RegisterSignature(vpn.NewOpenVPNSignature())
	det.RegisterSignature(vpn.NewL2TPSignature())
	det.RegisterSignature(vpn.NewIKEv2Signature())
	det.RegisterSignature(vpn.NewPPTPSignature())

	// Network
	det.RegisterSignature(network.NewICMPSignature())

	// Link layer
	det.RegisterSignature(link.NewARPSignature())

	return det
}
