package detector_test

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// writeDetectorPCAP creates a deterministic Ethernet capture owned by the test.
// Fixtures exercise the offline reader and packet decoding without downloaded
// captures or an ignored testdata directory.
func writeDetectorPCAP(tb testing.TB, name string) string {
	tb.Helper()
	packets := detectorFixturePackets(tb, name)
	path := filepath.Join(tb.TempDir(), name)
	file, err := os.Create(path)
	require.NoError(tb, err)
	defer func() { require.NoError(tb, file.Close()) }()
	writer := pcapgo.NewWriter(file)
	require.NoError(tb, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, packet := range packets {
		data := packet.Data()
		require.NoError(tb, writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(1700000000, 0).Add(time.Duration(i) * 20 * time.Millisecond),
			CaptureLength: len(data), Length: len(data),
		}, data))
	}
	return path
}

func detectorFixturePackets(tb testing.TB, name string) []gopacket.Packet {
	tb.Helper()
	one := func(packet gopacket.Packet) []gopacket.Packet { return []gopacket.Packet{packet} }
	tcp := func(port uint16, payload string) []gopacket.Packet {
		return one(serializeTCP(10, 40000, port, []byte(payload)))
	}
	udp := func(port uint16, payload []byte) []gopacket.Packet {
		return one(serializeUDP(10, 40000, port, payload))
	}
	switch name {
	case "dns.pcap":
		return one(createDNSPacket(0))
	case "http.pcap":
		return one(createHTTPPacket(1))
	case "tls.pcap":
		// TLS 1.2 ClientHello: random, empty session ID, one cipher, null compression.
		payload := make([]byte, 50)
		copy(payload, []byte{0x16, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3})
		copy(payload[11:43], []byte("deterministic-client-hello-random!"))
		copy(payload[43:], []byte{0, 0, 2, 0, 0x2f, 1, 0})
		return one(serializeTCP(2, 40000, 443, payload))
	case "rtp.pcap":
		packets := make([]gopacket.Packet, 120)
		for i := range packets {
			payload := make([]byte, 172) // RTP header plus 20 ms of PCMU audio.
			payload[0] = 0x80
			binary.BigEndian.PutUint16(payload[2:4], uint16(i+1))
			binary.BigEndian.PutUint32(payload[4:8], uint32(i*160))
			binary.BigEndian.PutUint32(payload[8:12], 0x12345678)
			for j := 12; j < len(payload); j++ {
				payload[j] = 0xff
			}
			packets[i] = serializeUDP(3, 20000, 21000, payload)
		}
		return packets
	case "mixed.pcap":
		packets := []gopacket.Packet{createDNSPacket(0), createHTTPPacket(1)}
		return append(packets, detectorFixturePackets(tb, "rtp.pcap")...)
	case "ssh.pcap":
		return tcp(22, "SSH-2.0-OpenSSH_9.0\r\n")
	case "ftp.pcap":
		return tcp(21, "USER fixture\r\n")
	case "smtp.pcap":
		return tcp(25, "EHLO example.invalid\r\n")
	case "pop3.pcap":
		return tcp(110, "+OK POP3 server ready\r\n")
	case "imap.pcap":
		return tcp(143, "* OK IMAP4rev1 server ready\r\n")
	case "telnet.pcap":
		return tcp(23, "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18")
	case "websocket.pcap":
		// Use a nonstandard port to exercise signature priority rather than the HTTP port hint.
		return tcp(9000, "GET /chat HTTP/1.1\r\nHost: example.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	case "mysql.pcap":
		return tcp(3306, "\x0a\x00\x00\x00\x03SELECT 1;")
	case "postgresql.pcap":
		return tcp(5432, "\x00\x00\x00\x16\x00\x03\x00\x00user\x00fixture\x00\x00")
	case "mongodb.pcap":
		// OP_MSG header, flags, and a kind-0 empty BSON document.
		payload := make([]byte, 26)
		binary.LittleEndian.PutUint32(payload[0:4], uint32(len(payload)))
		binary.LittleEndian.PutUint32(payload[4:8], 1)
		binary.LittleEndian.PutUint32(payload[12:16], 2013)
		payload[21] = 5
		return one(serializeTCP(10, 40000, 27017, payload))
	case "redis.pcap":
		return tcp(6379, "*1\r\n$4\r\nPING\r\n")
	case "sip.pcap":
		return udp(5060, []byte("INVITE sip:bob@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKfixture\r\nFrom: <sip:alice@example.invalid>;tag=1\r\nTo: <sip:bob@example.invalid>\r\nCall-ID: fixture@example.invalid\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))
	case "wireguard.pcap":
		payload := make([]byte, 148)
		payload[0], payload[4] = 1, 1
		return udp(51820, payload)
	case "openvpn.pcap":
		payload := make([]byte, 14)
		payload[0] = 0x38 // Hard reset client with zero initial session ID.
		return udp(1194, payload)
	case "l2tp.pcap":
		// Control header with length and sequence numbers, SCCRQ Message Type AVP.
		return udp(1701, []byte{0xc8, 2, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 8, 0, 0, 0, 0, 0, 1})
	case "ikev2.pcap":
		payload := make([]byte, 28)
		payload[0], payload[17], payload[18], payload[19] = 0x81, 0x20, 37, 8
		binary.BigEndian.PutUint32(payload[24:28], uint32(len(payload)))
		return udp(500, payload)
	case "pptp.pcap":
		// Start-Control-Connection-Request with its complete 156-byte body.
		payload := make([]byte, 156)
		copy(payload, []byte{0, 156, 0, 1, 0x1a, 0x2b, 0x3c, 0x4d, 0, 1, 0, 0, 1, 0})
		binary.BigEndian.PutUint32(payload[16:20], 3) // Async and sync framing.
		binary.BigEndian.PutUint32(payload[20:24], 3) // Analog and digital bearers.
		copy(payload[28:92], "fixture.example.invalid")
		copy(payload[92:], "lippycat")
		return one(serializeTCP(10, 40000, 1723, payload))
	case "dhcp.pcap":
		payload := make([]byte, 244)
		copy(payload, []byte{1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78})
		copy(payload[28:34], []byte{2, 0, 0, 0, 0, 1})
		copy(payload[236:], []byte{0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255})
		return one(serializeUDP(10, 68, 67, payload))
	case "ntp.pcap":
		payload := make([]byte, 48)
		payload[0], payload[2], payload[3] = 0x23, 6, 0xec
		binary.BigEndian.PutUint32(payload[40:44], 3900000000)
		return udp(123, payload)
	case "snmp.pcap":
		return udp(161, []byte{0x30, 0x26, 2, 1, 1, 4, 6, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 2, 1, 1, 2, 1, 0, 2, 1, 0, 0x30, 0x0e, 0x30, 0x0c, 6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0, 5, 0})
	case "arp.pcap":
		ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP}
		arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
			SourceHwAddress: ethernet.SrcMAC, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 0, 2, 2}}
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(tb, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, arp))
		return one(gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	case "icmp.pcap":
		ip := benchmarkIPv4(10)
		ip.Protocol = layers.IPProtocolICMPv4
		return one(serializePacket(ip, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: 1}, []byte("fixture")))
	default:
		tb.Fatalf("unknown detector PCAP fixture %q", name)
		return nil
	}
}
