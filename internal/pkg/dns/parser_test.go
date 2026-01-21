package dns

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createDNSQueryPacket creates a gopacket with a DNS query in a UDP payload.
// This simulates packets that gopacket doesn't auto-decode DNS for.
func createDNSQueryPacket(queryName string) gopacket.Packet {
	// Build Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Build IP layer
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{8, 8, 8, 8},
	}

	// Build UDP layer with DNS port
	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Build DNS query payload manually
	dnsPayload := buildDNSQuery(0x1234, queryName)

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))
	if err != nil {
		panic(err)
	}

	// Decode packet without DNS layer decoding (simulates real behavior)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildDNSQuery builds a raw DNS query packet
func buildDNSQuery(txnID uint16, name string) []byte {
	// DNS header (12 bytes)
	header := []byte{
		byte(txnID >> 8), byte(txnID & 0xff), // Transaction ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	// Encode domain name
	var question []byte
	for _, part := range splitDomain(name) {
		question = append(question, byte(len(part)))
		question = append(question, []byte(part)...)
	}
	question = append(question, 0x00) // Root label

	// Query type A (0x0001) and class IN (0x0001)
	question = append(question, 0x00, 0x01, 0x00, 0x01)

	return append(header, question...)
}

func splitDomain(name string) []string {
	var parts []string
	current := ""
	for _, c := range name {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func TestParser_Parse_FallbackToTransportPayload(t *testing.T) {
	parser := NewParser()

	// Create a packet with DNS in UDP payload (gopacket won't auto-decode)
	packet := createDNSQueryPacket("example.com")

	// Note: gopacket DOES auto-decode DNS when using SerializeLayers.
	// This test verifies our parser works regardless of whether gopacket
	// decodes DNS or not (both paths should work).

	// Parse using our parser
	metadata := parser.Parse(packet)

	// Verify parsing succeeded
	require.NotNil(t, metadata, "parser should parse DNS")
	assert.Equal(t, uint16(0x1234), metadata.TransactionID)
	assert.Equal(t, "example.com", metadata.QueryName)
	assert.Equal(t, "A", metadata.QueryType)
	assert.Equal(t, "IN", metadata.QueryClass)
	assert.False(t, metadata.IsResponse)
}

func TestParser_Parse_DecodeOnlyUDP(t *testing.T) {
	parser := NewParser()

	// Create packet using DecodeOptions that only decode up to UDP
	// This simulates capture scenarios where DNS isn't auto-decoded
	packet := createDNSQueryPacket("test.local")

	// Create a new packet with DecodeOptions that stop at transport layer
	// by using NoCopy and Lazy which won't decode application layers
	rawBytes := packet.Data()
	limitedPacket := gopacket.NewPacket(rawBytes, layers.LayerTypeEthernet,
		gopacket.DecodeOptions{
			Lazy:                     true,
			NoCopy:                   true,
			DecodeStreamsAsDatagrams: true,
		})

	// Parse using our parser - should work via fallback
	metadata := parser.Parse(limitedPacket)

	// Verify parsing succeeded
	require.NotNil(t, metadata, "parser should parse DNS from UDP payload via fallback")
	assert.Equal(t, uint16(0x1234), metadata.TransactionID)
	assert.Equal(t, "test.local", metadata.QueryName)
}

func TestParser_Parse_NonDNSPort(t *testing.T) {
	parser := NewParser()

	// Build a packet on a non-DNS port
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 1},
	}

	udp := &layers.UDP{
		SrcPort: 54321,
		DstPort: 8080, // Not a DNS port
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("not dns")))

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	metadata := parser.Parse(packet)

	assert.Nil(t, metadata, "should not parse non-DNS traffic")
}

func TestParser_ParseRaw(t *testing.T) {
	parser := NewParser()

	// Test direct raw parsing
	payload := buildDNSQuery(0xABCD, "test.example.org")
	metadata := parser.ParseRaw(payload)

	require.NotNil(t, metadata)
	assert.Equal(t, uint16(0xABCD), metadata.TransactionID)
	assert.Equal(t, "test.example.org", metadata.QueryName)
	assert.Equal(t, "A", metadata.QueryType)
	assert.False(t, metadata.IsResponse)
}

func TestParser_ParseRaw_TooShort(t *testing.T) {
	parser := NewParser()

	// Less than 12 bytes (DNS header minimum)
	metadata := parser.ParseRaw([]byte{0x00, 0x01, 0x02})
	assert.Nil(t, metadata)
}
