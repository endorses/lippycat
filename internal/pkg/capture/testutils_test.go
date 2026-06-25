package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// Common test utilities shared across all test files

// createTestPacket creates a mock PacketInfo for testing
func createTestPacket() PacketInfo {
	// Create a simple test packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	payload := []byte("test packet data")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}
}

// Mock implementations for reassembly
type MockStreamFactory struct{}

func (m *MockStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	return &MockStream{}
}

type MockStream struct{}

func (m *MockStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	*start = true
	return true
}

func (m *MockStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	// Mock implementation - do nothing
}

func (m *MockStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return true
}
