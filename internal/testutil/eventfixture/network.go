package eventfixture

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NetworkMessages is a deterministic DHCP discover/offer/retransmit and NTP
// request/reply fixture. Retransmits remain separate observations; endpoints
// intentionally change between DHCP messages.
func NetworkMessages() ([]capture.PacketInfo, error) {
	discover := make([]byte, 240)
	discover[0], discover[1], discover[2] = 1, 1, 6
	binary.BigEndian.PutUint32(discover[4:8], 0x12345678)
	copy(discover[28:34], []byte{0, 17, 34, 51, 68, 85})
	copy(discover[236:240], []byte{99, 130, 83, 99})
	discover = append(discover, 53, 1, 1, 61, 3, 0, 255, 1, 55, 2, 3, 6, 255)
	offer := append([]byte(nil), discover[:240]...)
	offer[0] = 2
	copy(offer[16:20], net.ParseIP("192.0.2.20").To4())
	offer = append(offer, 53, 1, 2, 54, 4, 192, 0, 2, 1, 255)
	request := make([]byte, 48)
	request[0], request[2], request[3] = 0x23, 6, 236
	binary.BigEndian.PutUint64(request[40:48], 0xee43fc0080000000)
	response := append([]byte(nil), request...)
	response[0], response[1] = 0x24, 2
	copy(response[24:32], request[40:48])
	binary.BigEndian.PutUint64(response[40:48], 0xee43fc0090000000)
	type input struct {
		src, dst     string
		sport, dport uint16
		payload      []byte
	}
	inputs := []input{
		{"0.0.0.0", "255.255.255.255", 68, 67, discover},
		{"192.0.2.1", "255.255.255.255", 67, 68, offer},
		{"0.0.0.0", "255.255.255.255", 68, 67, discover},
		{"192.0.2.20", "192.0.2.123", 40000, 123, request},
		{"192.0.2.123", "192.0.2.20", 123, 40000, response},
	}
	var packets []capture.PacketInfo
	for i, in := range inputs {
		packet, err := NetworkDatagram(in.src, in.dst, in.sport, in.dport, in.payload, BaseTime.Add(time.Duration(i)*time.Second))
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	return packets, nil
}

func NetworkDatagram(src, dst string, sport, dport uint16, payload []byte, at time.Time) (capture.PacketInfo, error) {
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return capture.PacketInfo{}, err
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload(payload)); err != nil {
		return capture.PacketInfo{}, err
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "fixture0"}, nil
}
