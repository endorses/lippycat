package eventfixture

import (
	"fmt"
	"net"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	BaseTime    = time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	HTTPPayload = []byte("GET /phase4 HTTP/1.1\r\nHost: parity.example.test\r\n\r\n")
)

// SegmentedHTTP returns one SYN and two contiguous data segments. Neither data
// segment is independently a complete HTTP message.
func SegmentedHTTP() ([]capture.PacketInfo, error) {
	split := 31
	parts := [][]byte{nil, HTTPPayload[:split], HTTPPayload[split:]}
	seqs := []uint32{1000, 1001, 1001 + uint32(split)}
	result := make([]capture.PacketInfo, 0, len(parts))
	for i, payload := range parts {
		packet, err := tcpPacket(payload, seqs[i], i == 0, BaseTime.Add(time.Duration(i)*time.Second))
		if err != nil {
			return nil, err
		}
		result = append(result, packet)
	}
	return result, nil
}

func Envelopes(kind pipeline.SourceKind, source string) ([]*pipeline.PacketEnvelope, error) {
	packets, err := SegmentedHTTP()
	if err != nil {
		return nil, err
	}
	result := make([]*pipeline.PacketEnvelope, 0, len(packets))
	for _, info := range packets {
		ci := info.Packet.Metadata().CaptureInfo
		provenance := pipeline.SourceProvenance{Kind: kind, InterfaceName: source}
		if kind == pipeline.SourcePCAPReplay {
			provenance.InputFile = source
		}
		result = append(result, &pipeline.PacketEnvelope{Data: append([]byte(nil), info.Packet.Data()...), LinkType: info.LinkType, CaptureTime: ci.Timestamp, CaptureLength: ci.CaptureLength, OriginalLength: ci.Length, Source: provenance})
	}
	return result, nil
}

func Captured() ([]*data.CapturedPacket, error) {
	packets, err := SegmentedHTTP()
	if err != nil {
		return nil, err
	}
	result := make([]*data.CapturedPacket, 0, len(packets))
	for _, info := range packets {
		tcp := info.Packet.TransportLayer().(*layers.TCP)
		network := info.Packet.NetworkLayer().NetworkFlow()
		result = append(result, &data.CapturedPacket{
			Data: append([]byte(nil), info.Packet.Data()...), TimestampNs: info.Packet.Metadata().Timestamp.UnixNano(), LinkType: uint32(info.LinkType),
			Metadata: &data.PacketMetadata{SrcIp: network.Src().String(), DstIp: network.Dst().String(), SrcPort: uint32(tcp.SrcPort), DstPort: uint32(tcp.DstPort), Transport: "tcp", Protocol: "HTTP"},
		})
	}
	return result, nil
}

func tcpPacket(payload []byte, seq uint32, syn bool, timestamp time.Time) (capture.PacketInfo, error) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: seq, SYN: syn, ACK: !syn, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return capture.PacketInfo{}, fmt.Errorf("set TCP checksum layer: %w", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return capture.PacketInfo{}, fmt.Errorf("serialize TCP fixture: %w", err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "fixture"}, nil
}
