//go:build hunter || tap || all

package voip

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildSIPPacketInfo synthesizes a capture.PacketInfo carrying a single
// reassembled SIP message as the application payload of a well-formed
// Ethernet/IP/TCP packet using the connection's real 5-tuple.
//
// This is used by the TCP SIP handlers (tap and hunter) so that each
// reassembled SIP message on a persistent connection is an independently
// matchable + forwardable unit: matching and forwarding operate on THIS
// message rather than on the first raw packet buffered for the whole flow.
//
// The IP addresses come from the network-layer flow (netFlow), which is robust
// for both IPv4 and IPv6; the ports are parsed from the "IP:port" endpoint
// strings. Returns ok=false if the endpoints/addresses cannot be resolved or
// serialization fails.
func buildSIPPacketInfo(sipMessage []byte, srcEndpoint, dstEndpoint string, netFlow gopacket.Flow, ts time.Time) (capture.PacketInfo, bool) {
	srcIP := net.IP(netFlow.Src().Raw())
	dstIP := net.IP(netFlow.Dst().Raw())
	if len(srcIP) == 0 || len(dstIP) == 0 {
		return capture.PacketInfo{}, false
	}

	srcPort, ok1 := endpointPort(srcEndpoint)
	dstPort, ok2 := endpointPort(dstEndpoint)
	if !ok1 || !ok2 {
		return capture.PacketInfo{}, false
	}

	isIPv6 := srcIP.To4() == nil

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		Ack:     1,
		PSH:     true,
		ACK:     true,
		Window:  65535,
	}

	var netLayer gopacket.SerializableLayer
	if isIPv6 {
		ip6 := &layers.IPv6{
			Version:    6,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip6)
		netLayer = ip6
	} else {
		ip4 := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip4)
		netLayer = ip4
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, netLayer, tcp, gopacket.Payload(sipMessage)); err != nil {
		logger.Debug("Failed to synthesize SIP packet for TCP forwarding", "error", err)
		return capture.PacketInfo{}, false
	}

	raw := buf.Bytes()
	pkt := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.Lazy)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(raw),
		Length:        len(raw),
	}
	return capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   pkt,
	}, true
}

// endpointPort extracts the port from an "IP:port" endpoint string. The IP part
// may itself contain colons (IPv6, e.g. "2001:db8::1:5060" or "[2001:db8::1]:5060"),
// so the port is taken as the segment after the LAST colon.
func endpointPort(endpoint string) (uint16, bool) {
	idx := strings.LastIndex(endpoint, ":")
	if idx <= 0 || idx == len(endpoint)-1 {
		return 0, false
	}
	p, err := strconv.ParseUint(endpoint[idx+1:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(p), true
}
