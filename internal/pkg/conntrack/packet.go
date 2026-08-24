package conntrack

import (
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FromPacket builds an observation from decoded packet layers.
func FromPacket(packet gopacket.Packet, env events.Envelope, service string) Observation {
	o := Observation{Envelope: env, Service: service}
	if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		o.IPBytes = uint64(ip.Length)
	}
	if ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		o.IPBytes = uint64(ip.Length) + 40
	}
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		o.PayloadBytes = uint64(len(tcp.Payload))
		o.TCP = &TCPFlags{SYN: tcp.SYN, ACK: tcp.ACK, FIN: tcp.FIN, RST: tcp.RST}
	}
	if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		o.PayloadBytes = uint64(len(udp.Payload))
	}
	if o.IPBytes == 0 && packet.NetworkLayer() != nil {
		o.IPBytes = uint64(len(packet.NetworkLayer().LayerContents()) + len(packet.NetworkLayer().LayerPayload()))
	}
	return o
}
