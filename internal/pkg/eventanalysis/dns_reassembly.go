package eventanalysis

import (
	"encoding/binary"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const minDNSMessageBytes = 12

func (r *Runtime) isDNSPort(port uint16) bool {
	for _, configured := range r.cfg.Policy.EffectiveDNS().Ports {
		if configured == port {
			return true
		}
	}
	return false
}

// rawDNSDatagram accepts complete UDP messages on configured DNS ports or an
// explicit DNS hint. A hint selects validation; it never substitutes for it.
// TCP messages must instead pass through the ordered, length-delimited parser.
func (r *Runtime) rawDNSDatagram(packet gopacket.Packet, hint string) *data.DNSMetadata {
	if packet == nil || packet.Metadata().Truncated {
		return nil
	}
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || hint != "dns" && !r.isDNSPort(uint16(udp.SrcPort)) && !r.isDNSPort(uint16(udp.DstPort)) {
		return nil
	}
	if info := packet.Metadata().CaptureInfo; info.CaptureLength < info.Length {
		return nil
	}
	return r.completeDNSMetadata(udp.Payload)
}

// completeDNSMetadata validates every declared section before using the shared
// parser. ParseRaw deliberately tolerates partial data for other consumers;
// canonical observations must not turn that recovery behavior into evidence.
func (r *Runtime) completeDNSMetadata(payload []byte) *data.DNSMetadata {
	if len(payload) < minDNSMessageBytes {
		return nil
	}
	// The decoder must not extend a short question into spare capacity owned by
	// the following TCP frame. Its slicing checks rely on capacity as well as
	// length; constrain both to this exact message before decoding.
	payload = payload[:len(payload):len(payload)]
	// Use gopacket's normal decode boundary, which turns both decoder errors
	// and decoder panics on malformed questions into a DecodeFailure layer.
	// Calling DNS.DecodeFromBytes directly bypasses that protection.
	decoded := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.NoCopy)
	if decoded.ErrorLayer() != nil || decoded.Layer(layers.LayerTypeDNS) == nil {
		return nil
	}
	return dnsToProto(r.dns.ParseRaw(payload))
}

func (s *applicationStream) isDNSStream(hint string) bool {
	return hint == "dns" || s.protocolHint == "dns" || s.runtime.isDNSPort(flowPort(s.tcpFlow.Src())) || s.runtime.isDNSPort(flowPort(s.tcpFlow.Dst()))
}

// RFC 1035 section 4.2.2 and RFC 7766 section 8 specify a two-octet message
// length that excludes the length field itself. Prefixes and messages may span
// TCP segments, and multiple messages may share a segment. The existing bounded
// assembler owns ordering, retransmission suppression, and capture provenance.
func (s *applicationStream) parseDNS() {
	if s.dnsFramingLost {
		s.consume(len(s.buffer))
		return
	}
	for len(s.buffer) >= 2 {
		length := int(binary.BigEndian.Uint16(s.buffer[:2]))
		end := length + 2 // The wire length bounds a single message to 65,535 bytes.
		if len(s.buffer) < end {
			return
		}
		metadata := s.runtime.completeDNSMetadata(s.buffer[2:end])
		mark := s.contextThrough(end)
		s.consume(end)
		if metadata == nil {
			s.runtime.stats.Invalid++
			s.partial = true
			continue
		}
		s.emitApplication(mark.ctx, mark.ci, &data.PacketMetadata{Dns: metadata})
	}
}
