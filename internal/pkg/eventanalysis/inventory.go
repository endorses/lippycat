package eventanalysis

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/inventory"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// emitConnection publishes only the lifecycle summary. Inventory is derived
// when positive evidence becomes available, independently of connection expiry.
func (r *Runtime) emitConnection(conn events.ConnEvent) {
	conn.LocalOrigin = r.inventory.Local(conn.Envelope().Flow.SourceAddress)
	conn.LocalResponse = r.inventory.Local(conn.Envelope().Flow.DestinationAddress)
	conn.Evidence = events.ConnEvidence{}
	conn.AnalysisScope = ""
	r.emit(conn)
}

// emitInventory is used only by local packet analysis. Event ingress relays
// source-produced inventory without deriving it again from connection events.
func (r *Runtime) emitInventory(conn *events.ConnEvent) {
	if conn == nil {
		return
	}
	proof := conn.Evidence
	derived := r.inventory.Observe(conn.AnalysisScope, r.expiryWatermark, *conn, inventory.Evidence{
		Host: proof.Host, Service: proof.Service, Responder: proof.Responder, Protocol: proof.Protocol,
	})
	for _, event := range derived {
		r.emit(event)
	}
}

// A transported metadata hint cannot invent positive evidence or endpoints.
func packetEvidenceMatches(packet gopacket.Packet, flow events.FlowTuple) bool {
	if packet == nil || packet.ErrorLayer() != nil {
		return false
	}
	var source, destination netip.Addr
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			return false
		}
	case *layers.IPv6:
		source, _ = netip.AddrFromSlice(ip.SrcIP)
		destination, _ = netip.AddrFromSlice(ip.DstIP)
	default:
		return false
	}
	if source.Unmap() != flow.SourceAddress.Unmap() || destination.Unmap() != flow.DestinationAddress.Unmap() {
		return false
	}
	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		return flow.Protocol == 6 && uint16(transport.SrcPort) == flow.SourcePort && uint16(transport.DstPort) == flow.DestinationPort
	case *layers.UDP:
		return flow.Protocol == 17 && uint16(transport.SrcPort) == flow.SourcePort && uint16(transport.DstPort) == flow.DestinationPort
	default:
		return false
	}
}

func (r *Runtime) unicastEndpoints(flow events.FlowTuple) bool {
	for _, address := range []netip.Addr{flow.SourceAddress, flow.DestinationAddress} {
		address = address.Unmap()
		if !r.inventory.Unicast(address) {
			return false
		}
	}
	return true
}

// DNS service proof is independent of transported/cached DNS metadata. Matching
// uses every question and its type/class, not merely the 16-bit transaction ID.
// A fixed-size digest is retained by conntrack; raw query names are not retained.
func (r *Runtime) dnsInventoryEvidence(udp *layers.UDP, env events.Envelope, truncated bool) *conntrack.UDPEvidence {
	if !r.cfg.Policy.Inventory.Enabled || truncated || !r.unicastEndpoints(env.Flow) || (udp.SrcPort != 53 && udp.DstPort != 53) {
		return nil
	}
	var message layers.DNS
	if err := message.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil || message.TC || message.OpCode != layers.DNSOpCodeQuery || len(message.Questions) == 0 || len(message.Questions) > 64 {
		return nil
	}
	hash := sha256.New()
	var numbers [6]byte
	binary.BigEndian.PutUint16(numbers[:2], message.ID)
	binary.BigEndian.PutUint16(numbers[2:4], uint16(len(message.Questions)))
	hash.Write(numbers[:4])
	for _, question := range message.Questions {
		if len(question.Name) == 0 || len(question.Name) > 255 {
			return nil
		}
		binary.BigEndian.PutUint16(numbers[:2], uint16(len(question.Name)))
		binary.BigEndian.PutUint16(numbers[2:4], uint16(question.Type))
		binary.BigEndian.PutUint16(numbers[4:6], uint16(question.Class))
		hash.Write(numbers[:])
		hash.Write([]byte(strings.ToLower(string(question.Name))))
	}
	proof := &conntrack.UDPEvidence{Protocol: "dns", Role: conntrack.UDPRequest, Matched: message.QR}
	copy(proof.Key[:], hash.Sum(nil))
	if message.QR {
		proof.Role = conntrack.UDPResponse
	}
	return proof
}
