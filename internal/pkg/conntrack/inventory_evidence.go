package conntrack

import (
	"net/netip"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
)

type UDPRole uint8

const (
	UDPRequest UDPRole = iota + 1
	UDPResponse
)

// UDPEvidence is supplied only by fresh, complete protocol decoding. Key is a
// digest of the parsed transaction, never a port hint or detector cache label.
// Matched is required for responses in addition to our same-flow request check.
type UDPEvidence struct {
	Protocol string
	Role     UDPRole
	Key      [32]byte
	Matched  bool
}

const inventoryRequestSlots = 8

type udpRequest struct {
	key      [32]byte
	protocol uint8
	source   netip.AddrPort
	at       time.Time
}

type inventoryProof struct {
	requestTimeout          time.Duration
	watermark               time.Time
	host                    events.InventoryEvidence
	service                 events.InventoryEvidence
	protocol                string
	responder               netip.AddrPort
	serviceAmbiguous        bool
	udpSeen                 [2]bool
	udpRequests             [inventoryRequestSlots]udpRequest
	nextUDP                 uint8
	tcpStage                uint8
	tcpOrigin, tcpResponder netip.AddrPort
	clientNext, serverNext  uint32
	analyzedService         string
}

func endpoints(f events.FlowTuple) (netip.AddrPort, netip.AddrPort) {
	return netip.AddrPortFrom(f.SourceAddress.Unmap(), f.SourcePort), netip.AddrPortFrom(f.DestinationAddress.Unmap(), f.DestinationPort)
}

func (f *flow) observeInventory(o Observation, at time.Time) {
	if !o.InventoryEligible {
		return
	}
	if f.inventory == nil {
		f.inventory = &inventoryProof{}
	}
	p := f.inventory
	if at.Before(p.watermark) {
		return
	}
	p.watermark = at
	source, dest := endpoints(o.Envelope.Flow)
	if o.Envelope.Flow.Protocol == flowid.ProtocolTCP {
		p.observeTCP(source, dest, o.TCP, o.PayloadBytes)
		return
	}
	if o.Envelope.Flow.Protocol != flowid.ProtocolUDP {
		return
	}
	dir := 0
	origin, _ := endpoints(f.orig)
	if source != origin {
		dir = 1
	}
	p.udpSeen[dir] = true
	if p.udpSeen[0] && p.udpSeen[1] {
		p.host = events.EvidenceUDPBidirectional
	}
	u := o.UDP
	if u == nil || !unicastServiceEndpoint(source) || !unicastServiceEndpoint(dest) || source == dest {
		return
	}
	protocol, evidence := udpProtocol(u.Protocol)
	if protocol == 0 {
		return
	}
	if u.Role == UDPRequest {
		for i := range p.udpRequests {
			r := &p.udpRequests[i]
			if r.protocol == protocol && r.key == u.Key && r.source == source {
				r.at = at
				return
			}
		}
		p.udpRequests[p.nextUDP] = udpRequest{key: u.Key, protocol: protocol, source: source, at: at}
		p.nextUDP = (p.nextUDP + 1) % inventoryRequestSlots
		return
	}
	if u.Role != UDPResponse || !u.Matched {
		return
	}
	for _, r := range p.udpRequests {
		if p.requestTimeout > 0 && !at.Before(r.at.Add(p.requestTimeout)) {
			continue
		}
		if r.protocol == protocol && r.key == u.Key && r.source == dest && !at.Before(r.at) {
			if p.service != "" && (p.responder != source || p.protocol != strings.ToLower(u.Protocol)) {
				p.serviceAmbiguous = true
			}
			if !p.serviceAmbiguous {
				p.service = evidence
				p.protocol = strings.ToLower(u.Protocol)
				p.responder = source
			}
			return
		}
	}
}

func unicastServiceEndpoint(a netip.AddrPort) bool {
	address := a.Addr().Unmap()
	// Link-local unicast is eligible when the explicit inventory policy includes
	// it. Capture scope/interface separates overlapping link-local networks.
	// The inventory policy additionally excludes configured directed broadcasts.
	return a.IsValid() && a.Port() != 0 && !address.IsUnspecified() && !address.IsMulticast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
func udpProtocol(protocol string) (uint8, events.InventoryEvidence) {
	switch strings.ToLower(protocol) {
	case "dns":
		return 1, events.EvidenceDNSExchange
	case "ntp":
		return 2, events.EvidenceNTPExchange
	case "dhcp":
		return 3, events.EvidenceDHCPExchange
	default:
		return 0, ""
	}
}

func (p *inventoryProof) observeTCP(source, dest netip.AddrPort, tcp *TCPFlags, payload uint64) {
	if tcp == nil || !tcp.SequenceValid || payload > uint64(^uint32(0)) {
		return
	}
	if p.host == events.EvidenceTCPHandshake {
		return
	}
	if tcp.RST || tcp.FIN {
		p.tcpStage = 0
		return
	}
	if tcp.SYN && !tcp.ACK {
		next := tcp.Sequence + 1 + uint32(payload)
		// An identical retransmitted SYN cannot erase a valid SYN/ACK already seen.
		if p.tcpStage != 0 && p.tcpOrigin == source && p.tcpResponder == dest && p.clientNext == next {
			return
		}
		p.tcpOrigin, p.tcpResponder = source, dest
		p.clientNext = next
		p.tcpStage = 1
		return
	}
	if tcp.SYN && tcp.ACK && p.tcpStage >= 1 && source == p.tcpResponder && dest == p.tcpOrigin && tcp.Acknowledgment == p.clientNext {
		p.serverNext = tcp.Sequence + 1 + uint32(payload)
		p.tcpStage = 2
		return
	}
	if !tcp.SYN && tcp.ACK && p.tcpStage == 2 && source == p.tcpOrigin && dest == p.tcpResponder && tcp.Sequence == p.clientNext && tcp.Acknowledgment == p.serverNext {
		p.host = events.EvidenceTCPHandshake
	}
}

func (p *inventoryProof) evidence() events.ConnEvidence {
	if p == nil {
		return events.ConnEvidence{}
	}
	e := events.ConnEvidence{Host: p.host}
	if p.host == events.EvidenceTCPHandshake && p.analyzedService != "" && unicastServiceEndpoint(p.tcpResponder) {
		e.Service = events.EvidenceTCPHandshake
		e.Responder = p.tcpResponder
		e.Protocol = p.analyzedService
	} else if p.host == events.EvidenceUDPBidirectional && !p.serviceAmbiguous {
		e.Service = p.service
		e.Responder = p.responder
		e.Protocol = p.protocol
	}
	return e
}

// SetAnalyzedService records positive TCP parser evidence only from eligible
// input in the same analysis epoch. Generic SetService and Observation.Service
// remain display labels and can never prove a known service.
func (t *Tracker) SetAnalyzedService(env events.Envelope, scope, service string, eligible bool) error {
	key, err := flowid.Normalize(env.Flow)
	if err != nil {
		return err
	}
	tk := trackerKeyForEnvelope(key, env, scope)
	s := t.shardFor(tk)
	s.Lock()
	defer s.Unlock()
	f := s.flows[tk]
	if f == nil {
		return nil
	}
	f.service = service
	service = strings.ToLower(service)
	if f.inventory == nil || !eligible || env.Flow.Protocol != flowid.ProtocolTCP || env.Timestamp.Before(f.inventory.watermark) {
		return nil
	}
	switch service {
	case "http", "tls", "smtp":
		f.inventory.analyzedService = service
	}
	return nil
}

// InventoryObservation snapshots the proof available for a still-active flow.
// It leaves accounting and lifecycle state unchanged.
func (t *Tracker) InventoryObservation(env events.Envelope, scope string) (*events.ConnEvent, error) {
	key, err := flowid.Normalize(env.Flow)
	if err != nil {
		return nil, err
	}
	tk := trackerKeyForEnvelope(key, env, scope)
	s := t.shardFor(tk)
	s.Lock()
	defer s.Unlock()
	if f := s.flows[tk]; f != nil {
		return f.inventoryObservation(), nil
	}
	return nil, nil
}

func (f *flow) inventoryObservation() *events.ConnEvent {
	if proof := f.inventory.evidence(); proof.Host == "" && proof.Service == "" {
		return nil
	}
	event := f.event()
	return &event
}
