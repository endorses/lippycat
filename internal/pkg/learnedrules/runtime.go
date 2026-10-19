package learnedrules

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Runtime is shared by remote sources and in-process tap subscriptions. Adapter
// registration, not a protocol-mode flag, determines which bindings it supports.
type Runtime struct {
	Store           *Store
	interfaces      map[string]DomainID
	maxCandidates   int
	projectionReady func(uint64) bool
}

func (r *Runtime) Domain(iface string) (DomainID, bool) {
	domain, ok := r.interfaces[iface]
	return domain, ok
}

func NewRuntime(config Config, interfaces map[string]DomainID, maxCandidates int, projectionReady func(uint64) bool) (*Runtime, error) {
	if len(interfaces) == 0 || maxCandidates <= 0 || maxCandidates > config.MaxRules {
		return nil, ErrInvalid
	}
	for name, domain := range interfaces {
		if name == "" {
			return nil, ErrScope
		}
		found := false
		for _, allowed := range config.Domains {
			if domain == allowed {
				found = true
			}
		}
		if !found {
			return nil, ErrScope
		}
	}
	s, err := New(config)
	if err != nil {
		return nil, err
	}
	r := &Runtime{Store: s, interfaces: make(map[string]DomainID, len(interfaces)), maxCandidates: maxCandidates, projectionReady: projectionReady}
	for name, domain := range interfaces {
		r.interfaces[name] = domain
	}
	return r, nil
}

// PacketFacts accepts only complete transport headers. Fragmented packets cannot
// establish endpoint selection through an inferred transport association.
func PacketFacts(packet gopacket.Packet, domain DomainID) (Packet, bool) {
	if packet == nil || packet.NetworkLayer() == nil {
		return Packet{}, false
	}
	// Application decoders also set Metadata.Truncated (for example, a short
	// non-SIP payload on port 5060). Endpoint selection depends on complete IP
	// and transport data, independently of application interpretation.
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 || ip.IHL < 5 || len(ip.Contents) != int(ip.IHL)*4 || int(ip.Length) > len(ip.Contents)+len(ip.Payload) {
			return Packet{}, false
		}
	case *layers.IPv6:
		if !completeIPv6Payload(ip) {
			return Packet{}, false
		}
	default:
		return Packet{}, false
	}
	if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		return Packet{}, false
	}
	src, e1 := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Src().String())
	dst, e2 := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Dst().String())
	if e1 != nil || e2 != nil {
		return Packet{}, false
	}
	p := Packet{Domain: domain, Source: Endpoint{Address: src.Unmap()}, Destination: Endpoint{Address: dst.Unmap()}}
	switch transport := packet.TransportLayer().(type) {
	case *layers.UDP:
		if len(transport.Contents) != 8 || (transport.Length != 0 && (transport.Length < 8 || int(transport.Length) > len(transport.Contents)+len(transport.Payload))) {
			return Packet{}, false
		}
		p.Protocol, p.Source.Port, p.Destination.Port, p.Payload = UDP, uint16(transport.SrcPort), uint16(transport.DstPort), transport.Payload
	case *layers.TCP:
		if transport.DataOffset < 5 || len(transport.Contents) != int(transport.DataOffset)*4 {
			return Packet{}, false
		}
		p.Protocol, p.Source.Port, p.Destination.Port, p.Payload = TCP, uint16(transport.SrcPort), uint16(transport.DstPort), transport.Payload
	default:
		return Packet{}, false
	}
	return p, true
}

func completeIPv6Payload(ip *layers.IPv6) bool {
	if len(ip.Contents) != 40 {
		return false
	}
	length := uint64(ip.Length)
	captured := uint64(len(ip.Payload))
	if ip.Length == 0 {
		if ip.HopByHop == nil {
			return false
		}
		for _, option := range ip.HopByHop.Options {
			if option.OptionType == layers.IPv6HopByHopOptionJumbogram {
				if length != 0 || len(option.OptionData) != 4 {
					return false
				}
				length = uint64(binary.BigEndian.Uint32(option.OptionData))
			}
		}
		if length <= 65535 {
			return false
		}
	} else if ip.HopByHop != nil {
		// Gopacket removes a non-jumbo hop-by-hop header from IPv6.Payload,
		// while the advertised IPv6 length still includes that header.
		captured += uint64(ip.HopByHop.ActualLength)
	}
	return length <= captured
}

func (r *Runtime) Match(packet gopacket.Packet, iface string) Candidates {
	domain, ok := r.interfaces[iface]
	if !ok {
		return Candidates{}
	}
	state := r.Store.Status()
	if !state.Ready || r.projectionReady != nil && !r.projectionReady(state.Sequence) {
		return Candidates{}
	}
	facts, ok := PacketFacts(packet, domain)
	if !ok {
		return Candidates{}
	}
	result := r.Store.Match(facts, r.maxCandidates)
	// A concurrent replacement cannot turn candidates from an old complete
	// projection into evidence for the newly installed generation.
	if r.Store.Status().Sequence != state.Sequence {
		return Candidates{}
	}
	return result
}
