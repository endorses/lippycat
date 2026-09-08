package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ErrFragmented identifies datagrams excluded by the no-reassembly profile.
var ErrFragmented = errors.New("fragmented RADIUS capture")

// DecodePacket is a pure decoder: downstream revalidation does not increment
// counters. Only a first-ingress owner should count its returned outcome. The
// returned observation owns the complete captured packet, including padding,
// even on rejection; rejected observations contain no message or identity.
// Scope is caller-supplied provenance, not authenticated by this decoder.
// Additional ports augment (never replace) UDP 1812 and 1813.
func DecodePacket(data []byte, linkType layers.LinkType, capture gopacket.CaptureInfo, scope CaptureScope, id Identity, additionalPorts ...uint16) (*Observation, Outcome, error) {
	o := &Observation{
		Packet: append([]byte(nil), data...), Scope: scope,
		Capture: CaptureInfo{Timestamp: capture.Timestamp.UTC(), LinkType: linkType,
			CapturedLength: capture.CaptureLength, OriginalLength: capture.Length, ID: id},
	}
	udp, endpoints, err := packetUDP(o.Packet, linkType)
	if err != nil {
		return o, packetOutcome(err), err
	}
	if capture.CaptureLength != len(data) || capture.Length < capture.CaptureLength || capture.CaptureLength < capture.Length {
		return o, OutcomeMalformed, fmt.Errorf("capture lengths %d/%d for %d bytes: %w", capture.CaptureLength, capture.Length, len(data), ErrMalformed)
	}
	if len(udp) < 8 {
		return o, OutcomeMalformed, fmt.Errorf("short UDP header: %w", ErrMalformed)
	}
	src, dst := binary.BigEndian.Uint16(udp[:2]), binary.BigEndian.Uint16(udp[2:4])
	if !servicePort(src, additionalPorts) && !servicePort(dst, additionalPorts) {
		return o, OutcomeUnsupported, fmt.Errorf("UDP ports outside configured RADIUS scope: %w", ErrUnsupported)
	}
	n := int(binary.BigEndian.Uint16(udp[4:6]))
	if n < 8 || n != len(udp) {
		return o, OutcomeMalformed, fmt.Errorf("UDP length %d differs from IP payload %d: %w", n, len(udp), ErrMalformed)
	}
	m, err := Decode(udp[8:n])
	if err != nil {
		return o, packetOutcome(err), err
	}
	endpoints.Source = netip.AddrPortFrom(endpoints.Source.Addr(), src)
	endpoints.Destination = netip.AddrPortFrom(endpoints.Destination.Addr(), dst)
	endpoints.Client, endpoints.Server = endpoints.Source, endpoints.Destination
	if m.Code != 1 && m.Code != 4 {
		endpoints.Client, endpoints.Server = endpoints.Destination, endpoints.Source
	}
	o.Endpoints, o.Message, o.NAS = endpoints, m, nasIdentity(m)
	o.Association.Status = AssociationUnprocessed
	return o, OutcomeValid, nil
}

func servicePort(port uint16, additional []uint16) bool {
	if port == 1812 || port == 1813 {
		return true
	}
	for _, p := range additional {
		if p != 0 && p == port {
			return true
		}
	}
	return false
}

func packetOutcome(err error) Outcome {
	switch {
	case errors.Is(err, ErrFragmented):
		return OutcomeFragmented
	case errors.Is(err, ErrUnsupported):
		return OutcomeUnsupported
	default:
		return OutcomeMalformed
	}
}

// Use gopacket only to locate the network header. Inspect the original IP bytes
// ourselves: its IPv6 hop-by-hop decoder adjusts Payload and the default UDP
// port decoder may reject padding that is legal for RADIUS.
func packetUDP(data []byte, linkType layers.LinkType) ([]byte, Endpoints, error) {
	if len(data) == 0 {
		return nil, Endpoints{}, fmt.Errorf("empty capture: %w", ErrMalformed)
	}
	p := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	offset := 0
	for _, layer := range p.Layers() {
		switch layer.LayerType() {
		case layers.LayerTypeIPv4:
			return ipv4UDP(data[offset:])
		case layers.LayerTypeIPv6:
			return ipv6UDP(data[offset:])
		case gopacket.LayerTypeDecodeFailure:
			return nil, Endpoints{}, fmt.Errorf("link/network decode: %w", ErrMalformed)
		}
		offset += len(layer.LayerContents())
		if offset > len(data) {
			return nil, Endpoints{}, fmt.Errorf("network offset: %w", ErrMalformed)
		}
	}
	return nil, Endpoints{}, fmt.Errorf("non-IP capture: %w", ErrUnsupported)
}

func ipv4UDP(b []byte) ([]byte, Endpoints, error) {
	var e Endpoints
	if len(b) < 20 {
		return nil, e, fmt.Errorf("short IPv4 header: %w", ErrMalformed)
	}
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return nil, e, ErrFragmented
	}
	h, n := int(b[0]&15)*4, int(binary.BigEndian.Uint16(b[2:4]))
	if b[0]>>4 != 4 || h < 20 || n < h || n > len(b) {
		return nil, e, fmt.Errorf("IPv4 lengths: %w", ErrMalformed)
	}
	if b[9] != 17 {
		return nil, e, fmt.Errorf("non-UDP IPv4: %w", ErrUnsupported)
	}
	if err := validateIPv4Options(b[20:h]); err != nil {
		return nil, e, err
	}
	e.IPFamily = 4
	e.Source = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), 0)
	e.Destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[16:20])), 0)
	return b[h:n], e, nil
}

func ipv6UDP(b []byte) ([]byte, Endpoints, error) {
	var e Endpoints
	if len(b) < 40 || b[0]>>4 != 6 {
		return nil, e, fmt.Errorf("short/invalid IPv6 header: %w", ErrMalformed)
	}
	n, next, pos := 40+int(binary.BigEndian.Uint16(b[4:6])), b[6], 40
	// Walk only the declared packet, but recognize a visible Fragment header
	// before classifying datagram truncation (including atomic fragments).
	limit := min(n, len(b))
	var optionErr error
	for {
		if next == 44 {
			return nil, e, ErrFragmented
		}
		switch next {
		case 0, 43, 60, 51:
			if pos+2 > limit {
				return nil, e, fmt.Errorf("short IPv6 extension: %w", ErrMalformed)
			}
			size := (int(b[pos+1]) + 1) * 8
			if next == 51 {
				size = (int(b[pos+1]) + 2) * 4
				if size < 12 {
					return nil, e, fmt.Errorf("short IPv6 authentication header: %w", ErrMalformed)
				}
			}
			if size < 8 || pos+size > limit {
				return nil, e, fmt.Errorf("IPv6 extension length: %w", ErrMalformed)
			}
			if (next == 0 || next == 60) && optionErr == nil {
				optionErr = validateIPv6Options(b[pos+2 : pos+size])
			}
			next, pos = b[pos], pos+size
		default:
			if optionErr != nil {
				return nil, e, optionErr
			}
			if n == 40 {
				return nil, e, fmt.Errorf("IPv6 jumbogram/empty payload: %w", ErrUnsupported)
			}
			if n > len(b) {
				return nil, e, fmt.Errorf("truncated IPv6: %w", ErrMalformed)
			}
			if next != 17 {
				return nil, e, fmt.Errorf("non-UDP IPv6: %w", ErrUnsupported)
			}
			e.IPFamily = 6
			e.Source = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), 0)
			e.Destination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[24:40])), 0)
			return b[pos:n], e, nil
		}
	}
}
