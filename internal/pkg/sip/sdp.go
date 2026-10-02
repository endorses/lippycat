package sip

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var ErrSDPEndpointLimit = errors.New("SDP endpoint limit exceeded")

// MediaEndpoint is an advertised UDP endpoint, not proof of packet ownership.
// RTP and RTCP share an entry when mux is advertised. Inactive/disabled media
// produce no endpoints; previously learned endpoints are retired by call policy.
type MediaEndpoint struct {
	Address netip.AddrPort
	Media   string
	RTCP    bool
}

type sdpMedia struct {
	kind         string
	address      netip.Addr
	port, count  uint64
	rtcpPort     uint64
	rtcpAddress  netip.Addr
	explicitRTCP bool
	mux          bool
	inactive     bool
	supported    bool
}

// ParseSDPEndpoints normalizes SDP connection and RTP/RTCP endpoint semantics
// (RFC 8866, RFC 3605, RFC 5761). The result is bounded and all-or-nothing.
// Session connection/direction applies separately to every media section; a
// media-level connection never leaks into the following section. ICE candidate
// learning and multicast address ranges are intentionally not inferred.
func ParseSDPEndpoints(body string, limit int) ([]MediaEndpoint, error) {
	if limit <= 0 {
		return nil, ErrSDPEndpointLimit
	}
	if len(body) > MaxMessageSize {
		return nil, fmt.Errorf("SDP exceeds maximum SIP message size")
	}
	var sessionAddress netip.Addr
	var current *sdpMedia
	var endpoints []MediaEndpoint
	seen := make(map[netip.AddrPort]bool)
	sessionInactive := false
	add := func(addr netip.Addr, port uint64, kind string, rtcp bool) error {
		if !addr.IsValid() || addr.IsUnspecified() || port == 0 {
			return nil
		}
		if port > 65535 {
			return fmt.Errorf("SDP port out of range")
		}
		endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(port))
		if seen[endpoint] {
			return nil
		}
		if len(endpoints) >= limit {
			return ErrSDPEndpointLimit
		}
		seen[endpoint] = true
		endpoints = append(endpoints, MediaEndpoint{Address: endpoint, Media: kind, RTCP: rtcp})
		return nil
	}
	flush := func() error {
		if current == nil || !current.supported || current.inactive || current.port == 0 {
			return nil
		}
		if current.count > uint64(limit) {
			return ErrSDPEndpointLimit
		}
		for i := uint64(0); i < current.count; i++ {
			port := current.port + 2*i
			if err := add(current.address, port, current.kind, false); err != nil {
				return err
			}
			if current.mux {
				continue
			}
			rtcpPort, rtcpAddress := port+1, current.address
			if current.explicitRTCP {
				// One explicit attribute describes one RTP session. Multi-port SDP with
				// an explicit noncontiguous RTCP layout is not unambiguously specified.
				if current.count != 1 {
					return fmt.Errorf("explicit RTCP with multiple RTP ports is unsupported")
				}
				rtcpPort = current.rtcpPort
				if current.rtcpAddress.IsValid() {
					rtcpAddress = current.rtcpAddress
				}
			}
			if err := add(rtcpAddress, rtcpPort, current.kind, true); err != nil {
				return err
			}
		}
		return nil
	}
	for raw := range strings.SplitSeq(body, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "m="):
			if err := flush(); err != nil {
				return nil, err
			}
			fields := strings.Fields(line[2:])
			if len(fields) < 3 {
				return nil, fmt.Errorf("malformed SDP media line")
			}
			current = &sdpMedia{kind: fields[0], address: sessionAddress, count: 1, inactive: sessionInactive}
			proto := strings.ToUpper(fields[2])
			current.supported = strings.HasPrefix(proto, "RTP/") || strings.HasPrefix(proto, "UDP/TLS/RTP/")
			if !current.supported {
				continue
			}
			port, count, hasCount := strings.Cut(fields[1], "/")
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid SDP media port: %w", err)
			}
			current.port = value
			if hasCount {
				value, err = strconv.ParseUint(count, 10, 16)
				if err != nil || value == 0 {
					return nil, fmt.Errorf("invalid SDP media port count")
				}
				current.count = value
			}
		case strings.HasPrefix(line, "c="):
			addr, err := parseSDPConnection(strings.Fields(line[2:]))
			if err != nil {
				return nil, err
			}
			if current == nil {
				sessionAddress = addr
			} else {
				current.address = addr
			}
		case line == "a=inactive":
			if current == nil {
				sessionInactive = true
			} else {
				current.inactive = true
			}
		case line == "a=sendrecv" || line == "a=sendonly" || line == "a=recvonly":
			if current == nil {
				sessionInactive = false
			} else {
				current.inactive = false
			}
		case line == "a=rtcp-mux" || line == "a=rtcp-mux-only":
			if current != nil {
				current.mux = true
			}
		case strings.HasPrefix(line, "a=rtcp:"):
			if current == nil || !current.supported {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(line, "a=rtcp:"))
			if len(fields) != 1 && len(fields) != 4 {
				return nil, fmt.Errorf("malformed SDP RTCP attribute")
			}
			port, err := strconv.ParseUint(fields[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid SDP RTCP port: %w", err)
			}
			current.rtcpPort, current.explicitRTCP = port, true
			if len(fields) == 4 {
				current.rtcpAddress, err = parseSDPConnection(fields[1:])
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func parseSDPConnection(fields []string) (netip.Addr, error) {
	if len(fields) != 3 || fields[0] != "IN" || (fields[1] != "IP4" && fields[1] != "IP6") {
		return netip.Addr{}, fmt.Errorf("unsupported SDP connection")
	}
	address, suffix, hasSuffix := strings.Cut(fields[2], "/")
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid SDP connection address")
	}
	if (fields[1] == "IP4") != addr.Is4() {
		return netip.Addr{}, fmt.Errorf("SDP connection address family mismatch")
	}
	if hasSuffix {
		// IPv4 multicast /ttl is meaningful; address-count ranges need explicit
		// expansion and are rejected rather than installing only their first IP.
		if !addr.Is4() || !addr.IsMulticast() || strings.Contains(suffix, "/") {
			return netip.Addr{}, fmt.Errorf("SDP connection address range unsupported")
		}
		if _, err := strconv.ParseUint(suffix, 10, 8); err != nil {
			return netip.Addr{}, fmt.Errorf("invalid SDP multicast TTL")
		}
	}
	return addr.Unmap(), nil
}
