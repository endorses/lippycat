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

// SDPDiagnostic contains only a reason category and section index. Section zero
// is session/global scope; no signaling or network identity is retained.
type SDPDiagnostic struct {
	Section int
	Reason  SDPReason
}

type SDPReason string

const (
	SDPMediaInvalid      SDPReason = "media-invalid"
	SDPConnectionInvalid SDPReason = "connection-invalid"
	SDPConnectionMissing SDPReason = "connection-missing"
	SDPRTCPInvalid       SDPReason = "rtcp-invalid"
	SDPBodyLimit         SDPReason = "body-limit"
	SDPEndpointLimit     SDPReason = "endpoint-limit"
	MaxSDPDiagnostics              = 32
)

// SDPResult retains independently verified numeric endpoints even when some
// media cannot be derived. Complete distinguishes intentional empty media from
// unknown media. ResourceLimited additionally marks whole-body/capacity failures.
// At endpoint capacity the first unique endpoints in wire order are retained.
type SDPResult struct {
	Endpoints          []MediaEndpoint
	Diagnostics        []SDPDiagnostic
	DiagnosticsDropped uint64
	Complete           bool
	ResourceLimited    bool
	IntentionalEmpty   bool
	reasonCounts       [6]uint64
}

func (r SDPResult) Err() error {
	if r.Complete {
		return nil
	}
	if r.ResourceLimited {
		for _, d := range r.Diagnostics {
			if d.Reason == SDPBodyLimit {
				return errors.New("SDP body limit exceeded")
			}
		}
		return ErrSDPEndpointLimit
	}
	return errors.New("SDP endpoint derivation incomplete")
}

type sdpMedia struct {
	kind                                            string
	address                                         netip.Addr
	port, count                                     uint64
	rtcpPort                                        uint64
	rtcpAddress                                     netip.Addr
	explicitRTCP, mux, inactive, supported, invalid bool
	section                                         int
}

// ParseSDPEndpoints preserves the strict compatibility API. Consumers that can
// retain safe independent sections should use ParseSDPResult instead.
func ParseSDPEndpoints(body string, limit int) ([]MediaEndpoint, error) {
	r := ParseSDPResult(body, limit)
	if err := r.Err(); err != nil {
		return nil, err
	}
	return r.Endpoints, nil
}

// ParseSDPResult normalizes SDP connection and RTP/RTCP semantics. Bad sections
// never supply endpoints; later sections inherit only the session connection.
// DNS, ICE candidate learning and address ranges are intentionally not inferred.
func ParseSDPResult(body string, limit int) SDPResult {
	r := SDPResult{Complete: true}
	diagnose := func(section int, reason SDPReason) {
		r.Complete = false
		r.reasonCounts[sdpReasonIndex(reason)]++
		if reason == SDPBodyLimit || reason == SDPEndpointLimit {
			r.ResourceLimited = true
		}
		if len(r.Diagnostics) < MaxSDPDiagnostics {
			r.Diagnostics = append(r.Diagnostics, SDPDiagnostic{Section: section, Reason: reason})
		} else {
			r.DiagnosticsDropped++
		}
	}
	if limit <= 0 {
		diagnose(0, SDPEndpointLimit)
		return r
	}
	if len(body) > MaxMessageSize {
		diagnose(0, SDPBodyLimit)
		return r
	}
	var sessionAddress netip.Addr
	var current *sdpMedia
	sessionInactive := false
	section := 0
	seen := make(map[netip.AddrPort]bool)
	add := func(addr netip.Addr, port uint64, kind string, rtcp bool) {
		if !addr.IsValid() || addr.IsUnspecified() || port == 0 {
			return
		}
		endpoint := netip.AddrPortFrom(addr.Unmap(), uint16(port))
		if seen[endpoint] {
			return
		}
		if len(r.Endpoints) >= limit {
			diagnose(current.section, SDPEndpointLimit)
			return
		}
		seen[endpoint] = true
		r.Endpoints = append(r.Endpoints, MediaEndpoint{Address: endpoint, Media: kind, RTCP: rtcp})
	}
	flush := func() {
		if current == nil || current.invalid || !current.supported || current.inactive || current.port == 0 {
			return
		}
		if !current.address.IsValid() {
			diagnose(current.section, SDPConnectionMissing)
			return
		}
		if current.address.IsUnspecified() {
			return
		} // intentional hold
		if current.count > uint64(limit) {
			diagnose(current.section, SDPEndpointLimit)
			return
		}
		last := current.port + 2*(current.count-1)
		if last > 65535 || (!current.mux && !current.explicitRTCP && last == 65535) {
			diagnose(current.section, SDPMediaInvalid)
			return
		}
		if current.explicitRTCP && current.count != 1 && !current.mux {
			diagnose(current.section, SDPRTCPInvalid)
			return
		}
		for i := uint64(0); i < current.count; i++ {
			port := current.port + 2*i
			add(current.address, port, current.kind, false)
			if current.mux {
				continue
			}
			rtcpPort, rtcpAddress := port+1, current.address
			if current.explicitRTCP {
				rtcpPort = current.rtcpPort
				if current.rtcpAddress.IsValid() {
					rtcpAddress = current.rtcpAddress
				}
			}
			add(rtcpAddress, rtcpPort, current.kind, true)
		}
	}
	for raw := range strings.SplitSeq(body, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "m="):
			flush()
			section++
			// Reset before validation, so attributes following a malformed m= can
			// affect neither the preceding section nor session-level inheritance.
			current = &sdpMedia{address: sessionAddress, count: 1, inactive: sessionInactive, section: section}
			fields := strings.Fields(line[2:])
			if len(fields) < 3 {
				current.invalid = true
				diagnose(section, SDPMediaInvalid)
				continue
			}
			current.kind = fields[0]
			proto := strings.ToUpper(fields[2])
			current.supported = strings.HasPrefix(proto, "RTP/") || strings.HasPrefix(proto, "UDP/TLS/RTP/")
			if !current.supported {
				continue
			}
			port, count, hasCount := strings.Cut(fields[1], "/")
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				current.invalid = true
				diagnose(section, SDPMediaInvalid)
				continue
			}
			current.port = value
			if hasCount {
				value, err = strconv.ParseUint(count, 10, 16)
				if err != nil || value == 0 {
					current.invalid = true
					diagnose(section, SDPMediaInvalid)
					continue
				}
				current.count = value
			}
		case strings.HasPrefix(line, "c="):
			addr, err := parseSDPConnection(strings.Fields(line[2:]))
			if current == nil {
				sessionAddress = addr
			} else {
				current.address = addr
			}
			if err != nil {
				diagnose(section, SDPConnectionInvalid)
				if current != nil {
					current.invalid = true
				}
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
				current.invalid = true
				diagnose(section, SDPRTCPInvalid)
				continue
			}
			port, err := strconv.ParseUint(fields[0], 10, 16)
			if err != nil {
				current.invalid = true
				diagnose(section, SDPRTCPInvalid)
				continue
			}
			current.rtcpPort, current.explicitRTCP = port, true
			if len(fields) == 4 {
				current.rtcpAddress, err = parseSDPConnection(fields[1:])
				if err != nil {
					current.invalid = true
					diagnose(section, SDPRTCPInvalid)
				}
			}
		}
	}
	flush()
	r.IntentionalEmpty = r.Complete && len(r.Endpoints) == 0
	return r
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
