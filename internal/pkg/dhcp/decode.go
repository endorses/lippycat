// Package dhcp decodes bounded DHCPv4 message observations (RFC 2131/2132).
// It does not decode bare BOOTP or DHCPv6, nor export opaque vendor options.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"
)

const (
	MaxDatagramBytes         = 65507
	MaxIdentifierBytes       = 1024
	MaxNameBytes             = 255
	MaxAddresses             = 64
	MaxParameterRequestBytes = 255
)

var (
	ErrHeader      = errors.New("invalid DHCP fixed header")
	ErrCookie      = errors.New("missing DHCP magic cookie")
	ErrBOOTP       = errors.New("BOOTP options without DHCP message type")
	ErrMessageType = errors.New("missing or unsupported DHCP message type")
	ErrOptions     = errors.New("incomplete or malformed DHCP options")
)

type Role string

const (
	RoleRequest  Role = "request"
	RoleResponse Role = "response"
	RoleUnknown  Role = "unknown"
)

// Message owns all its variable-size data. Invalid optional fields are omitted;
// Partial signals invalid/oversized options, and Truncated signals missing bytes
// or a missing END marker. IPv4 unspecified values in fixed fields are retained.
// Optional addresses are invalid netip.Addr values when absent.
type Message struct {
	Operation, MessageType, HardwareType, Hops                     uint8
	TransactionID                                                  uint32
	HardwareAddress, ClientIdentifier                              []byte
	ClientAddress, OfferedAddress, NextServerAddress, RelayAddress netip.Addr
	ServerIdentifier, RequestedAddress                             netip.Addr
	Hostname, Domain                                               string
	LeaseSeconds                                                   *uint32
	Routers, DNSServers                                            []netip.Addr
	ParameterRequestList                                           []byte
	Partial, Truncated                                             bool
}

func (m *Message) Role() Role {
	if m == nil {
		return RoleUnknown
	}
	switch m.MessageType {
	case 1, 3, 4, 7, 8:
		if m.Operation == 1 {
			return RoleRequest
		}
	case 2, 5, 6:
		if m.Operation == 2 {
			return RoleResponse
		}
	}
	return RoleUnknown
}

// ValidBOOTPHeader permits all nonzero hardware types, including allocations
// newer than the original signature's 1..32 heuristic, and 0..16 address bytes.
func ValidBOOTPHeader(b []byte) bool {
	return len(b) >= 236 && (b[0] == 1 || b[0] == 2) && b[1] != 0 && b[2] <= 16
}

// Decode parses each datagram independently. A nonnil message with an error is
// an accepted but explicitly partial observation. A nil message is not DHCPv4.
// Repeated options concatenate in options/file/sname order (RFC 3396) before
// validating their total length; repeated scalar options are thus invalid.
func Decode(b []byte) (*Message, error) {
	if !ValidBOOTPHeader(b) || len(b) > MaxDatagramBytes {
		return nil, ErrHeader
	}
	if len(b) < 240 || binary.BigEndian.Uint32(b[236:240]) != 0x63825363 {
		return nil, ErrCookie
	}
	m := &Message{Operation: b[0], HardwareType: b[1], Hops: b[3], TransactionID: binary.BigEndian.Uint32(b[4:8]), HardwareAddress: append([]byte(nil), b[28:28+int(b[2])]...), ClientAddress: addr(b[12:16]), OfferedAddress: addr(b[16:20]), NextServerAddress: addr(b[20:24]), RelayAddress: addr(b[24:28])}
	var options [256][]byte
	var invalid [256]bool
	read := func(area []byte, main bool) {
		for i := 0; i < len(area); {
			code := area[i]
			i++
			if code == 255 {
				return
			}
			if code == 0 {
				continue
			}
			if i >= len(area) {
				m.Partial = true
				m.Truncated = true
				return
			}
			n := int(area[i])
			i++
			if n > len(area)-i {
				m.Partial = true
				m.Truncated = true
				invalid[code] = true
				return
			}
			limit := optionLimit(code)
			if code == 52 && !main {
				m.Partial = true
				i += n
				continue
			}
			if limit > 0 {
				if invalid[code] || len(options[code])+n > limit {
					invalid[code] = true
					options[code] = nil
					m.Partial = true
				} else {
					// Keep presence of a zero-length option distinct from absence.
					if options[code] == nil {
						options[code] = make([]byte, 0)
					}
					options[code] = append(options[code], area[i:i+n]...)
				}
			}
			i += n
		}
		m.Partial = true
		m.Truncated = true
	}
	read(b[240:], true)
	overload := options[52]
	if overload != nil && (len(overload) != 1 || overload[0] < 1 || overload[0] > 3) {
		m.Partial = true
	} else if len(overload) == 1 {
		if overload[0]&1 != 0 {
			read(b[108:236], false)
		}
		if overload[0]&2 != 0 {
			read(b[44:108], false)
		}
	}
	mt := options[53]
	if mt == nil && !invalid[53] && !m.Partial {
		return nil, ErrBOOTP
	}
	if invalid[53] || len(mt) != 1 || mt[0] < 1 || mt[0] > 8 {
		return nil, ErrMessageType
	}
	m.MessageType = mt[0]
	if m.Role() == RoleUnknown {
		m.Partial = true
	}
	for code, value := range options {
		if value == nil || invalid[code] {
			continue
		}
		valid := true
		switch code {
		case 3, 6:
			if len(value) == 0 || len(value)%4 != 0 {
				valid = false
				break
			}
			list := make([]netip.Addr, 0, len(value)/4)
			for i := 0; i < len(value); i += 4 {
				list = append(list, addr(value[i:i+4]))
			}
			if code == 3 {
				m.Routers = list
			} else {
				m.DNSServers = list
			}
		case 12, 15:
			valid = len(value) > 0 && ValidName(string(value))
			if valid {
				if code == 12 {
					m.Hostname = string(value)
				} else {
					m.Domain = string(value)
				}
			}
		case 50, 54:
			valid = len(value) == 4
			if valid {
				if code == 50 {
					m.RequestedAddress = addr(value)
				} else {
					m.ServerIdentifier = addr(value)
				}
			}
		case 51:
			valid = len(value) == 4
			if valid {
				n := binary.BigEndian.Uint32(value)
				m.LeaseSeconds = &n
			}
		case 55:
			valid = len(value) > 0
			if valid {
				m.ParameterRequestList = value
			}
		case 61:
			valid = len(value) >= 2
			if valid {
				m.ClientIdentifier = value
			}
		}
		if !valid {
			m.Partial = true
		}
	}
	if m.Partial {
		return m, fmt.Errorf("%w (truncated=%t)", ErrOptions, m.Truncated)
	}
	return m, nil
}

func optionLimit(code byte) int {
	switch code {
	case 3, 6:
		return MaxAddresses * 4
	case 12, 15:
		return MaxNameBytes
	case 50, 51, 54:
		return 4
	case 52, 53:
		return 1
	case 55:
		return MaxParameterRequestBytes
	case 61:
		return MaxIdentifierBytes
	default:
		return 0
	}
}

func addr(b []byte) netip.Addr { return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}) }

// ValidName checks routine-output names without interpreting them as binary
// identifiers. Invalid names are omitted and make the observation partial.
func ValidName(value string) bool {
	if len(value) > MaxNameBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
