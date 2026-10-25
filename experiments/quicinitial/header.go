// Package quicinitial is an isolated QUIC feasibility experiment. No production
// analyzer imports it. Callers supply one connection epoch and proven direction.
package quicinitial

import (
	"encoding/binary"
	"encoding/hex"
)

const (
	Version1         uint32 = 1
	Version2         uint32 = 0x6b3343cf
	MaxDatagramBytes        = 65535
	MaxPackets              = 16
	MaxCryptoBytes          = 65536
	MaxFrames               = 256
	MaxDatagrams            = 64
	MaxParameters           = 128
)

type Reason string

const (
	Complete           Reason = "client_hello"
	ECHLimited         Reason = "ech_outer_only"
	Incomplete         Reason = "incomplete_crypto"
	UnsupportedVersion Reason = "unsupported_version"
	VersionNegotiation Reason = "version_negotiation"
	Retry              Reason = "retry_requires_new_context"
	UnsupportedPacket  Reason = "unsupported_packet_type"
	UnsupportedFrame   Reason = "unsupported_frame"
	ServerHandshake    Reason = "server_initial_no_client_hello"
	Malformed          Reason = "malformed"
	DecryptFailed      Reason = "decryption_failed"
	ResourceLimit      Reason = "resource_limit"
	ConflictingCrypto  Reason = "conflicting_crypto"
)

type PacketType string

const (
	Initial     PacketType = "initial"
	ZeroRTT     PacketType = "0rtt"
	Handshake   PacketType = "handshake"
	RetryPacket PacketType = "retry"
	Negotiation PacketType = "version_negotiation"
	Unknown     PacketType = "unknown"
)

// Header contains only observed shape. PacketNumberLength is populated after
// successful header unprotection; protected low bits are not a length hint.
type Header struct {
	Version            uint32
	Type               PacketType
	DCID               string
	SCID               string
	TokenLength        uint64
	PacketBytes        int
	PacketNumberLength int
	PacketNumber       uint64
	Versions           []uint32
	pnOffset           int
}

func takeVarint(data []byte, pos *int) (uint64, bool) {
	if *pos >= len(data) {
		return 0, false
	}
	n := 1 << (data[*pos] >> 6)
	if n > len(data)-*pos {
		return 0, false
	}
	v := uint64(data[*pos] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(data[*pos+i])
	}
	*pos += n
	return v, true
}

func parseHeader(data []byte) (Header, Reason) {
	h := Header{Type: Unknown}
	if len(data) > 0 && data[0]&0x80 == 0 {
		return h, UnsupportedPacket
	}
	if len(data) < 7 {
		return h, Malformed
	}
	h.Version = binary.BigEndian.Uint32(data[1:5])
	pos := 5
	for i := 0; i < 2; i++ {
		if pos >= len(data) {
			return h, Malformed
		}
		n := int(data[pos])
		pos++
		if n > 20 || n > len(data)-pos {
			return h, Malformed
		}
		cid := hex.EncodeToString(data[pos : pos+n])
		pos += n
		if i == 0 {
			h.DCID = cid
		} else {
			h.SCID = cid
		}
	}
	if h.Version == 0 {
		h.Type = Negotiation
		h.PacketBytes = len(data)
		if pos == len(data) || (len(data)-pos)%4 != 0 {
			return h, Malformed
		}
		// The datagram bound also bounds this list; avoid a large result vector.
		if (len(data)-pos)/4 > MaxParameters {
			return h, ResourceLimit
		}
		for pos < len(data) {
			h.Versions = append(h.Versions, binary.BigEndian.Uint32(data[pos:pos+4]))
			pos += 4
		}
		return h, VersionNegotiation
	}
	if h.Version != Version1 && h.Version != Version2 {
		return h, UnsupportedVersion
	}
	if data[0]&0x40 == 0 {
		return h, Malformed
	}
	typ := (data[0] >> 4) & 3
	if h.Version == Version2 {
		typ = (typ + 3) & 3
	}
	h.Type = []PacketType{Initial, ZeroRTT, Handshake, RetryPacket}[typ]
	if h.Type == RetryPacket {
		if len(data)-pos < 16 {
			return h, Malformed
		}
		h.TokenLength = uint64(len(data) - pos - 16)
		h.PacketBytes = len(data)
		return h, Retry
	}
	if h.Type == Initial {
		n, ok := takeVarint(data, &pos)
		if !ok || n > uint64(len(data)-pos) {
			return h, Malformed
		}
		h.TokenLength = n
		pos += int(n)
	}
	n, ok := takeVarint(data, &pos)
	if !ok || n == 0 || n > uint64(len(data)-pos) {
		return h, Malformed
	}
	h.pnOffset = pos
	h.PacketBytes = pos + int(n)
	return h, ""
}

// Inspect parses supported coalesced long headers without decrypting anything.
// A short-header tail is explicitly unsupported because it has no length field.
func Inspect(datagram []byte) ([]Header, Reason) {
	if len(datagram) > MaxDatagramBytes {
		return nil, ResourceLimit
	}
	var headers []Header
	for len(datagram) > 0 {
		if len(headers) == MaxPackets {
			return headers, ResourceLimit
		}
		h, reason := parseHeader(datagram)
		headers = append(headers, h)
		if reason != "" {
			return headers, reason
		}
		datagram = datagram[h.PacketBytes:]
	}
	if len(headers) == 0 {
		return nil, Malformed
	}
	return headers, ""
}
