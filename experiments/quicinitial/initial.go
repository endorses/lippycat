//go:build cli || hunter || processor || tap || tui || all

package quicinitial

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	lctls "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
)

type Direction uint8

const (
	Client Direction = iota
	Server
)

type Parameter struct {
	ID       uint64
	ValueHex string
}

// Result is a snapshot owned by the caller. A recovered ClientHello is only the
// visible outer hello when ECH is offered. Parameters retain exact TLV values;
// this experiment does not validate every parameter's protocol semantics.
type Result struct {
	Header                      Header
	Reason                      Reason
	ClientHello                 []byte
	TLS                         *types.TLSMetadata
	TransportParametersObserved bool
	Parameters                  []Parameter
}

type initialKeys struct {
	aead cipher.AEAD
	hp   cipher.Block
	iv   []byte
}

func expand(secret []byte, label string, n int) ([]byte, error) {
	label = "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, label...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

func keys(dcid []byte, direction Direction) (initialKeys, error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return initialKeys{}, err
	}
	label := "client in"
	if direction == Server {
		label = "server in"
	}
	secret, err = expand(secret, label, 32)
	if err != nil {
		return initialKeys{}, err
	}
	key, err := expand(secret, "quic key", 16)
	if err != nil {
		return initialKeys{}, err
	}
	iv, err := expand(secret, "quic iv", 12)
	if err != nil {
		return initialKeys{}, err
	}
	hp, err := expand(secret, "quic hp", 16)
	if err != nil {
		return initialKeys{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return initialKeys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return initialKeys{}, err
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return initialKeys{}, err
	}
	return initialKeys{aead, hpBlock, iv}, nil
}

// Session holds exactly one externally correlated connection epoch. originalDCID
// is the client's first Initial DCID (or its post-Retry DCID in a NEW session).
// Feed direction is supplied by the caller; ports and arrival order are not proof.
// Session is not safe for concurrent use. Close releases its bounded state.
type Session struct {
	keys       [2]initialKeys
	states     [2]*cryptoState
	packets    [2]uint64
	havePacket [2]bool
	datagrams  int
	closed     bool
}

type cryptoState struct {
	data       [MaxCryptoBytes]byte
	present    [MaxCryptoBytes / 8]byte
	contiguous int
	failure    Reason
}

func NewSession(originalDCID []byte) (*Session, error) {
	if len(originalDCID) > 20 {
		return nil, fmt.Errorf("QUIC initial DCID exceeds 20 bytes")
	}
	s := &Session{}
	for _, d := range []Direction{Client, Server} {
		k, err := keys(originalDCID, d)
		if err != nil {
			return nil, fmt.Errorf("derive initial keys: %w", err)
		}
		s.keys[d] = k
	}
	return s, nil
}

func (s *Session) Close() { s.states = [2]*cryptoState{}; s.keys = [2]initialKeys{}; s.closed = true }

// StateBytes reports retained CRYPTO payload+presence bitmap, excluding structs,
// cipher/runtime overhead and caller-owned result snapshots. It is not process RSS.
func (s *Session) StateBytes() int {
	n := 0
	for _, state := range s.states {
		if state != nil {
			n += len(state.data) + len(state.present)
		}
	}
	return n
}

func reconstruct(truncated uint64, length int, largest uint64, have bool) (uint64, bool) {
	expected := uint64(0)
	if have {
		expected = largest + 1
	}
	window := uint64(1) << (length * 8)
	half := window / 2
	candidate := (expected & ^(window - 1)) | truncated
	if candidate+half <= expected && candidate+window < (uint64(1)<<62) {
		candidate += window
	} else if candidate > expected+half && candidate >= window {
		candidate -= window
	}
	return candidate, candidate < (uint64(1) << 62)
}

func (s *Session) decrypt(data []byte, h *Header, d Direction) ([]byte, Reason) {
	if h.pnOffset+4+aes.BlockSize > len(data) {
		return nil, Malformed
	}
	k := s.keys[d]
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], data[h.pnOffset+4:h.pnOffset+4+aes.BlockSize])
	first := data[0] ^ (mask[0] & 0x0f)
	if first&0x0c != 0 {
		return nil, DecryptFailed
	}
	n := int(first&3) + 1
	if h.pnOffset+n+16 > len(data) {
		return nil, Malformed
	}
	aad := append([]byte(nil), data[:h.pnOffset+n]...)
	aad[0] = first
	pn := uint64(0)
	for i := 0; i < n; i++ {
		aad[h.pnOffset+i] ^= mask[i+1]
		pn = pn<<8 | uint64(aad[h.pnOffset+i])
	}
	pn, ok := reconstruct(pn, n, s.packets[d], s.havePacket[d])
	if !ok {
		return nil, Malformed
	}
	nonce := append([]byte(nil), k.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := k.aead.Open(nil, nonce, data[h.pnOffset+n:], aad)
	if err != nil {
		return nil, DecryptFailed
	}
	h.PacketNumberLength = n
	h.PacketNumber = pn
	if !s.havePacket[d] || pn > s.packets[d] {
		s.packets[d] = pn
		s.havePacket[d] = true
	}
	return plain, ""
}

type fragment struct {
	offset uint64
	data   []byte
}

// frames validates the entire plaintext before committing any CRYPTO fragments.
func frames(plain []byte) ([]fragment, Reason) {
	var fragments []fragment
	pos := 0
	for count := 0; pos < len(plain); count++ {
		if count == MaxFrames {
			return nil, ResourceLimit
		}
		start := pos
		typ, ok := takeVarint(plain, &pos)
		if !ok {
			return nil, Malformed
		}
		// Frame Type alone requires shortest encoding (RFC 9000 section 12.4).
		// Other QUIC varints may legitimately use a longer representation.
		width := 8
		switch {
		case typ < 1<<6:
			width = 1
		case typ < 1<<14:
			width = 2
		case typ < 1<<30:
			width = 4
		}
		if pos-start != width {
			return nil, Malformed
		}
		switch typ {
		case 0: // Collapse runs of PADDING instead of counting each byte as a frame.
			for pos < len(plain) && plain[pos] == 0 {
				pos++
			}
		case 1: // PING
		case 2, 3: // ACK, ACK_ECN: validate ranges without allocating a range list.
			largest, ok := takeVarint(plain, &pos)
			if !ok {
				return nil, Malformed
			}
			if _, ok = takeVarint(plain, &pos); !ok {
				return nil, Malformed
			}
			ranges, ok := takeVarint(plain, &pos)
			if !ok {
				return nil, Malformed
			}
			first, ok := takeVarint(plain, &pos)
			if !ok || first > largest {
				return nil, Malformed
			}
			if ranges > MaxFrames {
				return nil, ResourceLimit
			}
			smallest := largest - first
			for i := uint64(0); i < ranges; i++ {
				gap, ok := takeVarint(plain, &pos)
				if !ok || gap+2 > smallest {
					return nil, Malformed
				}
				last := smallest - gap - 2
				rangeLen, ok := takeVarint(plain, &pos)
				if !ok || rangeLen > last {
					return nil, Malformed
				}
				smallest = last - rangeLen
			}
			if typ == 3 {
				for i := 0; i < 3; i++ {
					if _, ok := takeVarint(plain, &pos); !ok {
						return nil, Malformed
					}
				}
			}
		case 6:
			off, ok := takeVarint(plain, &pos)
			if !ok {
				return nil, Malformed
			}
			n, ok := takeVarint(plain, &pos)
			if !ok || n > uint64(len(plain)-pos) {
				return nil, Malformed
			}
			if off > MaxCryptoBytes || n > MaxCryptoBytes-off {
				return nil, ResourceLimit
			}
			fragments = append(fragments, fragment{off, plain[pos : pos+int(n)]})
			pos += int(n)
		case 0x1c: // Transport CONNECTION_CLOSE, not an application close.
			for i := 0; i < 2; i++ {
				if _, ok := takeVarint(plain, &pos); !ok {
					return nil, Malformed
				}
			}
			n, ok := takeVarint(plain, &pos)
			if !ok || n > uint64(len(plain)-pos) {
				return nil, Malformed
			}
			pos += int(n)
		default:
			return nil, UnsupportedFrame
		}
	}
	return fragments, ""
}

func (c *cryptoState) add(f fragment) Reason {
	for i, v := range f.data {
		at := int(f.offset) + i
		mask := byte(1) << uint(at%8)
		if c.present[at/8]&mask != 0 && c.data[at] != v {
			c.failure = ConflictingCrypto
			return c.failure
		}
		c.data[at] = v
		c.present[at/8] |= mask
	}
	for c.contiguous < MaxCryptoBytes && c.present[c.contiguous/8]&(1<<uint(c.contiguous%8)) != 0 {
		c.contiguous++
	}
	return ""
}

func (c *cryptoState) result(h Header, d Direction) Result {
	r := Result{Header: h, Reason: Incomplete}
	if c.failure != "" {
		r.Reason = c.failure
		return r
	}
	if c.contiguous < 4 {
		return r
	}
	n := 4 + (int(c.data[1]) << 16) + (int(c.data[2]) << 8) + int(c.data[3])
	if n > MaxCryptoBytes {
		r.Reason = ResourceLimit
		return r
	}
	if c.contiguous < n {
		return r
	}
	if d == Server {
		r.Reason = ServerHandshake
		return r
	}
	if c.data[0] != 1 {
		r.Reason = Malformed
		return r
	}
	m := lctls.NewParser().ParseHandshake(lctls.VersionTLS12, c.data[:n])
	if m == nil || !m.ClientHelloObserved {
		r.Reason = Malformed
		return r
	}
	// The existing JA4 helper is explicitly TCP-only. Do not mislabel its 't'
	// fingerprint as QUIC; a transport-aware fingerprint is separate work.
	m.JA4String, m.JA4Fingerprint = "", ""
	m.RecordVersion = 0 // QUIC carries handshake bytes without a TLS record layer.
	params, present, reason := parameters(c.data[:n])
	if reason != "" {
		r.Reason = reason
		return r
	}
	r.ClientHello = append([]byte(nil), c.data[:n]...)
	r.TLS = m
	r.Parameters = params
	r.TransportParametersObserved = present
	r.Reason = Complete
	if m.ECHOffered {
		r.Reason = ECHLimited
	}
	return r
}

// Feed processes one complete UDP payload and preserves ordered CRYPTO offsets
// across at most 64 datagrams. IP fragmentation/reassembly and connection tracking
// belong to the caller. Retry does not mutate keys; start a new Session explicitly.
func (s *Session) Feed(datagram []byte, d Direction) []Result {
	if s == nil || s.closed || d > Server {
		return []Result{{Reason: Malformed}}
	}
	s.datagrams++
	if s.datagrams > MaxDatagrams || len(datagram) > MaxDatagramBytes {
		return []Result{{Reason: ResourceLimit}}
	}
	var out []Result
	for len(datagram) > 0 {
		if len(out) == MaxPackets {
			return append(out, Result{Reason: ResourceLimit})
		}
		h, reason := parseHeader(datagram)
		if reason != "" {
			return append(out, Result{Header: h, Reason: reason})
		}
		data := datagram[:h.PacketBytes]
		datagram = datagram[h.PacketBytes:]
		if h.Version == Version2 {
			out = append(out, Result{Header: h, Reason: UnsupportedVersion})
			continue
		}
		if h.Type != Initial {
			out = append(out, Result{Header: h, Reason: UnsupportedPacket})
			continue
		}
		plain, reason := s.decrypt(data, &h, d)
		if reason != "" {
			out = append(out, Result{Header: h, Reason: reason})
			continue
		}
		frags, reason := frames(plain)
		if reason != "" {
			out = append(out, Result{Header: h, Reason: reason})
			continue
		}
		if s.states[d] == nil {
			s.states[d] = &cryptoState{}
		}
		state := s.states[d]
		if state.failure == "" {
			for _, f := range frags {
				if state.add(f) != "" {
					break
				}
			}
		}
		out = append(out, state.result(h, d))
	}
	if len(out) == 0 {
		return []Result{{Reason: Malformed}}
	}
	return out
}

func parameters(hello []byte) ([]Parameter, bool, Reason) {
	// Called only after the shared parser validates every enclosing vector.
	pos := 39 + int(hello[38])
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	pos += 1 + int(hello[pos])
	if pos == len(hello) {
		return nil, false, ""
	}
	pos += 2
	var params []Parameter
	found := false
	for pos < len(hello) {
		typ := binary.BigEndian.Uint16(hello[pos : pos+2])
		n := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4
		body := hello[pos : pos+n]
		pos += n
		if typ != 57 {
			continue
		}
		if found {
			return nil, false, Malformed
		}
		found = true
		seen := make(map[uint64]bool)
		for at := 0; at < len(body); {
			if len(params) == MaxParameters {
				return nil, false, ResourceLimit
			}
			id, ok := takeVarint(body, &at)
			if !ok {
				return nil, false, Malformed
			}
			n, ok := takeVarint(body, &at)
			if !ok || n > uint64(len(body)-at) || seen[id] {
				return nil, false, Malformed
			}
			seen[id] = true
			params = append(params, Parameter{id, hex.EncodeToString(body[at : at+int(n)])})
			at += int(n)
		}
	}
	return params, found, ""
}
