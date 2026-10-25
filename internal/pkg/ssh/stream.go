package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	MaxIdentificationBytes = 255 // RFC 4253 section 4.2, including CR/LF.
	MaxPreludeBytes        = 8192
	MaxPreludeLines        = 32
)

type Identification struct {
	Banner          string // Exact bytes without CR/LF; comments may not be UTF-8.
	ProtocolVersion string
	SoftwareVersion string
	Supported       bool // SSH 2.0, including the SSH 1.99 compatibility banner.
}

// ParseIdentification accepts a complete LF-terminated identification, optionally
// preceded by CR for compatibility described in RFC 4253 sections 4.2 and 5.1.
// Comments are retained as exact bytes in Banner. Consumers must escape untrusted
// display text and encode invalid UTF-8 before placing it in a UTF-8 wire string.
func ParseIdentification(line []byte) (Identification, error) {
	if len(line) > MaxIdentificationBytes || len(line) < 2 || line[len(line)-1] != '\n' {
		return Identification{}, errors.New("incomplete or oversized SSH identification")
	}
	body := bytes.TrimSuffix(line[:len(line)-1], []byte{'\r'})
	if !bytes.HasPrefix(body, []byte("SSH-")) || bytes.IndexByte(body, 0) >= 0 || bytes.IndexAny(body, "\r\n") >= 0 {
		return Identification{}, errors.New("invalid SSH identification")
	}
	version, software, ok := strings.Cut(string(body[4:]), "-")
	if !ok || !identificationToken(version) {
		return Identification{}, errors.New("invalid SSH protocol version")
	}
	software, _, _ = strings.Cut(software, " ")
	if !identificationToken(software) {
		return Identification{}, errors.New("invalid SSH software version")
	}
	return Identification{Banner: string(body), ProtocolVersion: version, SoftwareVersion: software, Supported: version == "2.0" || version == "1.99"}, nil
}

func identificationToken(value string) bool {
	if value == "" {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 32 || b >= 127 || b == '-' {
			return false
		}
	}
	return true
}

type StopReason string

const (
	StopNone               StopReason = ""
	StopKEXComplete        StopReason = "kex_complete"
	StopNewKeys            StopReason = "newkeys_before_kex"
	StopUnsupportedVersion StopReason = "unsupported_version"
	StopMalformed          StopReason = "malformed"
	StopResourceLimit      StopReason = "resource_limit"
	StopMissingBanner      StopReason = "missing_banner"
	StopIncomplete         StopReason = "incomplete"
	StopNoKEX              StopReason = "no_kex"
	StopGap                StopReason = "gap"
	StopDisconnect         StopReason = "disconnect"
)

type Observation struct {
	Identification *Identification
	KEXINIT        *KEXINIT
}

// Stream is one ordered TCP half-stream. It holds at most one bounded cleartext
// packet and one bounded line. The owner supplies ordering, retransmission/gap
// handling, endpoint roles, flow expiry, and a bound on aggregate active streams.
// Stream stops after its first complete KEXINIT or NEWKEYS, so later encrypted
// rekeys can never be mistaken for another initial handshake.
type Stream struct {
	line         [MaxIdentificationBytes]byte
	lineBytes    int
	preludeBytes int
	preludeLines int
	identified   bool
	header       [5]byte
	headerBytes  int
	packet       []byte
	packetBytes  int
	reason       StopReason
}

func (s *Stream) Stopped() bool          { return s.reason != StopNone }
func (s *Stream) StopReason() StopReason { return s.reason }
func (s *Stream) BufferedBytes() int     { return s.lineBytes + s.headerBytes + len(s.packet) }

// Stop releases all buffered input. A stopped Stream must never be reset and
// reused for a different TCP incarnation; create a new Stream for that flow.
func (s *Stream) Stop(reason StopReason) {
	if reason == StopNone {
		reason = StopIncomplete
	}
	if s.reason == StopNone {
		s.reason = reason
	}
	s.lineBytes, s.headerBytes, s.packetBytes = 0, 0, 0
	s.packet = nil
}

// End distinguishes an unobserved banner, partial framing, and a banner without
// KEXINIT. EOF or capture expiry cannot turn partial bytes into a fingerprint.
func (s *Stream) End() StopReason {
	if s.Stopped() {
		return s.reason
	}
	reason := StopNoKEX
	if !s.identified {
		reason = StopMissingBanner
	} else if s.headerBytes != 0 || s.packet != nil {
		reason = StopIncomplete
	}
	s.Stop(reason)
	return reason
}

// Feed consumes arbitrary segmentation/coalescing without retaining caller data.
// Observations own their strings and may outlive Feed. Callbacks are synchronous
// and must not call Feed recursively on this Stream.
func (s *Stream) Feed(data []byte, emit func(Observation)) error {
	for len(data) > 0 && !s.Stopped() {
		if !s.identified {
			b := data[0]
			data = data[1:]
			if s.lineBytes == len(s.line) {
				return s.fail(StopResourceLimit, "SSH identification or prelude line exceeds bound")
			}
			s.line[s.lineBytes] = b
			s.lineBytes++
			if b != '\n' {
				continue
			}
			line := s.line[:s.lineBytes]
			if !bytes.HasPrefix(line, []byte("SSH-")) {
				s.preludeBytes += s.lineBytes
				s.preludeLines++
				s.lineBytes = 0
				if s.preludeBytes > MaxPreludeBytes || s.preludeLines > MaxPreludeLines {
					return s.fail(StopResourceLimit, "SSH prelude exceeds bound")
				}
				continue
			}
			identification, err := ParseIdentification(line)
			if err != nil {
				s.Stop(StopMalformed)
				return err
			}
			s.lineBytes, s.identified = 0, true
			if emit != nil {
				emit(Observation{Identification: &identification})
			}
			if !identification.Supported {
				s.Stop(StopUnsupportedVersion)
			}
			continue
		}
		if s.packet == nil {
			n := copy(s.header[s.headerBytes:], data)
			s.headerBytes += n
			data = data[n:]
			if s.headerBytes != len(s.header) {
				continue
			}
			length := uint64(binary.BigEndian.Uint32(s.header[:4])) + 4
			padding := uint64(s.header[4])
			if length > MaxPacketBytes {
				return s.fail(StopResourceLimit, "SSH cleartext packet exceeds bound")
			}
			if length < 16 || length%8 != 0 || padding < 4 || padding+6 > length {
				return s.fail(StopMalformed, "invalid SSH cleartext framing")
			}
			s.packet = make([]byte, int(length))
			copy(s.packet, s.header[:])
			s.packetBytes = len(s.header)
		}
		n := copy(s.packet[s.packetBytes:], data)
		s.packetBytes += n
		data = data[n:]
		if s.packetBytes != len(s.packet) {
			continue
		}
		payload := s.packet[5 : len(s.packet)-int(s.packet[4])]
		switch payload[0] {
		case 1:
			// RFC 4253 section 11.1: DISCONNECT is terminal, even if bytes
			// resembling another KEXINIT follow in the captured direction.
			s.Stop(StopDisconnect)
		case 20:
			kex, err := ParseKEXINIT(payload)
			if err != nil {
				s.Stop(StopMalformed)
				return err
			}
			s.Stop(StopKEXComplete)
			if emit != nil {
				emit(Observation{KEXINIT: kex})
			}
		case 21:
			if len(payload) != 1 {
				return s.fail(StopMalformed, "invalid SSH NEWKEYS payload")
			}
			s.Stop(StopNewKeys)
		default:
			if payload[0] == 0 || payload[0] > 49 {
				return s.fail(StopMalformed, "unexpected SSH initial transport message")
			}
			s.packet, s.packetBytes, s.headerBytes = nil, 0, 0
		}
	}
	return nil
}

func (s *Stream) fail(reason StopReason, text string) error {
	s.Stop(reason)
	return errors.New(text)
}
