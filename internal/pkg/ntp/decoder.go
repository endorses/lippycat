// Package ntp decodes bounded NTP time-message observations. It does not
// authenticate peers, interpret control/private messages, or estimate clock quality.
package ntp

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	HeaderSize           = 48
	MaxPacketSize        = 4096
	MaxExtensions        = 64
	ntpEpochOffset int64 = 2208988800
	eraSeconds     int64 = 1 << 32
)

var (
	ErrShortHeader = errors.New("NTP time header shorter than 48 bytes")
	ErrUnsupported = errors.New("unsupported NTP version or non-time mode")
)

// Timestamp retains the exact unsigned 32.32 wire representation. Time is
// unavailable (Go zero time) for wire zero or unavailable capture time. Otherwise
// its era is the nearest to capture time, with subnanoseconds rounded down.
// The raw value remains authoritative; capture-relative era selection is not a
// claim about the remote clock's correctness.
type Timestamp struct {
	Raw  uint64
	Time time.Time
}

func ResolveTimestamp(raw uint64, captureTime time.Time) Timestamp {
	t := Timestamp{Raw: raw}
	if raw == 0 || captureTime.IsZero() {
		return t
	}
	seconds := int64(raw >> 32)
	pivot := captureTime.Unix() + ntpEpochOffset
	era := (pivot - seconds) / eraSeconds
	resolved := seconds + era*eraSeconds
	nanos := (int64(uint32(raw)) * 1_000_000_000) >> 32
	candidate := time.Unix(resolved-ntpEpochOffset, nanos).UTC()
	halfEra := time.Duration(eraSeconds/2) * time.Second
	if candidate.After(captureTime.Add(halfEra)) {
		resolved -= eraSeconds
	}
	if candidate.Before(captureTime.Add(-halfEra)) {
		resolved += eraSeconds
	}
	t.Time = time.Unix(resolved-ntpEpochOffset, nanos).UTC()
	return t
}

// Observation is a value-only, immutable-by-copy fixed-header observation.
// RootDelay is signed 16.16 and RootDispersion is unsigned 16.16, in seconds.
// Poll and Precision are signed base-two exponents, not elapsed durations.
type Observation struct {
	Version, Mode, LeapIndicator, Stratum uint8
	Poll, Precision                       int8
	RootDelay                             int32
	RootDispersion                        uint32
	ReferenceID                           [4]byte
	Reference, Origin, Receive, Transmit  Timestamp
	ExtensionCount                        uint16
	TrailingBytes                         uint32
	Partial, Truncated                    bool
}

// ReferenceIDKind describes only interpretations supported by the header.
// A v4 secondary ID can be an IPv4 address or an IPv6-address hash; the observed
// sender's address family does not establish its upstream reference family.
func (o Observation) ReferenceIDKind() string {
	switch {
	case o.Stratum == 0:
		return "kiss_code"
	case o.Stratum == 1:
		return "clock_id"
	case o.Stratum >= 2 && o.Stratum <= 15 && o.Version < 4:
		return "ipv4"
	case o.Stratum >= 2 && o.Stratum <= 15:
		return "ipv4_or_hash"
	default:
		return "opaque"
	}
}

func (o Observation) Role() string {
	switch o.Mode {
	case 1:
		return "symmetric_active"
	case 2:
		return "symmetric_passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	default:
		return "unknown"
	}
}

// Decode accepts versions 1–4 and time modes 1–5. Signed exponents and reserved
// stratum values are preserved without clock-quality heuristics. A malformed or
// oversized tail yields a partial observation, never silently complete input.
// Extension contents and authentication bytes are never retained. Trailing
// 4/20/24-byte authentication-shaped data is opaque, not authenticated evidence.
func Decode(payload []byte, captureTime time.Time) (Observation, error) {
	var o Observation
	if len(payload) < HeaderSize {
		return o, ErrShortHeader
	}
	o.Version, o.Mode, o.LeapIndicator = payload[0]>>3&7, payload[0]&7, payload[0]>>6
	if o.Version < 1 || o.Version > 4 || o.Mode < 1 || o.Mode > 5 {
		return Observation{}, ErrUnsupported
	}
	o.Stratum, o.Poll, o.Precision = payload[1], int8(payload[2]), int8(payload[3])
	o.RootDelay = int32(binary.BigEndian.Uint32(payload[4:8]))
	o.RootDispersion = binary.BigEndian.Uint32(payload[8:12])
	copy(o.ReferenceID[:], payload[12:16])
	o.Reference = ResolveTimestamp(binary.BigEndian.Uint64(payload[16:24]), captureTime)
	o.Origin = ResolveTimestamp(binary.BigEndian.Uint64(payload[24:32]), captureTime)
	o.Receive = ResolveTimestamp(binary.BigEndian.Uint64(payload[32:40]), captureTime)
	o.Transmit = ResolveTimestamp(binary.BigEndian.Uint64(payload[40:48]), captureTime)
	if len(payload) > MaxPacketSize {
		o.Partial, o.Truncated = true, true
		return o, nil
	}
	tail := payload[HeaderSize:]
	o.TrailingBytes = uint32(len(tail))
	for len(tail) > 0 {
		if len(tail) == 4 || len(tail) == 20 || len(tail) == 24 {
			break
		}
		if len(tail) < 4 {
			o.Partial, o.Truncated = true, true
			break
		}
		length := int(binary.BigEndian.Uint16(tail[2:4]))
		if length < 16 || length%4 != 0 {
			o.Partial = true
			break
		}
		if length > len(tail) {
			o.Partial, o.Truncated = true, true
			break
		}
		if o.ExtensionCount >= MaxExtensions {
			o.Partial, o.Truncated = true, true
			break
		}
		o.ExtensionCount++
		tail = tail[length:]
	}
	return o, nil
}
