package sms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strings"
	"time"
)

// Stable errors permit callers to classify failures without exposing raw data.
var (
	ErrIncomplete  = errors.New("incomplete SMS")
	ErrMalformed   = errors.New("malformed SMS")
	ErrUnsupported = errors.New("unsupported SMS")
)

// IsSMS recognizes the registered binary SMS media type, including parameters.
func IsSMS(contentType string) bool {
	t, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(t, "application/vnd.3gpp.sms")
}

type cursor struct {
	b []byte
	n int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b)-c.n {
		return nil, ErrIncomplete
	}
	b := c.b[c.n : c.n+n]
	c.n += n
	return b, nil
}
func (c *cursor) octet() (byte, error) {
	b, e := c.take(1)
	if e != nil {
		return 0, e
	}
	return b[0], nil
}
func (c *cursor) lv() ([]byte, error) {
	n, e := c.octet()
	if e != nil {
		return nil, e
	}
	return c.take(int(n))
}
func invalid(s string) error     { return fmt.Errorf("%w: %s", ErrMalformed, s) }
func unsupported(s string) error { return fmt.Errorf("%w: %s", ErrUnsupported, s) }

// Decode reads an RPDU, returning an owned partial result even on failure. Errors
// are content-free and classified with errors.Is. A successful control message
// has StatusControl and is never treated as decoded user text.
func Decode(body []byte) (*Message, error) {
	m := &Message{Encoding: EncodingUnknown, Direction: DirectionUnknown}
	err := decodeRP(body, m)
	if err != nil {
		switch {
		case errors.Is(err, ErrIncomplete):
			m.Status = StatusIncomplete
		case errors.Is(err, ErrUnsupported):
			m.Status = StatusUnsupported
		default:
			m.Status = StatusMalformed
		}
	}
	return m, err
}

func decodeRP(body []byte, m *Message) error {
	c := cursor{b: body}
	t, err := c.octet()
	if err != nil {
		return err
	}
	m.RPType = t
	m.Reference, err = c.octet()
	if err != nil {
		return err
	}
	if t > 6 {
		return unsupported("RP message type")
	}
	if t&1 == 0 {
		m.Direction = DirectionMO
	} else {
		m.Direction = DirectionMT
	}
	if t != 0 && t != 1 {
		m.Status = StatusControl
		if t == 4 || t == 5 {
			cause, e := c.lv()
			if e != nil {
				return e
			}
			if len(cause) < 1 || len(cause) > 2 {
				return invalid("RP cause length")
			}
		}
		if c.n < len(c.b) {
			if t == 6 {
				return invalid("RP-SMMA length")
			}
			iei, e := c.octet()
			if e != nil {
				return e
			}
			if iei != 0x41 {
				return invalid("RP user-data element")
			}
			if _, e = c.lv(); e != nil {
				return e
			}
		}
		if c.n != len(c.b) {
			return invalid("trailing RP data")
		}
		return nil
	}
	// RP addresses identify service centres, not the other SMS user. Do not
	// substitute them for an absent TPDU party.
	for range 2 {
		a, e := c.lv()
		if e != nil {
			return e
		}
		if len(a) > 12 {
			return invalid("RP address length")
		}
	}
	tp, e := c.lv()
	if e != nil {
		return e
	}
	if len(tp) == 0 {
		return invalid("empty TPDU")
	}
	if c.n != len(c.b) {
		return invalid("trailing RP data")
	}
	return decodeTP(tp, m)
}

func decodeTP(tp []byte, m *Message) error {
	c := cursor{b: tp}
	first, err := c.octet()
	if err != nil {
		return err
	}
	m.TPType = first & 3
	if (m.Direction == DirectionMO && m.TPType != 1) || (m.Direction == DirectionMT && m.TPType != 0) {
		if m.TPType == 3 {
			return unsupported("reserved TP message type")
		}
		if m.Direction == DirectionMO && m.TPType == 2 {
			return unsupported("SMS-COMMAND")
		}
		m.Status = StatusControl
		return nil
	}
	if m.Direction == DirectionMO {
		if _, err = c.octet(); err != nil {
			return err
		}
	}
	address, err := readAddress(&c)
	if err != nil {
		return err
	}
	if m.Direction == DirectionMO {
		m.To = address
	} else {
		m.From = address
	}
	m.PID, err = c.octet()
	if err != nil {
		return err
	}
	m.DCS, err = c.octet()
	if err != nil {
		return err
	}
	if m.Direction == DirectionMT {
		stamp, e := c.take(7)
		if e != nil {
			return e
		}
		m.Timestamp, e = timestamp(stamp)
		if e != nil {
			return e
		}
	} else {
		// VPF: absent, enhanced (7 octets), relative (1), absolute (7).
		n := []int{0, 7, 1, 7}[(first>>3)&3]
		if _, err = c.take(n); err != nil {
			return err
		}
	}
	udl, err := c.octet()
	if err != nil {
		return err
	}
	m.Encoding, err = coding(m.DCS)
	if err != nil {
		return err
	}
	n := int(udl)
	if m.Encoding == EncodingGSM7 {
		n = (n*7 + 7) / 8
	}
	if n > 140 {
		return invalid("user data exceeds SMS limit")
	}
	ud, err := c.take(n)
	if err != nil {
		return err
	}
	if c.n != len(c.b) {
		return invalid("trailing TP data")
	}
	header := 0
	if first&0x40 != 0 {
		if len(ud) == 0 {
			return invalid("missing user data header")
		}
		header = int(ud[0]) + 1
		if header > len(ud) {
			return invalid("user data header length")
		}
		if err = parseHeader(ud[1:header], m); err != nil {
			return err
		}
	}
	if m.Encoding == EncodingGSM7 {
		headerSeptets := (header*8 + 6) / 7
		if headerSeptets > int(udl) {
			return invalid("header exceeds septet count")
		}
		m.Text, err = decodeGSM7(ud, headerSeptets*7, int(udl)-headerSeptets)
	} else {
		data := ud[header:]
		if len(data)%2 != 0 {
			return invalid("odd UCS2 length")
		}
		runes := make([]rune, 0, len(data)/2)
		for len(data) > 0 {
			u := binary.BigEndian.Uint16(data)
			if u >= 0xd800 && u <= 0xdfff {
				return invalid("surrogate in UCS2")
			}
			runes = append(runes, rune(u))
			data = data[2:]
		}
		m.Text = string(runes)
	}
	if err != nil {
		return err
	}
	m.Status = StatusDecoded
	return nil
}

func coding(d byte) (Encoding, error) {
	if d&0xc0 == 0 || d&0xc0 == 0x40 {
		if d&0x20 != 0 {
			return EncodingUnknown, unsupported("compressed user data")
		}
		switch (d >> 2) & 3 {
		case 0:
			return EncodingGSM7, nil
		case 1:
			return EncodingBinary, unsupported("8-bit user data")
		case 2:
			return EncodingUCS2, nil
		default:
			return EncodingUnknown, unsupported("reserved alphabet")
		}
	}
	switch d & 0xf0 {
	case 0xc0, 0xd0:
		if d&4 != 0 {
			return EncodingUnknown, unsupported("reserved message waiting coding")
		}
		return EncodingGSM7, nil
	case 0xe0:
		if d&4 != 0 {
			return EncodingUnknown, unsupported("reserved message waiting coding")
		}
		return EncodingUCS2, nil
	case 0xf0:
		if d&8 != 0 {
			return EncodingUnknown, unsupported("reserved class coding")
		}
		if d&4 != 0 {
			return EncodingBinary, unsupported("8-bit user data")
		}
		return EncodingGSM7, nil
	default:
		return EncodingUnknown, unsupported("reserved coding group")
	}
}

func parseHeader(b []byte, m *Message) error {
	c := cursor{b: b}
	for c.n < len(c.b) {
		id, e := c.octet()
		if e != nil {
			return e
		}
		v, e := c.lv()
		if e != nil {
			return invalid("truncated user data header element")
		}
		switch id {
		case 0, 8:
			if m.Concat != nil {
				return invalid("multiple concatenation elements")
			}
			p := &Concatenation{ReferenceBits: 8}
			if id == 0 {
				if len(v) != 3 {
					return invalid("8-bit concatenation length")
				}
				p.Reference = uint16(v[0])
				p.Total = v[1]
				p.Part = v[2]
			} else {
				if len(v) != 4 {
					return invalid("16-bit concatenation length")
				}
				p.ReferenceBits = 16
				p.Reference = binary.BigEndian.Uint16(v)
				p.Total = v[2]
				p.Part = v[3]
			}
			if p.Total == 0 || p.Part == 0 || p.Part > p.Total {
				return invalid("concatenation position")
			}
			m.Concat = p
		case 0x24, 0x25:
			return unsupported("national-language shift table")
		default:
			m.Header = append(m.Header, id, byte(len(v)))
			m.Header = append(m.Header, v...)
		}
	}
	return nil
}

func readAddress(c *cursor) (string, error) {
	n, e := c.octet()
	if e != nil {
		return "", e
	}
	toa, e := c.octet()
	if e != nil {
		return "", e
	}
	if n > 20 {
		return "", invalid("TP address length")
	}
	if toa&0x80 == 0 {
		return "", invalid("TP address type")
	}
	b, e := c.take((int(n) + 1) / 2)
	if e != nil {
		return "", e
	}
	if toa&0x70 == 0x50 {
		return decodeGSM7(b, 0, int(n)*4/7)
	}
	const digits = "0123456789*#abc"
	var s strings.Builder
	if toa&0x70 == 0x10 && n > 0 {
		s.WriteByte('+')
	}
	for i := 0; i < int(n); i++ {
		v := b[i/2] >> uint((i%2)*4) & 15
		if v == 15 {
			return "", invalid("address digit")
		}
		s.WriteByte(digits[v])
	}
	if n%2 != 0 && b[len(b)-1]>>4 != 15 {
		return "", invalid("address padding")
	}
	return s.String(), nil
}

func timestamp(b []byte) (time.Time, error) {
	v := [7]int{}
	for i, x := range b {
		if i == 6 {
			x &^= 8
		}
		if x&15 > 9 || x>>4 > 9 {
			return time.Time{}, invalid("timestamp digits")
		}
		v[i] = int(x&15)*10 + int(x>>4)
	}
	year := 2000 + v[0]
	if v[0] >= 70 {
		year = 1900 + v[0]
	}
	zone := v[6] * 15 * 60
	if b[6]&8 != 0 {
		zone = -zone
	}
	if v[6] > 79 {
		return time.Time{}, invalid("timestamp timezone")
	}
	t := time.Date(year, time.Month(v[1]), v[2], v[3], v[4], v[5], 0, time.FixedZone("", zone))
	if int(t.Month()) != v[1] || t.Day() != v[2] || t.Hour() != v[3] || t.Minute() != v[4] || t.Second() != v[5] {
		return time.Time{}, invalid("timestamp range")
	}
	return t, nil
}
