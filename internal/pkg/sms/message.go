// Package sms decodes the RP and transfer layers of SMS-over-IMS. It deliberately
// does not depend on SIP framing or the presentation and transport layers.
package sms

import "time"

// DecodeStatus distinguishes empty decoded text from unavailable user content.
type DecodeStatus string

const (
	StatusDecoded     DecodeStatus = "decoded"
	StatusControl     DecodeStatus = "control"
	StatusUnsupported DecodeStatus = "unsupported"
	StatusMalformed   DecodeStatus = "malformed"
	StatusIncomplete  DecodeStatus = "incomplete"
)

// Encoding identifies the user-data alphabet, independently of decode success.
type Encoding string

const (
	EncodingGSM7    Encoding = "gsm7"
	EncodingUCS2    Encoding = "ucs2"
	EncodingBinary  Encoding = "binary"
	EncodingUnknown Encoding = "unknown"
)

// Direction is relative to the mobile station, not the capture interface.
type Direction string

const (
	DirectionMO      Direction = "mobile_originated"
	DirectionMT      Direction = "mobile_terminated"
	DirectionUnknown Direction = "unknown"
)

// Concatenation is the validated concatenation UDH information element.
type Concatenation struct {
	Reference     uint16
	ReferenceBits uint8
	Total         uint8
	Part          uint8
}

// AssemblyStatus describes whether complete text can be used for filtering.
type AssemblyStatus string

const (
	AssemblyNone            AssemblyStatus = "none"
	AssemblyPending         AssemblyStatus = "pending"
	AssemblyComplete        AssemblyStatus = "complete"
	AssemblyConflict        AssemblyStatus = "conflict"
	AssemblyExpired         AssemblyStatus = "expired"
	AssemblyResourceLimited AssemblyStatus = "resource_limited"
)

// AssemblyInfo never replaces per-segment Message.Text. Text is assembled text
// on completion and an explicitly partial preview otherwise.
type AssemblyInfo struct {
	ID       string
	Status   AssemblyStatus
	Text     string
	Received []uint8
	Missing  []uint8
}

// Message owns its decoded content. Unknown protocol values remain absent/zero;
// the Direction and Status disambiguate valid zero-valued RP/TP message types.
type Message struct {
	Text                                string
	Status                              DecodeStatus
	Encoding                            Encoding
	Direction                           Direction
	RPType, TPType, Reference, DCS, PID uint8
	From, To                            string
	Timestamp                           time.Time
	Concat                              *Concatenation
	Assembly                            AssemblyInfo
	// Header is an owned UDH copy used to reject incompatible segment headers.
	// Concatenation elements are removed, because their part numbers differ.
	Header []byte
}

// Clone returns an independent owned copy, or nil for nil input.
func Clone(m *Message) *Message {
	if m == nil {
		return nil
	}
	c := *m
	if m.Concat != nil {
		v := *m.Concat
		c.Concat = &v
	}
	c.Header = append([]byte(nil), m.Header...)
	c.Assembly.Received = append([]uint8(nil), m.Assembly.Received...)
	c.Assembly.Missing = append([]uint8(nil), m.Assembly.Missing...)
	return &c
}
