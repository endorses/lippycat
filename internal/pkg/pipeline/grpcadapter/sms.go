package grpcadapter

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/sms"
)

// ToProtoSMS converts owned SMS content to additive transport metadata.
// It never encodes raw binary user data as a string.
func ToProtoSMS(message *sms.Message) *data.SMSMetadata {
	if message == nil {
		return nil
	}
	m := sms.Clone(message)
	sanitizeSMS(m)
	result := &data.SMSMetadata{
		Text: m.Text, Status: toSMSStatus(m.Status), Encoding: toSMSEncoding(m.Encoding), Direction: toSMSDirection(m.Direction),
		RpType: uint32(m.RPType), TpType: uint32(m.TPType), Reference: uint32(m.Reference), Dcs: uint32(m.DCS), Pid: uint32(m.PID),
		From: m.From, To: m.To, Header: append([]byte(nil), m.Header...),
	}
	if !m.Timestamp.IsZero() {
		stamp := m.Timestamp.UnixNano()
		result.TimestampUnixNano = &stamp
	}
	if c := m.Concat; c != nil {
		result.Concat = &data.SMSMetadata_Concatenation{Reference: uint32(c.Reference), ReferenceBits: uint32(c.ReferenceBits), Total: uint32(c.Total), Part: uint32(c.Part)}
	}
	a := m.Assembly
	if a.Status != "" || a.ID != "" || a.Text != "" || len(a.Received) != 0 || len(a.Missing) != 0 {
		result.Assembly = &data.SMSMetadata_Assembly{Id: a.ID, Status: toSMSAssemblyStatus(a.Status), Text: a.Text, Received: smsPositionsToProto(a.Received), Missing: smsPositionsToProto(a.Missing)}
	}
	return result
}

// FromProtoSMS converts metadata to owned domain values. Invalid numeric wire
// claims are marked malformed rather than truncated into valid protocol values.
// Unknown future enum values map to the domain's unspecified zero value.
func FromProtoSMS(m *data.SMSMetadata) *sms.Message {
	if m == nil {
		return nil
	}
	result := &sms.Message{
		Text: m.Text, Status: fromSMSStatus(m.Status), Encoding: fromSMSEncoding(m.Encoding), Direction: fromSMSDirection(m.Direction),
		From: m.From, To: m.To, Header: append([]byte(nil), m.Header...),
	}
	valid := m.RpType <= 255 && m.TpType <= 255 && m.Reference <= 255 && m.Dcs <= 255 && m.Pid <= 255
	if valid {
		result.RPType, result.TPType, result.Reference, result.DCS, result.PID = uint8(m.RpType), uint8(m.TpType), uint8(m.Reference), uint8(m.Dcs), uint8(m.Pid)
	}
	if m.TimestampUnixNano != nil {
		result.Timestamp = time.Unix(0, *m.TimestampUnixNano).UTC()
	}
	if c := m.Concat; c != nil {
		concatValid := (c.ReferenceBits == 8 || c.ReferenceBits == 16) && c.Reference <= 65535 && (c.ReferenceBits != 8 || c.Reference <= 255) && c.Total > 0 && c.Total <= 255 && c.Part > 0 && c.Part <= c.Total
		valid = valid && concatValid
		if concatValid {
			result.Concat = &sms.Concatenation{Reference: uint16(c.Reference), ReferenceBits: uint8(c.ReferenceBits), Total: uint8(c.Total), Part: uint8(c.Part)}
		}
	}
	if a := m.Assembly; a != nil {
		received, receivedValid := smsPositionsFromProto(a.Received)
		missing, missingValid := smsPositionsFromProto(a.Missing)
		valid = valid && receivedValid && missingValid
		result.Assembly = sms.AssemblyInfo{ID: a.Id, Status: fromSMSAssemblyStatus(a.Status), Text: a.Text, Received: received, Missing: missing}
	}
	if !valid {
		result.Status = sms.StatusMalformed
		result.Text = ""
		result.Assembly = sms.AssemblyInfo{}
	}
	sanitizeSMS(result)
	return result
}

func sanitizeSMS(m *sms.Message) {
	if !utf8.ValidString(m.Text) || !utf8.ValidString(m.From) || !utf8.ValidString(m.To) || !utf8.ValidString(m.Assembly.ID) || !utf8.ValidString(m.Assembly.Text) {
		m.Status = sms.StatusMalformed
		m.Text = ""
		m.From = strings.ToValidUTF8(m.From, "�")
		m.To = strings.ToValidUTF8(m.To, "�")
		m.Assembly = sms.AssemblyInfo{}
	}
}

func smsPositionsToProto(positions []uint8) []uint32 {
	if positions == nil {
		return nil
	}
	result := make([]uint32, len(positions))
	for i, part := range positions {
		result[i] = uint32(part)
	}
	return result
}

func smsPositionsFromProto(positions []uint32) ([]uint8, bool) {
	if len(positions) > 255 {
		return nil, false
	}
	if positions == nil {
		return nil, true
	}
	result := make([]uint8, len(positions))
	for i, part := range positions {
		if part == 0 || part > 255 {
			return nil, false
		}
		result[i] = uint8(part)
	}
	return result, true
}

func toSMSStatus(value sms.DecodeStatus) data.SMSMetadata_DecodeStatus {
	switch value {
	case sms.StatusDecoded:
		return data.SMSMetadata_DECODE_STATUS_DECODED
	case sms.StatusControl:
		return data.SMSMetadata_DECODE_STATUS_CONTROL
	case sms.StatusUnsupported:
		return data.SMSMetadata_DECODE_STATUS_UNSUPPORTED
	case sms.StatusMalformed:
		return data.SMSMetadata_DECODE_STATUS_MALFORMED
	case sms.StatusIncomplete:
		return data.SMSMetadata_DECODE_STATUS_INCOMPLETE
	default:
		return data.SMSMetadata_DECODE_STATUS_UNSPECIFIED
	}
}

func fromSMSStatus(value data.SMSMetadata_DecodeStatus) sms.DecodeStatus {
	switch value {
	case data.SMSMetadata_DECODE_STATUS_DECODED:
		return sms.StatusDecoded
	case data.SMSMetadata_DECODE_STATUS_CONTROL:
		return sms.StatusControl
	case data.SMSMetadata_DECODE_STATUS_UNSUPPORTED:
		return sms.StatusUnsupported
	case data.SMSMetadata_DECODE_STATUS_MALFORMED:
		return sms.StatusMalformed
	case data.SMSMetadata_DECODE_STATUS_INCOMPLETE:
		return sms.StatusIncomplete
	default:
		return ""
	}
}

func toSMSEncoding(value sms.Encoding) data.SMSMetadata_Encoding {
	switch value {
	case sms.EncodingGSM7:
		return data.SMSMetadata_ENCODING_GSM7
	case sms.EncodingUCS2:
		return data.SMSMetadata_ENCODING_UCS2
	case sms.EncodingBinary:
		return data.SMSMetadata_ENCODING_BINARY
	case sms.EncodingUnknown:
		return data.SMSMetadata_ENCODING_UNKNOWN
	default:
		return data.SMSMetadata_ENCODING_UNSPECIFIED
	}
}

func fromSMSEncoding(value data.SMSMetadata_Encoding) sms.Encoding {
	switch value {
	case data.SMSMetadata_ENCODING_GSM7:
		return sms.EncodingGSM7
	case data.SMSMetadata_ENCODING_UCS2:
		return sms.EncodingUCS2
	case data.SMSMetadata_ENCODING_BINARY:
		return sms.EncodingBinary
	case data.SMSMetadata_ENCODING_UNKNOWN:
		return sms.EncodingUnknown
	default:
		return ""
	}
}

func toSMSDirection(value sms.Direction) data.SMSMetadata_Direction {
	switch value {
	case sms.DirectionMO:
		return data.SMSMetadata_DIRECTION_MOBILE_ORIGINATED
	case sms.DirectionMT:
		return data.SMSMetadata_DIRECTION_MOBILE_TERMINATED
	case sms.DirectionUnknown:
		return data.SMSMetadata_DIRECTION_UNKNOWN
	default:
		return data.SMSMetadata_DIRECTION_UNSPECIFIED
	}
}

func fromSMSDirection(value data.SMSMetadata_Direction) sms.Direction {
	switch value {
	case data.SMSMetadata_DIRECTION_MOBILE_ORIGINATED:
		return sms.DirectionMO
	case data.SMSMetadata_DIRECTION_MOBILE_TERMINATED:
		return sms.DirectionMT
	case data.SMSMetadata_DIRECTION_UNKNOWN:
		return sms.DirectionUnknown
	default:
		return ""
	}
}

func toSMSAssemblyStatus(value sms.AssemblyStatus) data.SMSMetadata_AssemblyStatus {
	switch value {
	case sms.AssemblyNone:
		return data.SMSMetadata_ASSEMBLY_STATUS_NONE
	case sms.AssemblyPending:
		return data.SMSMetadata_ASSEMBLY_STATUS_PENDING
	case sms.AssemblyComplete:
		return data.SMSMetadata_ASSEMBLY_STATUS_COMPLETE
	case sms.AssemblyConflict:
		return data.SMSMetadata_ASSEMBLY_STATUS_CONFLICT
	case sms.AssemblyExpired:
		return data.SMSMetadata_ASSEMBLY_STATUS_EXPIRED
	case sms.AssemblyResourceLimited:
		return data.SMSMetadata_ASSEMBLY_STATUS_RESOURCE_LIMITED
	default:
		return data.SMSMetadata_ASSEMBLY_STATUS_UNSPECIFIED
	}
}

func fromSMSAssemblyStatus(value data.SMSMetadata_AssemblyStatus) sms.AssemblyStatus {
	switch value {
	case data.SMSMetadata_ASSEMBLY_STATUS_NONE:
		return sms.AssemblyNone
	case data.SMSMetadata_ASSEMBLY_STATUS_PENDING:
		return sms.AssemblyPending
	case data.SMSMetadata_ASSEMBLY_STATUS_COMPLETE:
		return sms.AssemblyComplete
	case data.SMSMetadata_ASSEMBLY_STATUS_CONFLICT:
		return sms.AssemblyConflict
	case data.SMSMetadata_ASSEMBLY_STATUS_EXPIRED:
		return sms.AssemblyExpired
	case data.SMSMetadata_ASSEMBLY_STATUS_RESOURCE_LIMITED:
		return sms.AssemblyResourceLimited
	default:
		return ""
	}
}
