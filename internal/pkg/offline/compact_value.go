package offline

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// Schema-v2 field order is explicitly frozen here, independent of Go declaration
// order. Field additions require an explicit schema-version decision. Integer
// widths follow the declared fixed-width types; Go int is always signed 64-bit.
// Strings and containers have uint32 lengths; containers, pointers and bools
// use one-byte presence/value markers. Timestamps use int64 seconds + uint32 ns.
var compactFieldNames = map[reflect.Type][]string{
	reflect.TypeOf(compactRow{}):              {"Argument", "Interface", "Sequence", "Locator", "Context", "PhysicalOrdinal", "OriginalCaptured", "OriginalWire", "OriginalLink", "Derived", "Captured", "Original", "Timestamp", "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol", "Info", "Node", "Device", "Transport", "Length", "LinkType", "Projection", "NodeRef", "DeviceRef", "ContextRef"},
	reflect.TypeOf(compactProjection{}):       {"Presence", "User", "From", "To", "CallID", "Method", "Codec", "FromTag", "ToTag", "IMSI", "IMEI", "Status", "IsRTP", "SequenceNum", "SSRC", "QueryName", "QueryType", "QueryResponseTimeMs", "AnswerPresent", "TTL", "SNI", "JA3", "Host", "Path", "HTTPMethod", "StatusCode", "ContentLength"},
	reflect.TypeOf(compactMetadata{}):         {"VoIP", "DNS", "Email", "TLS", "HTTP"},
	reflect.TypeOf(compactOverrides{}):        {"Mask", "Metadata"},
	reflect.TypeOf(Locator{}):                 {"BackingID", "Offset", "Length", "Digest"},
	reflect.TypeOf(CaptureContext{}):          {"Format", "ByteOrder", "SectionID", "InterfaceID", "LinkType", "Snaplen", "TimestampResolutionBase", "TimestampResolutionExponent", "TimestampOffset", "TimestampMissing"},
	reflect.TypeOf(types.VoIPMetadata{}):      {"CallID", "Method", "CSeqMethod", "Status", "From", "To", "FromTag", "ToTag", "User", "ContentType", "Body", "Headers", "RawSIP", "IMSI", "IMEI", "AccessNetworkInfo", "VisitedNetworkID", "IsRTP", "SSRC", "PayloadType", "SequenceNum", "SeqNumber", "Timestamp", "Codec", "MergeFromCallID"},
	reflect.TypeOf(types.AccessNetworkInfo{}): {"AccessType", "BSSID", "CellID", "LocalIP", "Parameters"},
	reflect.TypeOf(types.DNSMetadata{}):       {"TransactionID", "IsResponse", "Opcode", "ResponseCode", "Authoritative", "Truncated", "RecursionDesired", "RecursionAvailable", "AuthenticatedData", "CheckingDisabled", "QuestionCount", "AnswerCount", "AuthorityCount", "AdditionalCount", "QueryName", "QueryType", "QueryClass", "Answers", "QueryResponseTimeMs", "CorrelatedQuery", "TunnelingScore", "EntropyScore"},
	reflect.TypeOf(types.DNSAnswer{}):         {"Name", "Type", "Class", "TTL", "Data"},
	reflect.TypeOf(types.EmailMetadata{}):     {"Protocol", "IsServer", "MailFrom", "RcptTo", "Subject", "MessageID", "ContentType", "Command", "ResponseCode", "ResponseText", "STARTTLSOffered", "STARTTLSRequested", "Encrypted", "AuthMethod", "AuthUser", "SessionID", "ServerBanner", "ClientHelo", "Timestamp", "MessageSize", "BodyPreview", "BodySize", "BodyTruncated", "TransactionTimeMs", "Correlated", "IMAPTag", "IMAPCommand", "IMAPMailbox", "IMAPUID", "IMAPSeqNum", "IMAPStatus", "IMAPFlags", "IMAPExists", "IMAPRecent", "IMAPUIDNext", "IMAPUIDValidity", "POP3Command", "POP3Status", "POP3MsgNum", "POP3MsgSize", "POP3MsgCount", "POP3TotalSize"},
	reflect.TypeOf(types.TLSMetadata{}):       {"Version", "VersionRaw", "RecordVersion", "HandshakeType", "IsServer", "SessionID", "SNI", "CipherSuites", "Extensions", "SupportedVersions", "SupportedGroups", "SignatureAlgos", "ECPointFormats", "ALPNProtocols", "SelectedCipher", "Compression", "JA3String", "JA3Fingerprint", "JA3SString", "JA3SFingerprint", "JA4String", "JA4Fingerprint", "FlowKey", "CorrelatedPeer", "HandshakeTimeMs", "RiskScore", "RiskFlags"},
	reflect.TypeOf(types.HTTPMetadata{}):      {"Type", "IsServer", "Method", "Path", "Version", "StatusCode", "StatusReason", "Host", "Server", "ContentType", "ContentLength", "UserAgent", "SessionID", "RequestTime", "ResponseTime", "IsHTTPS", "HasAuth", "CorrelatedResponse", "RequestResponseTimeMs", "Headers", "QueryString", "BodyPreview", "BodySize", "BodyTruncated"},
}

// Resolve the frozen wire order once. These tables are immutable after package
// initialization, so concurrent codecs need no locks or per-record name lookup.
var compactFieldIndexes = func() map[reflect.Type][]int {
	indexes := make(map[reflect.Type][]int, len(compactFieldNames))
	for typ, names := range compactFieldNames {
		indexes[typ] = compactSchemaIndexes(typ, names)
	}
	return indexes
}()

var compactProjectionType = reflect.TypeOf(compactProjection{})
var compactProjectionPresenceIndex = compactSchemaIndexes(compactProjectionType, []string{"Presence"})[0]
var compactProjectionGroupIndexes = func() [][]int {
	groups := make([][]int, len(compactProjectionGroups))
	for i, names := range compactProjectionGroups {
		groups[i] = compactSchemaIndexes(compactProjectionType, names)
	}
	return groups
}()

func compactSchemaIndexes(typ reflect.Type, names []string) []int {
	indexes := make([]int, len(names))
	for i, name := range names {
		field, ok := typ.FieldByName(name)
		if !ok || len(field.Index) != 1 {
			panic(fmt.Sprintf("invalid compact schema field %s.%s", typ, name))
		}
		indexes[i] = field.Index[0]
	}
	return indexes
}

type compactEncoder struct{ encoder }
type compactDecoder struct{ decoder }

// Compact records measure their owned decoded graph directly. This deliberately
// does not depend on the legacy oracle codec's accepted wire-value wrappers.
func compactRecordMemory(value any, max uint64) (uint64, error) {
	var v reflect.Value
	switch p := value.(type) {
	case *Detail:
		if p == nil {
			return 0, fmt.Errorf("nil compact detail")
		}
		v = reflect.ValueOf(p).Elem()
	case *Summary:
		if p == nil {
			return 0, fmt.Errorf("nil compact summary")
		}
		v = reflect.ValueOf(p).Elem()
	default:
		return 0, fmt.Errorf("unsupported compact record %T", value)
	}
	n := uint64(v.Type().Size())
	err := measureMemory(v, &n, max)
	return n, err
}

func compactIntegerBytes(kind reflect.Kind) int {
	switch kind {
	case reflect.Int8, reflect.Uint8:
		return 1
	case reflect.Int16, reflect.Uint16:
		return 2
	case reflect.Int32, reflect.Uint32:
		return 4
	default:
		return 8
	}
}
func (e *compactEncoder) integer(n uint64, width int) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return e.put(b[:width])
}
func (d *compactDecoder) integer(width int) (uint64, error) {
	p, err := d.take(uint64(width))
	if err != nil {
		return 0, err
	}
	var b [8]byte
	copy(b[:], p)
	return binary.LittleEndian.Uint64(b[:]), nil
}

func encodeCompactValue(value any, max uint64) ([]byte, error) {
	if row, ok := value.(compactRow); ok {
		return encodeCompactRow(&row, max, 0)
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() || max > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("invalid compact value or budget")
	}
	memory := uint64(v.Type().Size())
	if err := measureMemory(v, &memory, max); err != nil {
		return nil, err
	}
	if memory > max {
		return nil, fmt.Errorf("compact value exceeds memory budget")
	}
	e := compactEncoder{encoder: encoder{max: max}}
	if err := e.value(v); err != nil {
		return nil, err
	}
	e = compactEncoder{encoder: encoder{max: max, data: make([]byte, 0, int(e.size))}}
	if err := e.value(v); err != nil {
		return nil, err
	}
	return e.data, nil
}
func decodeCompactValue(data []byte, target any, max uint64) error {
	v := reflect.ValueOf(target)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() || uint64(len(data)) > max {
		return fmt.Errorf("invalid compact destination or size")
	}
	result := reflect.New(v.Elem().Type()).Elem()
	memory := uint64(result.Type().Size())
	if memory > max {
		return fmt.Errorf("compact value exceeds memory budget")
	}
	d := compactDecoder{decoder: decoder{data: data, max: max, memory: memory}}
	if err := d.value(result); err != nil {
		return err
	}
	if d.pos != len(data) {
		return fmt.Errorf("compact trailing value bytes")
	}
	v.Elem().Set(result)
	return nil
}

func (e *compactEncoder) value(v reflect.Value) error {
	if v.Type() == compactProjectionType {
		presence := v.Field(compactProjectionPresenceIndex).Uint()
		if presence & ^uint64(31) != 0 {
			return fmt.Errorf("invalid compact projection presence")
		}
		if err := e.integer(presence, 1); err != nil {
			return err
		}
		for i, fields := range compactProjectionGroupIndexes {
			if presence&(1<<i) != 0 {
				for _, index := range fields {
					if err := e.value(v.Field(index)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if v.Type() == timestampType {
		t := v.Interface().(time.Time)
		if err := e.number(uint64(t.Unix())); err != nil {
			return err
		}
		return e.integer(uint64(t.Nanosecond()), 4)
	}
	switch v.Kind() {
	case reflect.Struct:
		fields, ok := compactFieldIndexes[v.Type()]
		if !ok {
			return fmt.Errorf("unsupported compact struct %s", v.Type())
		}
		for _, index := range fields {
			field := v.Field(index)
			if err := e.value(field); err != nil {
				return err
			}
		}
	case reflect.Pointer:
		if v.IsNil() {
			return e.put([]byte{0})
		}
		if err := e.put([]byte{1}); err != nil {
			return err
		}
		return e.value(v.Elem())
	case reflect.Bool:
		if v.Bool() {
			return e.put([]byte{1})
		}
		return e.put([]byte{0})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.integer(uint64(v.Int()), compactIntegerBytes(v.Kind()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.integer(v.Uint(), compactIntegerBytes(v.Kind()))
	case reflect.Float64:
		return e.number(math.Float64bits(v.Float()))
	case reflect.String:
		if err := e.length(v.Len()); err != nil {
			return err
		}
		if err := addBudget(&e.size, uint64(v.Len()), e.max); err != nil {
			return err
		}
		if e.data != nil {
			e.data = append(e.data, v.String()...)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Map:
		if v.IsNil() {
			return e.put([]byte{0})
		}
		if err := e.put([]byte{1}); err != nil {
			return err
		}
		if err := e.length(v.Len()); err != nil {
			return err
		}
		if v.Kind() == reflect.Map {
			keys := v.MapKeys()
			sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
			for _, key := range keys {
				if err := e.value(key); err != nil {
					return err
				}
				if err := e.value(v.MapIndex(key)); err != nil {
					return err
				}
			}
			return nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if err := addBudget(&e.size, uint64(v.Len()), e.max); err != nil {
				return err
			}
			if e.data != nil {
				e.data = append(e.data, v.Bytes()...)
			}
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported offline schema type %s", v.Type())
	}
	return nil
}

func (d *compactDecoder) value(v reflect.Value) error {
	if v.Type() == compactProjectionType {
		presence, err := d.integer(1)
		if err != nil {
			return err
		}
		if presence & ^uint64(31) != 0 {
			return fmt.Errorf("invalid compact projection presence")
		}
		v.Field(compactProjectionPresenceIndex).SetUint(presence)
		for i, fields := range compactProjectionGroupIndexes {
			if presence&(1<<i) != 0 {
				for _, index := range fields {
					if err := d.value(v.Field(index)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if v.Type() == timestampType {
		s, err := d.number()
		if err != nil {
			return err
		}
		ns, err := d.integer(4)
		if err != nil {
			return err
		}
		if ns >= 1e9 {
			return fmt.Errorf("invalid offline timestamp nanoseconds")
		}
		v.Set(reflect.ValueOf(time.Unix(int64(s), int64(ns)).UTC()))
		return nil
	}
	switch v.Kind() {
	case reflect.Struct:
		fields, ok := compactFieldIndexes[v.Type()]
		if !ok {
			return fmt.Errorf("unsupported compact struct %s", v.Type())
		}
		for _, index := range fields {
			field := v.Field(index)
			if err := d.value(field); err != nil {
				return err
			}
		}
	case reflect.Pointer:
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] == 0 {
			return nil
		}
		if p[0] != 1 {
			return fmt.Errorf("invalid offline pointer marker")
		}
		if err = addBudget(&d.memory, uint64(v.Type().Elem().Size()), d.max); err != nil {
			return err
		}
		v.Set(reflect.New(v.Type().Elem()))
		return d.value(v.Elem())
	case reflect.Bool:
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] > 1 {
			return fmt.Errorf("invalid offline boolean")
		}
		v.SetBool(p[0] == 1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		width := compactIntegerBytes(v.Kind())
		n, err := d.integer(width)
		if err != nil {
			return err
		}
		signed := int64(n)
		if width < 8 {
			shift := uint(64 - width*8)
			signed = int64(n<<shift) >> shift
		}
		if v.OverflowInt(signed) {
			return fmt.Errorf("compact integer overflow")
		}
		v.SetInt(signed)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := d.integer(compactIntegerBytes(v.Kind()))
		if err != nil {
			return err
		}
		if v.OverflowUint(n) {
			return fmt.Errorf("compact integer overflow")
		}
		v.SetUint(n)
	case reflect.Float64:
		n, err := d.number()
		if err != nil {
			return err
		}
		v.SetFloat(math.Float64frombits(n))
	case reflect.String:
		n, err := d.integer(4)
		if err != nil {
			return err
		}
		if err = addBudget(&d.memory, n, d.max); err != nil {
			return err
		}
		p, err := d.take(n)
		if err != nil {
			return err
		}
		v.SetString(string(p))
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := d.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Map:
		marker, err := d.take(1)
		if err != nil {
			return err
		}
		if marker[0] == 0 {
			return nil
		}
		if marker[0] != 1 {
			return fmt.Errorf("invalid compact container marker")
		}
		n, err := d.integer(4)
		if err != nil {
			return err
		}
		// Every non-byte element occupies at least one payload byte. Check this
		// independently of the memory cap before allocating a backing array/map.
		if n > uint64(len(d.data)-d.pos) {
			return io.ErrUnexpectedEOF
		}
		size := uint64(128)
		if v.Kind() == reflect.Slice {
			size = uint64(v.Type().Elem().Size())
		}
		if err = addProduct(&d.memory, n, size, d.max); err != nil {
			return err
		}
		if v.Kind() == reflect.Map {
			if err = addBudget(&d.memory, 512, d.max); err != nil {
				return err
			}
			v.Set(reflect.MakeMapWithSize(v.Type(), int(n)))
			for i := uint64(0); i < n; i++ {
				k := reflect.New(v.Type().Key()).Elem()
				val := reflect.New(v.Type().Elem()).Elem()
				if err = d.value(k); err != nil {
					return err
				}
				if err = d.value(val); err != nil {
					return err
				}
				if v.MapIndex(k).IsValid() {
					return fmt.Errorf("duplicate offline map key")
				}
				v.SetMapIndex(k, val)
			}
			return nil
		}
		v.Set(reflect.MakeSlice(v.Type(), int(n), int(n)))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			p, err := d.take(n)
			if err != nil {
				return err
			}
			reflect.Copy(v, reflect.ValueOf(p))
			return nil
		}
		for i := 0; i < int(n); i++ {
			if err = d.value(v.Index(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported offline schema type %s", v.Type())
	}
	return nil
}

// encodeCompactFields returns schema-ordered top-level columns. Concatenating
// the returned fields is exactly encodeCompactValue's row representation.
func encodeCompactFields(value any, max uint64) ([][]byte, error) {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return nil, fmt.Errorf("invalid compact column value")
	}
	indexes, ok := compactFieldIndexes[v.Type()]
	if !ok {
		return nil, fmt.Errorf("unsupported compact column type %s", v.Type())
	}
	memory := uint64(v.Type().Size())
	if max > uint64(int(^uint(0)>>1)) || memory > max {
		return nil, fmt.Errorf("invalid compact column memory budget")
	}
	if err := measureMemory(v, &memory, max); err != nil {
		return nil, err
	}
	columns := make([][]byte, 0, len(indexes))
	var total uint64
	for _, index := range indexes {
		field := v.Field(index)
		e := compactEncoder{encoder: encoder{max: max - total}}
		if err := e.value(field); err != nil {
			return nil, err
		}
		e = compactEncoder{encoder: encoder{max: max - total, data: make([]byte, 0, int(e.size))}}
		if err := e.value(field); err != nil {
			return nil, err
		}
		total += e.size
		columns = append(columns, e.data)
	}
	return columns, nil
}

var compactProjectionGroups = [][]string{
	{"User", "From", "To", "CallID", "Method", "Codec", "FromTag", "ToTag", "IMSI", "IMEI", "Status", "IsRTP", "SequenceNum", "SSRC"},
	{"QueryName", "QueryType", "QueryResponseTimeMs", "AnswerPresent", "TTL"},
	{},
	{"SNI", "JA3"},
	{"Host", "Path", "HTTPMethod", "StatusCode", "ContentLength"},
}

func (e *compactEncoder) length(n int) error {
	if uint64(n) > math.MaxUint32 {
		return fmt.Errorf("compact length overflow")
	}
	return e.integer(uint64(n), 4)
}
func decodeCompactFields(parts [][]byte, target any, max uint64) error {
	v := reflect.ValueOf(target)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("invalid compact columns destination")
	}
	indexes, ok := compactFieldIndexes[v.Elem().Type()]
	if !ok || len(indexes) != len(parts) {
		return fmt.Errorf("invalid compact column count")
	}
	var size uint64
	for _, p := range parts {
		if err := addBudget(&size, uint64(len(p)), max); err != nil {
			return err
		}
	}
	result := reflect.New(v.Elem().Type()).Elem()
	memory := uint64(result.Type().Size())
	if memory > max {
		return fmt.Errorf("compact columns exceed memory budget")
	}
	for i, index := range indexes {
		d := compactDecoder{decoder: decoder{data: parts[i], max: max, memory: memory}}
		if err := d.value(result.Field(index)); err != nil {
			return err
		}
		if d.pos != len(parts[i]) {
			return fmt.Errorf("trailing compact column bytes")
		}
		memory = d.memory
	}
	v.Elem().Set(result)
	return nil
}
