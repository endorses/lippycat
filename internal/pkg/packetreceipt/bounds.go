package packetreceipt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/endorses/lippycat/api/gen/data"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Scan the JSON bytes before decoding maps, repeated records, or base64 payloads.
// The scanner never copies values. Only bounded object keys are decoded, and
// each collection is rejected before allocating an entry beyond its limit.
func validateJSONBounds(encoded []byte, config StoreConfig) error {
	scanner := jsonBounds{data: encoded, config: config}
	if err := scanner.value("", 0); err != nil {
		return fmt.Errorf("raw custody checkpoint bounds: %w", err)
	}
	scanner.space()
	if scanner.pos != len(encoded) || !json.Valid(encoded) {
		return errors.New("invalid raw custody checkpoint JSON")
	}
	return nil
}

type jsonBounds struct {
	data    []byte
	pos     int
	config  StoreConfig
	records int
}

func (s *jsonBounds) space() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\r', '\n', '\t':
			s.pos++
		default:
			return
		}
	}
}
func (s *jsonBounds) stringBytes(limit int) ([]byte, error) {
	start := s.pos
	if s.pos >= len(s.data) || s.data[s.pos] != '"' {
		return nil, errors.New("expected string")
	}
	s.pos++
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		s.pos++
		if c == '"' {
			if s.pos-start-2 > limit {
				return nil, errors.New("string exceeds bounded length")
			}
			return s.data[start:s.pos], nil
		}
		if c == '\\' {
			if s.pos >= len(s.data) {
				break
			}
			s.pos++
		}
		if s.pos-start-1 > limit {
			return nil, errors.New("string exceeds bounded length")
		}
	}
	return nil, errors.New("unterminated string")
}
func (s *jsonBounds) value(label string, depth int) error {
	if depth > 12 {
		return errors.New("nested JSON exceeds maximum depth")
	}
	s.space()
	if s.pos >= len(s.data) {
		return errors.New("missing value")
	}
	switch s.data[s.pos] {
	case '{':
		s.pos++
		s.space()
		fields := 0
		seen := map[string]struct{}{}
		if s.pos < len(s.data) && s.data[s.pos] == '}' {
			s.pos++
			return nil
		}
		for {
			fields++
			limit := 16
			if label == "sessions" {
				limit = s.config.MaxSessions
			}
			if fields > limit {
				return errors.New("object entry limit exceeded")
			}
			raw, err := s.stringBytes(384)
			if err != nil {
				return err
			}
			var key string
			if err := json.Unmarshal(raw, &key); err != nil {
				return err
			}
			if len(key) > 64 {
				return errors.New("object key limit exceeded")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			s.space()
			if s.pos >= len(s.data) || s.data[s.pos] != ':' {
				return errors.New("missing object separator")
			}
			s.pos++
			if err := s.value(key, depth+1); err != nil {
				return err
			}
			s.space()
			if s.pos >= len(s.data) {
				return errors.New("unterminated object")
			}
			c := s.data[s.pos]
			s.pos++
			if c == '}' {
				return nil
			}
			if c != ',' {
				return errors.New("invalid object separator")
			}
			s.space()
		}
	case '[':
		if label != "records" && label != "losses" {
			return errors.New("unexpected collection")
		}
		s.pos++
		s.space()
		count := 0
		if s.pos < len(s.data) && s.data[s.pos] == ']' {
			s.pos++
			return nil
		}
		for {
			count++
			if label == "records" {
				s.records++
				if s.records > s.config.MaxRecords {
					return errors.New("record history limit exceeded")
				}
			}
			if label == "losses" && count > s.config.MaxLossRanges {
				return errors.New("loss history limit exceeded")
			}
			if err := s.value("", depth+1); err != nil {
				return err
			}
			s.space()
			if s.pos >= len(s.data) {
				return errors.New("unterminated collection")
			}
			c := s.data[s.pos]
			s.pos++
			if c == ']' {
				return nil
			}
			if c != ',' {
				return errors.New("invalid collection separator")
			}
		}
	case '"':
		limit := 1536
		if label == "payload" {
			limit = base64.StdEncoding.EncodedLen(s.config.MaxRecordBytes)
		}
		_, err := s.stringBytes(limit)
		return err
	default:
		start := s.pos
		for s.pos < len(s.data) {
			switch s.data[s.pos] {
			case ',', ']', '}', ' ', '\r', '\n', '\t':
				if s.pos == start {
					return errors.New("missing scalar")
				}
				return nil
			default:
				s.pos++
			}
		}
		if s.pos == start {
			return errors.New("missing scalar")
		}
		return nil
	}
}

// A protobuf byte bound alone permits enormous repeated-message allocation.
// Count nested messages against a finite decoding budget before unmarshalling.
// This counts map entries as messages and rejects groups and excessive depth.
func validateBatchWire(encoded []byte, maxBytes int) error {
	if len(encoded) > maxBytes {
		return errors.New("raw payload record limit exceeded")
	}
	budget := min(maxBytes, 65536)
	return scanProto(encoded, (&data.PacketBatch{}).ProtoReflect().Descriptor(), &budget, 0)
}
func scanProto(encoded []byte, descriptor protoreflect.MessageDescriptor, budget *int, depth int) error {
	if depth > 24 {
		return errors.New("raw payload nested message depth exceeded")
	}
	*budget--
	if *budget < 0 {
		return errors.New("raw payload decoded message limit exceeded")
	}
	for len(encoded) > 0 {
		number, kind, n := protowire.ConsumeTag(encoded)
		if n < 0 {
			return errors.New("invalid raw payload tag")
		}
		encoded = encoded[n:]
		if kind == protowire.StartGroupType || kind == protowire.EndGroupType {
			return errors.New("raw payload protobuf groups are unsupported")
		}
		field := descriptor.Fields().ByNumber(protoreflect.FieldNumber(number))
		if kind == protowire.BytesType && field != nil && field.Message() != nil {
			child, n := protowire.ConsumeBytes(encoded)
			if n < 0 {
				return errors.New("invalid raw payload message length")
			}
			if err := scanProto(child, field.Message(), budget, depth+1); err != nil {
				return err
			}
			encoded = encoded[n:]
		} else {
			n := protowire.ConsumeFieldValue(number, kind, encoded)
			if n < 0 {
				return errors.New("invalid raw payload wire value")
			}
			encoded = encoded[n:]
		}
	}
	return nil
}
