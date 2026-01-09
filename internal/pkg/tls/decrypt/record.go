//go:build cli || hunter || tap || all

package decrypt

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// RecordParser parses TLS record layer.
type RecordParser struct {
	mu sync.RWMutex

	// Partial record data for reassembly
	buffer    []byte
	expecting int // Expected remaining bytes for current record
}

// NewRecordParser creates a new TLS record parser.
func NewRecordParser() *RecordParser {
	return &RecordParser{
		buffer: make([]byte, 0, 16384),
	}
}

// ParseRecords extracts all complete TLS records from the data.
// Returns the parsed records and any remaining partial data.
// Call this with each TCP segment to handle reassembly.
func (p *RecordParser) ParseRecords(data []byte) ([]*Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Append new data to buffer
	p.buffer = append(p.buffer, data...)

	var records []*Record
	for {
		record, remaining, err := p.parseOneRecord(p.buffer)
		if err == ErrInsufficientData {
			// Need more data, keep buffer as-is
			break
		}
		if err != nil {
			// Reset buffer on error
			p.buffer = p.buffer[:0]
			return records, err
		}

		records = append(records, record)
		p.buffer = remaining
	}

	return records, nil
}

// parseOneRecord parses a single TLS record from the data.
// Returns the record, remaining data, and any error.
func (p *RecordParser) parseOneRecord(data []byte) (*Record, []byte, error) {
	// Need at least 5 bytes for header
	if len(data) < RecordHeaderSize {
		return nil, data, ErrInsufficientData
	}

	// Parse header
	contentType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	// Validate content type
	if !isValidContentType(contentType) {
		return nil, nil, fmt.Errorf("%w: invalid content type %d", ErrInvalidRecord, contentType)
	}

	// Validate version (must be 0x03xx for SSL 3.0 through TLS 1.3)
	// Note: TLS 1.3 uses 0x0303 in the record layer for compatibility
	if data[1] != 0x03 || data[2] > 0x04 {
		return nil, nil, fmt.Errorf("%w: invalid version 0x%04x", ErrInvalidRecord, version)
	}

	// Validate length
	if length > MaxRecordSize {
		return nil, nil, fmt.Errorf("%w: length %d exceeds max %d", ErrRecordTooLarge, length, MaxRecordSize)
	}

	// Check if we have complete record
	recordLen := RecordHeaderSize + int(length)
	if len(data) < recordLen {
		return nil, data, ErrInsufficientData
	}

	// Extract fragment
	fragment := make([]byte, length)
	copy(fragment, data[RecordHeaderSize:recordLen])

	record := &Record{
		ContentType: contentType,
		Version:     version,
		Fragment:    fragment,
		IsEncrypted: false, // Will be set by caller based on context
	}

	return record, data[recordLen:], nil
}

// Reset clears the parser state.
func (p *RecordParser) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buffer = p.buffer[:0]
	p.expecting = 0
}

// BufferedBytes returns the number of bytes waiting in the buffer.
func (p *RecordParser) BufferedBytes() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.buffer)
}

// isValidContentType checks if the content type is valid.
func isValidContentType(ct uint8) bool {
	switch ct {
	case ContentTypeChangeCipherSpec,
		ContentTypeAlert,
		ContentTypeHandshake,
		ContentTypeApplicationData,
		ContentTypeHeartbeat:
		return true
	default:
		return false
	}
}

// ParseSingleRecord parses a single TLS record without state.
// Useful for one-shot parsing when you have complete record data.
func ParseSingleRecord(data []byte) (*Record, error) {
	if len(data) < RecordHeaderSize {
		return nil, ErrInsufficientData
	}

	contentType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	if !isValidContentType(contentType) {
		return nil, fmt.Errorf("%w: invalid content type %d", ErrInvalidRecord, contentType)
	}

	if data[1] != 0x03 || data[2] > 0x04 {
		return nil, fmt.Errorf("%w: invalid version 0x%04x", ErrInvalidRecord, version)
	}

	if length > MaxRecordSize {
		return nil, fmt.Errorf("%w: length %d exceeds max %d", ErrRecordTooLarge, length, MaxRecordSize)
	}

	recordLen := RecordHeaderSize + int(length)
	if len(data) < recordLen {
		return nil, ErrInsufficientData
	}

	fragment := make([]byte, length)
	copy(fragment, data[RecordHeaderSize:recordLen])

	return &Record{
		ContentType: contentType,
		Version:     version,
		Fragment:    fragment,
		IsEncrypted: false,
	}, nil
}

// IsEncryptedRecord determines if a record is likely encrypted.
// This is a heuristic based on content type and context.
func IsEncryptedRecord(record *Record, encryptionActive bool) bool {
	// Application data is always encrypted after ChangeCipherSpec
	if record.ContentType == ContentTypeApplicationData {
		return encryptionActive
	}

	// In TLS 1.3, handshake records after ServerHello are encrypted
	// This needs session context to determine
	return encryptionActive
}

// ExtractClientRandom extracts the client random from a ClientHello record.
// Returns nil if not a ClientHello or if parsing fails.
func ExtractClientRandom(record *Record) []byte {
	if record.ContentType != ContentTypeHandshake {
		return nil
	}

	if len(record.Fragment) < 38 {
		return nil
	}

	// Handshake header: Type(1) + Length(3) + Version(2) + Random(32)
	handshakeType := record.Fragment[0]
	if handshakeType != 1 { // ClientHello
		return nil
	}

	// Skip: Type(1) + Length(3) + Version(2) = 6 bytes
	// Random is at offset 6, 32 bytes
	random := make([]byte, 32)
	copy(random, record.Fragment[6:38])
	return random
}

// ExtractServerRandom extracts the server random from a ServerHello record.
// Returns nil if not a ServerHello or if parsing fails.
func ExtractServerRandom(record *Record) []byte {
	if record.ContentType != ContentTypeHandshake {
		return nil
	}

	if len(record.Fragment) < 38 {
		return nil
	}

	// Handshake header: Type(1) + Length(3) + Version(2) + Random(32)
	handshakeType := record.Fragment[0]
	if handshakeType != 2 { // ServerHello
		return nil
	}

	// Skip: Type(1) + Length(3) + Version(2) = 6 bytes
	// Random is at offset 6, 32 bytes
	random := make([]byte, 32)
	copy(random, record.Fragment[6:38])
	return random
}

// ExtractCipherSuite extracts the selected cipher suite from a ServerHello.
// Returns 0 if not a ServerHello or if parsing fails.
func ExtractCipherSuite(record *Record) uint16 {
	if record.ContentType != ContentTypeHandshake {
		return 0
	}

	if len(record.Fragment) < 40 {
		return 0
	}

	handshakeType := record.Fragment[0]
	if handshakeType != 2 { // ServerHello
		return 0
	}

	// Skip: Type(1) + Length(3) + Version(2) + Random(32) = 38 bytes
	// Session ID length at offset 38
	sessionIDLen := int(record.Fragment[38])

	// Cipher suite at offset 39 + sessionIDLen
	cipherOffset := 39 + sessionIDLen
	if len(record.Fragment) < cipherOffset+2 {
		return 0
	}

	return binary.BigEndian.Uint16(record.Fragment[cipherOffset : cipherOffset+2])
}

// ExtractTLSVersion extracts the negotiated TLS version from handshake.
// For TLS 1.3, this checks the supported_versions extension.
func ExtractTLSVersion(record *Record) uint16 {
	if record.ContentType != ContentTypeHandshake {
		return 0
	}

	if len(record.Fragment) < 6 {
		return 0
	}

	handshakeType := record.Fragment[0]

	// Get record layer version (may not be real version for TLS 1.3)
	if len(record.Fragment) < 6 {
		return 0
	}
	version := binary.BigEndian.Uint16(record.Fragment[4:6])

	// For ServerHello, check supported_versions extension for TLS 1.3
	if handshakeType == 2 && version == VersionTLS12 {
		// Parse extensions to find supported_versions
		realVersion := parseSupportedVersionsFromServerHello(record.Fragment)
		if realVersion != 0 {
			return realVersion
		}
	}

	return version
}

// parseSupportedVersionsFromServerHello extracts the real version from
// the supported_versions extension in a ServerHello.
func parseSupportedVersionsFromServerHello(data []byte) uint16 {
	if len(data) < 40 {
		return 0
	}

	// Skip handshake header + version + random
	pos := 38

	// Skip session ID
	if pos >= len(data) {
		return 0
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suite (2 bytes)
	pos += 2

	// Skip compression method (1 byte)
	pos++

	// Extensions
	if pos+2 > len(data) {
		return 0
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	endPos := pos + extLen
	if endPos > len(data) {
		endPos = len(data)
	}

	// Parse extensions looking for supported_versions (type 43)
	for pos+4 <= endPos {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extDataLen > endPos {
			break
		}

		if extType == 43 && extDataLen >= 2 { // supported_versions
			return binary.BigEndian.Uint16(data[pos : pos+2])
		}

		pos += extDataLen
	}

	return 0
}

// StreamReassembler handles TCP stream reassembly for TLS.
type StreamReassembler struct {
	clientParser *RecordParser
	serverParser *RecordParser
}

// NewStreamReassembler creates a new stream reassembler.
func NewStreamReassembler() *StreamReassembler {
	return &StreamReassembler{
		clientParser: NewRecordParser(),
		serverParser: NewRecordParser(),
	}
}

// AddClientData adds data from the client direction.
func (s *StreamReassembler) AddClientData(data []byte) ([]*Record, error) {
	return s.clientParser.ParseRecords(data)
}

// AddServerData adds data from the server direction.
func (s *StreamReassembler) AddServerData(data []byte) ([]*Record, error) {
	return s.serverParser.ParseRecords(data)
}

// Reset clears both parsers.
func (s *StreamReassembler) Reset() {
	s.clientParser.Reset()
	s.serverParser.Reset()
}

// ClientBuffered returns bytes buffered for client direction.
func (s *StreamReassembler) ClientBuffered() int {
	return s.clientParser.BufferedBytes()
}

// ServerBuffered returns bytes buffered for server direction.
func (s *StreamReassembler) ServerBuffered() int {
	return s.serverParser.BufferedBytes()
}
