//go:build cli || hunter || tap || all

// Package decrypt provides TLS record decryption using session keys
// from SSLKEYLOGFILE format.
//
// This package implements:
// - TLS record layer parsing and reassembly
// - TLS 1.2 key derivation (PRF-based)
// - TLS 1.3 key derivation (HKDF-based)
// - Cipher suite implementations for decryption
package decrypt

import (
	"crypto/cipher"
	"errors"
)

// TLS record content types
const (
	ContentTypeChangeCipherSpec = 20
	ContentTypeAlert            = 21
	ContentTypeHandshake        = 22
	ContentTypeApplicationData  = 23
	ContentTypeHeartbeat        = 24
)

// TLS versions
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// TLS record header size
const RecordHeaderSize = 5

// Maximum TLS record size (RFC 8449 allows up to 16KB + overhead)
const MaxRecordSize = 16384 + 2048

// Hash algorithm identifiers for key derivation
const (
	HashSHA256 = iota
	HashSHA384
)

// Errors
var (
	// ErrInvalidRecord indicates a malformed TLS record.
	ErrInvalidRecord = errors.New("invalid TLS record")

	// ErrRecordTooLarge indicates a record exceeding maximum size.
	ErrRecordTooLarge = errors.New("TLS record too large")

	// ErrInsufficientData indicates not enough data to parse.
	ErrInsufficientData = errors.New("insufficient data")

	// ErrUnsupportedVersion indicates an unsupported TLS version.
	ErrUnsupportedVersion = errors.New("unsupported TLS version")

	// ErrNoKeys indicates no decryption keys available.
	ErrNoKeys = errors.New("no decryption keys available")

	// ErrDecryptionFailed indicates decryption failure.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrUnsupportedCipher indicates an unsupported cipher suite.
	ErrUnsupportedCipher = errors.New("unsupported cipher suite")

	// ErrInvalidMAC indicates MAC verification failure.
	ErrInvalidMAC = errors.New("invalid MAC")

	// ErrInvalidPadding indicates invalid padding (CBC mode).
	ErrInvalidPadding = errors.New("invalid padding")
)

// Record represents a TLS record.
type Record struct {
	// ContentType is the record content type (handshake, application data, etc.)
	ContentType uint8

	// Version is the record layer version.
	Version uint16

	// Fragment is the record payload (may be encrypted).
	Fragment []byte

	// IsEncrypted indicates whether the fragment is encrypted.
	IsEncrypted bool
}

// ContentTypeName returns a human-readable content type name.
func (r *Record) ContentTypeName() string {
	switch r.ContentType {
	case ContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentTypeAlert:
		return "Alert"
	case ContentTypeHandshake:
		return "Handshake"
	case ContentTypeApplicationData:
		return "ApplicationData"
	case ContentTypeHeartbeat:
		return "Heartbeat"
	default:
		return "Unknown"
	}
}

// VersionName returns a human-readable TLS version name.
func VersionName(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSL 3.0"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// Direction indicates the direction of TLS traffic.
type Direction int

const (
	// DirectionClient indicates client-to-server traffic.
	DirectionClient Direction = iota
	// DirectionServer indicates server-to-client traffic.
	DirectionServer
)

// String returns the direction as a string.
func (d Direction) String() string {
	if d == DirectionClient {
		return "client"
	}
	return "server"
}

// SessionState holds the decryption state for a TLS session.
type SessionState struct {
	// TLS version negotiated
	Version uint16

	// Client random from ClientHello (32 bytes)
	ClientRandom [32]byte

	// Server random from ServerHello (32 bytes)
	ServerRandom [32]byte

	// Selected cipher suite
	CipherSuite uint16

	// Derived keys (after key derivation)
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte

	// For CBC mode with HMAC
	ClientMACKey []byte
	ServerMACKey []byte

	// Sequence numbers (per direction)
	ClientSeqNum uint64
	ServerSeqNum uint64

	// Cipher instances (created after key derivation)
	ClientCipher cipher.AEAD
	ServerCipher cipher.AEAD

	// For TLS 1.3, we need to track traffic secrets for key updates
	ClientTrafficSecret []byte
	ServerTrafficSecret []byte

	// Hash algorithm used (SHA-256 or SHA-384)
	HashAlgorithm int

	// Flag indicating encryption is active
	ClientEncrypted bool
	ServerEncrypted bool
}

// GetSeqNum returns the current sequence number for the given direction.
func (s *SessionState) GetSeqNum(dir Direction) uint64 {
	if dir == DirectionClient {
		return s.ClientSeqNum
	}
	return s.ServerSeqNum
}

// IncrementSeqNum increments and returns the sequence number for the direction.
func (s *SessionState) IncrementSeqNum(dir Direction) uint64 {
	if dir == DirectionClient {
		seq := s.ClientSeqNum
		s.ClientSeqNum++
		return seq
	}
	seq := s.ServerSeqNum
	s.ServerSeqNum++
	return seq
}

// GetWriteKey returns the write key for the given direction.
func (s *SessionState) GetWriteKey(dir Direction) []byte {
	if dir == DirectionClient {
		return s.ClientWriteKey
	}
	return s.ServerWriteKey
}

// GetWriteIV returns the write IV for the given direction.
func (s *SessionState) GetWriteIV(dir Direction) []byte {
	if dir == DirectionClient {
		return s.ClientWriteIV
	}
	return s.ServerWriteIV
}

// GetCipher returns the AEAD cipher for the given direction.
func (s *SessionState) GetCipher(dir Direction) cipher.AEAD {
	if dir == DirectionClient {
		return s.ClientCipher
	}
	return s.ServerCipher
}

// IsEncrypted returns whether traffic in the given direction is encrypted.
func (s *SessionState) IsEncrypted(dir Direction) bool {
	if dir == DirectionClient {
		return s.ClientEncrypted
	}
	return s.ServerEncrypted
}

// SetEncrypted sets the encryption state for the given direction.
func (s *SessionState) SetEncrypted(dir Direction, encrypted bool) {
	if dir == DirectionClient {
		s.ClientEncrypted = encrypted
	} else {
		s.ServerEncrypted = encrypted
	}
}

// CipherSuiteInfo contains information about a cipher suite.
type CipherSuiteInfo struct {
	// ID is the cipher suite identifier.
	ID uint16

	// Name is the cipher suite name.
	Name string

	// KeyLen is the key length in bytes.
	KeyLen int

	// IVLen is the IV length in bytes.
	IVLen int

	// MACLen is the MAC length in bytes (0 for AEAD).
	MACLen int

	// HashAlgorithm is SHA-256 or SHA-384.
	HashAlgorithm int

	// IsAEAD indicates whether the cipher is AEAD.
	IsAEAD bool

	// IsTLS13 indicates whether this is a TLS 1.3 cipher suite.
	IsTLS13 bool
}

// Common TLS 1.2 cipher suites
var (
	// TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
	CipherSuiteRSAAES128GCM = CipherSuiteInfo{
		ID: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		KeyLen: 16, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true,
	}

	// TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
	CipherSuiteRSAAES256GCM = CipherSuiteInfo{
		ID: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		KeyLen: 32, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA384, IsAEAD: true,
	}

	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
	CipherSuiteECDHERSAAES128GCM = CipherSuiteInfo{
		ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		KeyLen: 16, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true,
	}

	// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
	CipherSuiteECDHERSAAES256GCM = CipherSuiteInfo{
		ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		KeyLen: 32, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA384, IsAEAD: true,
	}

	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
	CipherSuiteECDHEECDSAAES128GCM = CipherSuiteInfo{
		ID: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		KeyLen: 16, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true,
	}

	// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
	CipherSuiteECDHEECDSAAES256GCM = CipherSuiteInfo{
		ID: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		KeyLen: 32, IVLen: 4, MACLen: 0, HashAlgorithm: HashSHA384, IsAEAD: true,
	}

	// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
	CipherSuiteECDHERSAChaCha20 = CipherSuiteInfo{
		ID: 0xcca8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		KeyLen: 32, IVLen: 12, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true,
	}

	// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
	CipherSuiteECDHEECDSAChaCha20 = CipherSuiteInfo{
		ID: 0xcca9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		KeyLen: 32, IVLen: 12, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true,
	}

	// TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	CipherSuiteRSAAES128CBC = CipherSuiteInfo{
		ID: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA",
		KeyLen: 16, IVLen: 16, MACLen: 20, HashAlgorithm: HashSHA256, IsAEAD: false,
	}

	// TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
	CipherSuiteRSAAES256CBC = CipherSuiteInfo{
		ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA",
		KeyLen: 32, IVLen: 16, MACLen: 20, HashAlgorithm: HashSHA256, IsAEAD: false,
	}

	// TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)
	CipherSuiteRSAAES128CBCSHA256 = CipherSuiteInfo{
		ID: 0x003c, Name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
		KeyLen: 16, IVLen: 16, MACLen: 32, HashAlgorithm: HashSHA256, IsAEAD: false,
	}

	// TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
	CipherSuiteRSAAES256CBCSHA256 = CipherSuiteInfo{
		ID: 0x003d, Name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
		KeyLen: 32, IVLen: 16, MACLen: 32, HashAlgorithm: HashSHA256, IsAEAD: false,
	}
)

// TLS 1.3 cipher suites
var (
	// TLS_AES_128_GCM_SHA256 (0x1301)
	CipherSuiteTLS13AES128GCM = CipherSuiteInfo{
		ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256",
		KeyLen: 16, IVLen: 12, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true, IsTLS13: true,
	}

	// TLS_AES_256_GCM_SHA384 (0x1302)
	CipherSuiteTLS13AES256GCM = CipherSuiteInfo{
		ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384",
		KeyLen: 32, IVLen: 12, MACLen: 0, HashAlgorithm: HashSHA384, IsAEAD: true, IsTLS13: true,
	}

	// TLS_CHACHA20_POLY1305_SHA256 (0x1303)
	CipherSuiteTLS13ChaCha20 = CipherSuiteInfo{
		ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256",
		KeyLen: 32, IVLen: 12, MACLen: 0, HashAlgorithm: HashSHA256, IsAEAD: true, IsTLS13: true,
	}
)

// cipherSuites maps cipher suite IDs to their info.
var cipherSuites = map[uint16]CipherSuiteInfo{
	// TLS 1.2 AEAD
	0x009c: CipherSuiteRSAAES128GCM,
	0x009d: CipherSuiteRSAAES256GCM,
	0xc02f: CipherSuiteECDHERSAAES128GCM,
	0xc030: CipherSuiteECDHERSAAES256GCM,
	0xc02b: CipherSuiteECDHEECDSAAES128GCM,
	0xc02c: CipherSuiteECDHEECDSAAES256GCM,
	0xcca8: CipherSuiteECDHERSAChaCha20,
	0xcca9: CipherSuiteECDHEECDSAChaCha20,

	// TLS 1.2 CBC
	0x002f: CipherSuiteRSAAES128CBC,
	0x0035: CipherSuiteRSAAES256CBC,
	0x003c: CipherSuiteRSAAES128CBCSHA256,
	0x003d: CipherSuiteRSAAES256CBCSHA256,

	// TLS 1.3
	0x1301: CipherSuiteTLS13AES128GCM,
	0x1302: CipherSuiteTLS13AES256GCM,
	0x1303: CipherSuiteTLS13ChaCha20,
}

// GetCipherSuiteInfo returns information about a cipher suite.
// Returns nil if the cipher suite is not supported.
func GetCipherSuiteInfo(id uint16) *CipherSuiteInfo {
	if info, ok := cipherSuites[id]; ok {
		return &info
	}
	return nil
}

// IsSupportedCipherSuite returns whether a cipher suite is supported.
func IsSupportedCipherSuite(id uint16) bool {
	_, ok := cipherSuites[id]
	return ok
}
