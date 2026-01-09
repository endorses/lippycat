//go:build cli || hunter || tap || tui || all

// Package ciphers implements TLS cipher suite decryption.
//
// This package provides implementations for common TLS cipher suites used in
// TLS 1.2 and TLS 1.3:
//
// AEAD ciphers (TLS 1.2 and 1.3):
//   - AES-128-GCM, AES-256-GCM
//   - ChaCha20-Poly1305
//
// CBC ciphers (TLS 1.2 only):
//   - AES-128-CBC, AES-256-CBC with HMAC-SHA1/SHA256
//
// Usage:
//
//	cipher, err := ciphers.NewCipher(cipherSuiteID, key, iv)
//	if err != nil {
//	    return err
//	}
//	plaintext, err := cipher.Decrypt(ciphertext, nonce, additionalData)
package ciphers

import "errors"

// Errors returned by cipher operations.
var (
	// ErrAuthenticationFailed indicates AEAD authentication tag verification failed.
	ErrAuthenticationFailed = errors.New("cipher: authentication failed")

	// ErrInvalidKeySize indicates the key size is wrong for the cipher.
	ErrInvalidKeySize = errors.New("cipher: invalid key size")

	// ErrInvalidIVSize indicates the IV/nonce size is wrong.
	ErrInvalidIVSize = errors.New("cipher: invalid IV size")

	// ErrInvalidCiphertext indicates the ciphertext is malformed.
	ErrInvalidCiphertext = errors.New("cipher: invalid ciphertext")

	// ErrInvalidPadding indicates CBC padding verification failed.
	ErrInvalidPadding = errors.New("cipher: invalid padding")

	// ErrMACVerificationFailed indicates HMAC verification failed.
	ErrMACVerificationFailed = errors.New("cipher: MAC verification failed")

	// ErrUnsupportedCipher indicates the cipher suite is not supported.
	ErrUnsupportedCipher = errors.New("cipher: unsupported cipher suite")
)

// Cipher is the interface for TLS record decryption.
type Cipher interface {
	// Decrypt decrypts a TLS record.
	//
	// For AEAD ciphers (GCM, ChaCha20-Poly1305):
	//   - nonce is the full nonce (12 bytes for GCM/ChaCha20)
	//   - additionalData is the AAD (sequence number + header for TLS 1.2,
	//     record header for TLS 1.3)
	//   - ciphertext includes the authentication tag
	//
	// For CBC ciphers:
	//   - nonce is the explicit IV (from record for TLS 1.1+)
	//   - additionalData is used for MAC computation
	//   - ciphertext includes the MAC
	//
	// Returns the decrypted plaintext or an error if decryption/verification fails.
	Decrypt(ciphertext, nonce, additionalData []byte) ([]byte, error)

	// Encrypt encrypts a TLS record (optional, for testing).
	// Same parameter semantics as Decrypt.
	Encrypt(plaintext, nonce, additionalData []byte) ([]byte, error)

	// TagSize returns the authentication tag size in bytes.
	// For AEAD: 16 bytes (GCM) or 16 bytes (Poly1305)
	// For CBC: MAC size (20 for SHA1, 32 for SHA256)
	TagSize() int

	// KeySize returns the cipher key size in bytes.
	KeySize() int

	// NonceSize returns the required nonce size in bytes.
	NonceSize() int

	// IsAEAD returns true if this is an AEAD cipher.
	IsAEAD() bool
}

// CipherMode identifies the cipher operating mode.
type CipherMode int

const (
	// ModeGCM is AES-GCM mode.
	ModeGCM CipherMode = iota
	// ModeChaCha20Poly1305 is ChaCha20-Poly1305 AEAD.
	ModeChaCha20Poly1305
	// ModeCBC is AES-CBC with HMAC.
	ModeCBC
)

// String returns the mode name.
func (m CipherMode) String() string {
	switch m {
	case ModeGCM:
		return "GCM"
	case ModeChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case ModeCBC:
		return "CBC"
	default:
		return "Unknown"
	}
}

// CipherSuiteID constants for supported cipher suites.
const (
	// TLS 1.2 AEAD cipher suites
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305    uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305  uint16 = 0xcca9

	// TLS 1.2 CBC cipher suites
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0x003c
	TLS_RSA_WITH_AES_256_CBC_SHA256         uint16 = 0x003d
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   uint16 = 0xc028
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 uint16 = 0xc023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 uint16 = 0xc024

	// TLS 1.3 cipher suites
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
)

// NewCipher creates a new cipher for the given cipher suite.
// For AEAD ciphers, macKey should be nil.
// For CBC ciphers, macKey is the HMAC key.
func NewCipher(cipherSuiteID uint16, key, iv, macKey []byte) (Cipher, error) {
	switch cipherSuiteID {
	// TLS 1.2 AES-GCM
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return NewAESGCM(key, iv, 128)

	case TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return NewAESGCM(key, iv, 256)

	// TLS 1.2 ChaCha20-Poly1305
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return NewChaCha20Poly1305(key, iv)

	// TLS 1.2 AES-CBC
	case TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return NewAESCBC(key, macKey, 128, HashSHA1)

	case TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return NewAESCBC(key, macKey, 256, HashSHA1)

	case TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return NewAESCBC(key, macKey, 128, HashSHA256)

	case TLS_RSA_WITH_AES_256_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return NewAESCBC(key, macKey, 256, HashSHA256)

	// TLS 1.3 cipher suites
	case TLS_AES_128_GCM_SHA256:
		return NewAESGCMTLS13(key, iv, 128)

	case TLS_AES_256_GCM_SHA384:
		return NewAESGCMTLS13(key, iv, 256)

	case TLS_CHACHA20_POLY1305_SHA256:
		return NewChaCha20Poly1305TLS13(key, iv)

	default:
		return nil, ErrUnsupportedCipher
	}
}

// IsSupportedCipherSuite returns true if the cipher suite is supported.
func IsSupportedCipherSuite(id uint16) bool {
	switch id {
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// IsAEADCipherSuite returns true if the cipher suite uses AEAD.
func IsAEADCipherSuite(id uint16) bool {
	switch id {
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// IsTLS13CipherSuite returns true if the cipher suite is for TLS 1.3.
func IsTLS13CipherSuite(id uint16) bool {
	switch id {
	case TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// GetCipherSuiteName returns a human-readable name for the cipher suite.
func GetCipherSuiteName(id uint16) string {
	switch id {
	case TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case TLS_RSA_WITH_AES_256_CBC_SHA256:
		return "TLS_RSA_WITH_AES_256_CBC_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return "UNKNOWN"
	}
}

// Hash algorithm constants for CBC cipher construction.
const (
	HashSHA1   = 1
	HashSHA256 = 2
	HashSHA384 = 3
)
