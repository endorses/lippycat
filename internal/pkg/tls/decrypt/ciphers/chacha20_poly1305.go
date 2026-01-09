//go:build cli || hunter || tap || tui || all

package ciphers

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305 implements ChaCha20-Poly1305 AEAD for TLS.
//
// ChaCha20-Poly1305 is used in both TLS 1.2 and TLS 1.3 with slightly different
// nonce construction:
//
// TLS 1.2 (RFC 7905):
//   - Nonce: 12 bytes = writeIV (12) XOR padded_seqNum (8 bytes, left-padded with zeros)
//   - AAD: seq_num (8) + content_type (1) + version (2) + plaintext_length (2)
//
// TLS 1.3 (RFC 8446):
//   - Nonce: 12 bytes = writeIV (12) XOR padded_seqNum (8 bytes, left-padded with zeros)
//   - AAD: opaque_type (1) + legacy_version (2) + ciphertext_length (2)
type ChaCha20Poly1305 struct {
	aead    cipher.AEAD
	writeIV []byte // 12 bytes
	isTLS13 bool
}

// NewChaCha20Poly1305 creates a ChaCha20-Poly1305 cipher for TLS 1.2.
// key must be 32 bytes, iv must be 12 bytes.
func NewChaCha20Poly1305(key, iv []byte) (*ChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, chacha20poly1305.KeySize, len(key))
	}

	if len(iv) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, chacha20poly1305.NonceSize, len(iv))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
	}

	writeIV := make([]byte, 12)
	copy(writeIV, iv)

	return &ChaCha20Poly1305{
		aead:    aead,
		writeIV: writeIV,
		isTLS13: false,
	}, nil
}

// NewChaCha20Poly1305TLS13 creates a ChaCha20-Poly1305 cipher for TLS 1.3.
// key must be 32 bytes, iv must be 12 bytes.
func NewChaCha20Poly1305TLS13(key, iv []byte) (*ChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, chacha20poly1305.KeySize, len(key))
	}

	if len(iv) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, chacha20poly1305.NonceSize, len(iv))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305: %w", err)
	}

	writeIV := make([]byte, 12)
	copy(writeIV, iv)

	return &ChaCha20Poly1305{
		aead:    aead,
		writeIV: writeIV,
		isTLS13: true,
	}, nil
}

// Decrypt decrypts a TLS record using ChaCha20-Poly1305.
//
// For both TLS 1.2 and TLS 1.3:
//   - nonce: full 12-byte nonce (writeIV XOR padded_seqNum, computed by caller)
//   - ciphertext: encrypted data + 16-byte auth tag
//   - additionalData: varies by TLS version (computed by caller)
func (c *ChaCha20Poly1305) Decrypt(ciphertext, nonce, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, chacha20poly1305.NonceSize, len(nonce))
	}

	// Minimum ciphertext size is the tag size (16 bytes)
	if len(ciphertext) < c.aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext too short (min %d bytes)", ErrInvalidCiphertext, c.aead.Overhead())
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	return plaintext, nil
}

// Encrypt encrypts a TLS record using ChaCha20-Poly1305.
func (c *ChaCha20Poly1305) Encrypt(plaintext, nonce, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, chacha20poly1305.NonceSize, len(nonce))
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// TagSize returns the Poly1305 authentication tag size (16 bytes).
func (c *ChaCha20Poly1305) TagSize() int {
	return c.aead.Overhead()
}

// KeySize returns the ChaCha20 key size (32 bytes).
func (c *ChaCha20Poly1305) KeySize() int {
	return chacha20poly1305.KeySize
}

// NonceSize returns the nonce size (12 bytes).
func (c *ChaCha20Poly1305) NonceSize() int {
	return chacha20poly1305.NonceSize
}

// IsAEAD returns true (ChaCha20-Poly1305 is an AEAD cipher).
func (c *ChaCha20Poly1305) IsAEAD() bool {
	return true
}

// ConstructNonce constructs the nonce for ChaCha20-Poly1305.
// nonce = writeIV XOR padded_seqNum
// This works for both TLS 1.2 and TLS 1.3.
func (c *ChaCha20Poly1305) ConstructNonce(seqNum uint64) []byte {
	return constructChaCha20Nonce(c.writeIV, seqNum)
}

// DecryptTLS12Record decrypts a TLS 1.2 ChaCha20-Poly1305 record.
// Unlike GCM, ChaCha20-Poly1305 in TLS 1.2 does NOT have an explicit nonce in the record.
// The nonce is constructed from writeIV XOR seqNum.
func (c *ChaCha20Poly1305) DecryptTLS12Record(record []byte, seqNum uint64, contentType uint8, version uint16) ([]byte, error) {
	if c.isTLS13 {
		return nil, fmt.Errorf("use DecryptTLS13Record for TLS 1.3")
	}

	// TLS 1.2 ChaCha20 record: ciphertext + tag (16)
	// Minimum length: 0 + 16 = 16 bytes
	if len(record) < 16 {
		return nil, fmt.Errorf("%w: TLS 1.2 ChaCha20 record too short", ErrInvalidCiphertext)
	}

	// Construct nonce
	nonce := c.ConstructNonce(seqNum)

	// Compute plaintext length
	plaintextLen := len(record) - c.aead.Overhead()

	// Compute additional data
	additionalData := computeTLS12AAD(seqNum, contentType, version, plaintextLen)

	return c.Decrypt(record, nonce, additionalData)
}

// DecryptTLS13Record decrypts a TLS 1.3 ChaCha20-Poly1305 record.
func (c *ChaCha20Poly1305) DecryptTLS13Record(record []byte, seqNum uint64) ([]byte, error) {
	if !c.isTLS13 {
		return nil, fmt.Errorf("use DecryptTLS12Record for TLS 1.2")
	}

	// TLS 1.3 ChaCha20 record: ciphertext + tag (16)
	// Minimum length: 1 (content type) + 16 = 17 bytes
	if len(record) < 17 {
		return nil, fmt.Errorf("%w: TLS 1.3 ChaCha20 record too short", ErrInvalidCiphertext)
	}

	// Construct nonce
	nonce := c.ConstructNonce(seqNum)

	// Compute additional data
	additionalData := computeTLS13AAD(len(record))

	plaintext, err := c.Decrypt(record, nonce, additionalData)
	if err != nil {
		return nil, err
	}

	// Remove TLS 1.3 padding and content type
	return removeTLS13Padding(plaintext)
}

// constructChaCha20Nonce constructs the nonce for ChaCha20-Poly1305.
// nonce = writeIV XOR padded_seqNum
func constructChaCha20Nonce(writeIV []byte, seqNum uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, writeIV)

	// XOR with sequence number (right-aligned in the 12-byte nonce)
	// The sequence number is 8 bytes, so it XORs with the last 8 bytes
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}

	return nonce
}

// GetWriteIV returns a copy of the write IV.
// This is useful for debugging and testing.
func (c *ChaCha20Poly1305) GetWriteIV() []byte {
	iv := make([]byte, 12)
	copy(iv, c.writeIV)
	return iv
}

// IsTLS13 returns true if this cipher was created for TLS 1.3.
func (c *ChaCha20Poly1305) IsTLS13() bool {
	return c.isTLS13
}
