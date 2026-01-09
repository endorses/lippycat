//go:build cli || hunter || tap || tui || all

package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// AESGCM implements AES-GCM for TLS 1.2.
//
// TLS 1.2 GCM structure:
// - Nonce: 4-byte implicit IV (from key derivation) + 8-byte explicit nonce (from record)
// - Ciphertext: encrypted data + 16-byte authentication tag
// - AAD: seq_num (8) + content_type (1) + version (2) + plaintext_length (2)
type AESGCM struct {
	aead       cipher.AEAD
	implicitIV []byte // 4 bytes for TLS 1.2
	keySize    int
	isTLS13    bool
}

// NewAESGCM creates a new AES-GCM cipher for TLS 1.2.
// keyBits must be 128 or 256.
// iv is the 4-byte implicit IV from key derivation.
func NewAESGCM(key, iv []byte, keyBits int) (*AESGCM, error) {
	expectedKeyLen := keyBits / 8
	if len(key) != expectedKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, expectedKeyLen, len(key))
	}

	// TLS 1.2 GCM uses 4-byte implicit IV
	if len(iv) != 4 {
		return nil, fmt.Errorf("%w: expected 4 bytes for TLS 1.2 implicit IV, got %d", ErrInvalidIVSize, len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	implicitIV := make([]byte, 4)
	copy(implicitIV, iv)

	return &AESGCM{
		aead:       aead,
		implicitIV: implicitIV,
		keySize:    expectedKeyLen,
		isTLS13:    false,
	}, nil
}

// NewAESGCMTLS13 creates a new AES-GCM cipher for TLS 1.3.
// keyBits must be 128 or 256.
// iv is the 12-byte write IV from key derivation.
func NewAESGCMTLS13(key, iv []byte, keyBits int) (*AESGCM, error) {
	expectedKeyLen := keyBits / 8
	if len(key) != expectedKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, expectedKeyLen, len(key))
	}

	// TLS 1.3 GCM uses 12-byte IV
	if len(iv) != 12 {
		return nil, fmt.Errorf("%w: expected 12 bytes for TLS 1.3 IV, got %d", ErrInvalidIVSize, len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	implicitIV := make([]byte, 12)
	copy(implicitIV, iv)

	return &AESGCM{
		aead:       aead,
		implicitIV: implicitIV,
		keySize:    expectedKeyLen,
		isTLS13:    true,
	}, nil
}

// Decrypt decrypts a TLS record using AES-GCM.
//
// For TLS 1.2:
//   - nonce: 8-byte explicit nonce from the record (prepended to ciphertext)
//   - The full 12-byte nonce is: implicitIV (4) + explicitNonce (8)
//   - ciphertext: encrypted data + 16-byte auth tag
//   - additionalData: seq_num (8) + content_type (1) + version (2) + plaintext_length (2)
//
// For TLS 1.3:
//   - nonce: full 12-byte nonce (writeIV XOR seqNum, computed by caller)
//   - ciphertext: encrypted data + 16-byte auth tag
//   - additionalData: content_type (1) + version (2) + ciphertext_length (2)
func (g *AESGCM) Decrypt(ciphertext, nonce, additionalData []byte) ([]byte, error) {
	var fullNonce []byte

	if g.isTLS13 {
		// TLS 1.3: nonce is the full 12-byte nonce
		if len(nonce) != 12 {
			return nil, fmt.Errorf("%w: expected 12-byte nonce for TLS 1.3, got %d", ErrInvalidIVSize, len(nonce))
		}
		fullNonce = nonce
	} else {
		// TLS 1.2: nonce is the 8-byte explicit nonce
		if len(nonce) != 8 {
			return nil, fmt.Errorf("%w: expected 8-byte explicit nonce for TLS 1.2, got %d", ErrInvalidIVSize, len(nonce))
		}
		// Construct full nonce: implicitIV (4) + explicitNonce (8)
		fullNonce = make([]byte, 12)
		copy(fullNonce[:4], g.implicitIV)
		copy(fullNonce[4:], nonce)
	}

	// Minimum ciphertext size is the tag size (16 bytes)
	if len(ciphertext) < g.aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext too short (min %d bytes)", ErrInvalidCiphertext, g.aead.Overhead())
	}

	plaintext, err := g.aead.Open(nil, fullNonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	return plaintext, nil
}

// Encrypt encrypts a TLS record using AES-GCM.
func (g *AESGCM) Encrypt(plaintext, nonce, additionalData []byte) ([]byte, error) {
	var fullNonce []byte

	if g.isTLS13 {
		if len(nonce) != 12 {
			return nil, fmt.Errorf("%w: expected 12-byte nonce for TLS 1.3, got %d", ErrInvalidIVSize, len(nonce))
		}
		fullNonce = nonce
	} else {
		if len(nonce) != 8 {
			return nil, fmt.Errorf("%w: expected 8-byte explicit nonce for TLS 1.2, got %d", ErrInvalidIVSize, len(nonce))
		}
		fullNonce = make([]byte, 12)
		copy(fullNonce[:4], g.implicitIV)
		copy(fullNonce[4:], nonce)
	}

	ciphertext := g.aead.Seal(nil, fullNonce, plaintext, additionalData)
	return ciphertext, nil
}

// TagSize returns the GCM authentication tag size (16 bytes).
func (g *AESGCM) TagSize() int {
	return g.aead.Overhead()
}

// KeySize returns the cipher key size in bytes.
func (g *AESGCM) KeySize() int {
	return g.keySize
}

// NonceSize returns the required nonce size.
// For TLS 1.2: 8 bytes (explicit nonce)
// For TLS 1.3: 12 bytes (full nonce)
func (g *AESGCM) NonceSize() int {
	if g.isTLS13 {
		return 12
	}
	return 8
}

// IsAEAD returns true (GCM is an AEAD cipher).
func (g *AESGCM) IsAEAD() bool {
	return true
}

// DecryptTLS12Record decrypts a TLS 1.2 AES-GCM record.
// The record structure is: explicit_nonce (8) + encrypted_content + auth_tag (16)
// This is a convenience function that handles the TLS 1.2 record format.
func (g *AESGCM) DecryptTLS12Record(record []byte, seqNum uint64, contentType uint8, version uint16) ([]byte, error) {
	if g.isTLS13 {
		return nil, fmt.Errorf("use DecryptTLS13Record for TLS 1.3")
	}

	// TLS 1.2 GCM record: explicit_nonce (8) + ciphertext + tag (16)
	// Minimum length: 8 + 0 + 16 = 24 bytes
	if len(record) < 24 {
		return nil, fmt.Errorf("%w: TLS 1.2 GCM record too short", ErrInvalidCiphertext)
	}

	// Extract explicit nonce (first 8 bytes)
	explicitNonce := record[:8]
	ciphertext := record[8:]

	// Compute plaintext length (ciphertext - tag)
	plaintextLen := len(ciphertext) - g.aead.Overhead()

	// Compute additional data
	additionalData := computeTLS12AAD(seqNum, contentType, version, plaintextLen)

	return g.Decrypt(ciphertext, explicitNonce, additionalData)
}

// DecryptTLS13Record decrypts a TLS 1.3 AES-GCM record.
// The record structure is: encrypted_content + auth_tag (16)
// The nonce is constructed by XORing the write IV with the sequence number.
func (g *AESGCM) DecryptTLS13Record(record []byte, seqNum uint64) ([]byte, error) {
	if !g.isTLS13 {
		return nil, fmt.Errorf("use DecryptTLS12Record for TLS 1.2")
	}

	// TLS 1.3 GCM record: ciphertext + tag (16)
	// Minimum length: 0 + 16 = 16 bytes (but inner content type adds 1)
	if len(record) < 17 {
		return nil, fmt.Errorf("%w: TLS 1.3 GCM record too short", ErrInvalidCiphertext)
	}

	// Construct nonce: writeIV XOR padded_seqNum
	nonce := constructTLS13Nonce(g.implicitIV, seqNum)

	// Compute additional data (record header)
	additionalData := computeTLS13AAD(len(record))

	plaintext, err := g.Decrypt(record, nonce, additionalData)
	if err != nil {
		return nil, err
	}

	// TLS 1.3 inner plaintext format: content + content_type (1) + padding (0s)
	// Remove padding and content type
	return removeTLS13Padding(plaintext)
}

// computeTLS12AAD computes the additional authenticated data for TLS 1.2.
// AAD = seq_num (8) + content_type (1) + version (2) + plaintext_length (2)
func computeTLS12AAD(seqNum uint64, contentType uint8, version uint16, plaintextLen int) []byte {
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[:8], seqNum)
	aad[8] = contentType
	binary.BigEndian.PutUint16(aad[9:11], version)
	binary.BigEndian.PutUint16(aad[11:13], uint16(plaintextLen))
	return aad
}

// computeTLS13AAD computes the additional authenticated data for TLS 1.3.
// AAD = opaque_type (1) + legacy_record_version (2) + ciphertext_length (2)
// opaque_type is always 0x17 (application_data)
// legacy_record_version is always 0x0303 (TLS 1.2)
func computeTLS13AAD(ciphertextLen int) []byte {
	aad := make([]byte, 5)
	aad[0] = 0x17 // application_data
	aad[1] = 0x03 // version high byte
	aad[2] = 0x03 // version low byte
	binary.BigEndian.PutUint16(aad[3:5], uint16(ciphertextLen))
	return aad
}

// constructTLS13Nonce constructs the nonce for TLS 1.3.
// nonce = writeIV XOR padded_seqNum
func constructTLS13Nonce(writeIV []byte, seqNum uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, writeIV)

	// XOR with sequence number (right-aligned)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}

	return nonce
}

// removeTLS13Padding removes the TLS 1.3 inner plaintext padding and content type.
// TLS 1.3 inner plaintext: content + content_type (1) + padding (zeros)
// Returns the content without content type and padding.
func removeTLS13Padding(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: empty TLS 1.3 inner plaintext", ErrInvalidCiphertext)
	}

	// Find the content type (last non-zero byte)
	i := len(plaintext) - 1
	for i >= 0 && plaintext[i] == 0 {
		i--
	}

	if i < 0 {
		return nil, fmt.Errorf("%w: TLS 1.3 inner plaintext all zeros", ErrInvalidCiphertext)
	}

	// plaintext[i] is the content type
	// Content is everything before it
	return plaintext[:i], nil
}

// GetInnerContentType extracts the inner content type from TLS 1.3 decrypted plaintext.
// This is useful when you need both the content and the content type.
func GetInnerContentType(plaintext []byte) (content []byte, contentType uint8, err error) {
	if len(plaintext) == 0 {
		return nil, 0, fmt.Errorf("%w: empty TLS 1.3 inner plaintext", ErrInvalidCiphertext)
	}

	// Find the content type (last non-zero byte)
	i := len(plaintext) - 1
	for i >= 0 && plaintext[i] == 0 {
		i--
	}

	if i < 0 {
		return nil, 0, fmt.Errorf("%w: TLS 1.3 inner plaintext all zeros", ErrInvalidCiphertext)
	}

	return plaintext[:i], plaintext[i], nil
}
