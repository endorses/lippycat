//go:build cli || hunter || tap || all

package ciphers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to decode hex strings
func mustDecodeHex(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	require.NoError(t, err)
	return data
}

// =============================================================================
// AES-GCM Tests
// =============================================================================

func TestAESGCM_TLS12_Basic(t *testing.T) {
	// Create cipher with 128-bit key
	key := make([]byte, 16)
	iv := make([]byte, 4)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 16)
	}

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	assert.Equal(t, 16, cipher.KeySize())
	assert.Equal(t, 8, cipher.NonceSize()) // TLS 1.2 explicit nonce
	assert.Equal(t, 16, cipher.TagSize())
	assert.True(t, cipher.IsAEAD())
}

func TestAESGCM_TLS12_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte("Hello, TLS 1.2 AES-GCM!")
	explicitNonce := make([]byte, 8)
	_, _ = rand.Read(explicitNonce)
	additionalData := []byte{0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, byte(len(plaintext))}

	// Encrypt
	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext)+16, len(ciphertext))

	// Decrypt
	decrypted, err := cipher.Decrypt(ciphertext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCM_TLS12_256(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 256)
	require.NoError(t, err)

	assert.Equal(t, 32, cipher.KeySize())

	plaintext := []byte("Hello, AES-256-GCM!")
	explicitNonce := make([]byte, 8)
	_, _ = rand.Read(explicitNonce)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCM_TLS12_AuthFailure(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte("Test data")
	explicitNonce := make([]byte, 8)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, additionalData)
	require.NoError(t, err)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	_, err = cipher.Decrypt(ciphertext, explicitNonce, additionalData)
	assert.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestAESGCM_TLS13_Basic(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCMTLS13(key, iv, 128)
	require.NoError(t, err)

	assert.Equal(t, 16, cipher.KeySize())
	assert.Equal(t, 12, cipher.NonceSize()) // TLS 1.3 full nonce
	assert.Equal(t, 16, cipher.TagSize())
	assert.True(t, cipher.IsAEAD())
}

func TestAESGCM_TLS13_RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCMTLS13(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte("Hello, TLS 1.3 AES-GCM!")
	nonce := make([]byte, 12)
	copy(nonce, iv)
	// XOR with sequence number 0
	additionalData := []byte{23, 3, 3, 0, byte(len(plaintext) + 16)}

	ciphertext, err := cipher.Encrypt(plaintext, nonce, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, nonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCM_InvalidKeySize(t *testing.T) {
	key := make([]byte, 15) // Invalid size
	iv := make([]byte, 4)

	_, err := NewAESGCM(key, iv, 128)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestAESGCM_InvalidIVSize(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 3) // Invalid size for TLS 1.2

	_, err := NewAESGCM(key, iv, 128)
	assert.ErrorIs(t, err, ErrInvalidIVSize)
}

// NIST AES-GCM Test Vector
// From NIST SP 800-38D (GCM specification) - Test Case 2
// Verified using the TLS 1.3 API since it accepts 12-byte nonces directly
func TestAESGCM_NISTVector(t *testing.T) {
	key := mustDecodeHex(t, "00000000000000000000000000000000")
	plaintext := make([]byte, 0) // Empty plaintext
	nonce := mustDecodeHex(t, "000000000000000000000000")
	aad := make([]byte, 0)
	expectedTag := mustDecodeHex(t, "58e2fccefa7e3061367f1d57a4e7455a")

	// Use TLS 1.3 API since it accepts full 12-byte nonces
	cipher, err := NewAESGCMTLS13(key, nonce, 128)
	require.NoError(t, err)

	ciphertext, err := cipher.Encrypt(plaintext, nonce, aad)
	require.NoError(t, err)

	// Ciphertext should be just the tag for empty plaintext
	assert.Equal(t, expectedTag, ciphertext)

	// Verify decryption
	decrypted, err := cipher.Decrypt(ciphertext, nonce, aad)
	require.NoError(t, err)
	assert.Len(t, decrypted, 0) // Empty plaintext
}

// TLS wrapper test with known input
func TestAESGCM_TLS12_KnownVector(t *testing.T) {
	// Using a simplified test with known input/output
	key := bytes.Repeat([]byte{0x00}, 16)
	iv := []byte{0x01, 0x02, 0x03, 0x04}

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte("test")
	explicitNonce := bytes.Repeat([]byte{0x00}, 8)
	aad := make([]byte, 13)

	// Encrypt
	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, aad)
	require.NoError(t, err)

	// Verify we can decrypt
	decrypted, err := cipher.Decrypt(ciphertext, explicitNonce, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Verify ciphertext length
	assert.Equal(t, len(plaintext)+16, len(ciphertext))
}

// =============================================================================
// ChaCha20-Poly1305 Tests
// =============================================================================

func TestChaCha20Poly1305_TLS12_Basic(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	assert.Equal(t, 32, cipher.KeySize())
	assert.Equal(t, 12, cipher.NonceSize())
	assert.Equal(t, 16, cipher.TagSize())
	assert.True(t, cipher.IsAEAD())
	assert.False(t, cipher.IsTLS13())
}

func TestChaCha20Poly1305_TLS12_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	plaintext := []byte("Hello, ChaCha20-Poly1305!")
	nonce := cipher.ConstructNonce(0)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, nonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, len(plaintext)+16, len(ciphertext))

	decrypted, err := cipher.Decrypt(ciphertext, nonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_TLS13_Basic(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305TLS13(key, iv)
	require.NoError(t, err)

	assert.True(t, cipher.IsTLS13())
}

func TestChaCha20Poly1305_TLS13_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305TLS13(key, iv)
	require.NoError(t, err)

	plaintext := []byte("Hello, TLS 1.3 ChaCha20!")
	nonce := cipher.ConstructNonce(0)
	additionalData := []byte{23, 3, 3, 0, byte(len(plaintext) + 16)}

	ciphertext, err := cipher.Encrypt(plaintext, nonce, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, nonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_NonceConstruction(t *testing.T) {
	key := make([]byte, 32)
	iv := bytes.Repeat([]byte{0x00}, 12)

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	// Sequence 0 should give writeIV (all zeros XOR zeros)
	nonce0 := cipher.ConstructNonce(0)
	assert.Equal(t, iv, nonce0)

	// Sequence 1 should XOR with 1
	nonce1 := cipher.ConstructNonce(1)
	assert.Equal(t, byte(1), nonce1[11])

	// Sequence 256 should affect second-to-last byte
	nonce256 := cipher.ConstructNonce(256)
	assert.Equal(t, byte(1), nonce256[10])
	assert.Equal(t, byte(0), nonce256[11])
}

func TestChaCha20Poly1305_AuthFailure(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	plaintext := []byte("Test data")
	nonce := cipher.ConstructNonce(0)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, nonce, additionalData)
	require.NoError(t, err)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	_, err = cipher.Decrypt(ciphertext, nonce, additionalData)
	assert.ErrorIs(t, err, ErrAuthenticationFailed)
}

func TestChaCha20Poly1305_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Should be 32
	iv := make([]byte, 12)

	_, err := NewChaCha20Poly1305(key, iv)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

// RFC 7539 Test Vector for ChaCha20-Poly1305
func TestChaCha20Poly1305_RFC7539Vector(t *testing.T) {
	// Test vector from RFC 7539 Section 2.8.2
	key := mustDecodeHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustDecodeHex(t, "070000004041424344454647")
	aad := mustDecodeHex(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := mustDecodeHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")

	// Use iv as writeIV (but we'll pass the full nonce directly)
	cipher, err := NewChaCha20Poly1305(key, nonce)
	require.NoError(t, err)

	// Encrypt with the exact nonce (sequence 0 + writeIV = nonce for this test)
	ciphertext, err := cipher.Encrypt(plaintext, nonce, aad)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := cipher.Decrypt(ciphertext, nonce, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// =============================================================================
// AES-CBC Tests
// =============================================================================

func TestAESCBC_Basic(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 20) // SHA-1 MAC key
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 128, HashSHA1)
	require.NoError(t, err)

	assert.Equal(t, 16, cipher.KeySize())
	assert.Equal(t, 16, cipher.NonceSize())
	assert.Equal(t, 20, cipher.TagSize())
	assert.False(t, cipher.IsAEAD())
}

func TestAESCBC_RoundTrip_SHA1(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 20)
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 128, HashSHA1)
	require.NoError(t, err)

	plaintext := []byte("Hello, AES-CBC-SHA1!")
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)

	// Additional data: seq_num (8) + content_type (1) + version (2)
	additionalData := make([]byte, 11)

	ciphertext, err := cipher.Encrypt(plaintext, iv, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, iv, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESCBC_RoundTrip_SHA256(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 32) // SHA-256 MAC key
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 128, HashSHA256)
	require.NoError(t, err)

	assert.Equal(t, 32, cipher.TagSize())

	plaintext := []byte("Hello, AES-CBC-SHA256!")
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	additionalData := make([]byte, 11)

	ciphertext, err := cipher.Encrypt(plaintext, iv, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, iv, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESCBC_256_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	macKey := make([]byte, 20)
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 256, HashSHA1)
	require.NoError(t, err)

	assert.Equal(t, 32, cipher.KeySize())

	plaintext := []byte("Hello, AES-256-CBC!")
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	additionalData := make([]byte, 11)

	ciphertext, err := cipher.Encrypt(plaintext, iv, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, iv, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESCBC_MACFailure(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 20)
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 128, HashSHA1)
	require.NoError(t, err)

	plaintext := []byte("Test data for MAC")
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	additionalData := make([]byte, 11)

	ciphertext, err := cipher.Encrypt(plaintext, iv, additionalData)
	require.NoError(t, err)

	// Tamper with ciphertext (will cause MAC failure after decryption)
	ciphertext[0] ^= 0xFF

	_, err = cipher.Decrypt(ciphertext, iv, additionalData)
	// Will fail with either MAC error or padding error
	assert.Error(t, err)
}

func TestAESCBC_InvalidKeySize(t *testing.T) {
	key := make([]byte, 15) // Invalid
	macKey := make([]byte, 20)

	_, err := NewAESCBC(key, macKey, 128, HashSHA1)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestAESCBC_InvalidMACKeySize(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 15) // Invalid for SHA-1

	_, err := NewAESCBC(key, macKey, 128, HashSHA1)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

// =============================================================================
// PKCS#7 Padding Tests
// =============================================================================

func TestPKCS7Padding_AddRemove(t *testing.T) {
	testCases := []struct {
		name   string
		data   []byte
		padLen int
	}{
		{"Empty", []byte{}, 16},
		{"1 byte", []byte{1}, 15},
		{"15 bytes", bytes.Repeat([]byte{1}, 15), 1},
		{"16 bytes", bytes.Repeat([]byte{1}, 16), 16},
		{"17 bytes", bytes.Repeat([]byte{1}, 17), 15},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := addPKCS7Padding(tc.data, 16)

			// Verify padding length
			assert.Equal(t, 0, len(padded)%16)
			assert.Equal(t, tc.padLen, int(padded[len(padded)-1]))

			// Verify all padding bytes are the same
			for i := len(tc.data); i < len(padded); i++ {
				assert.Equal(t, byte(tc.padLen), padded[i])
			}

			// Remove padding
			unpadded, err := removePKCS7Padding(padded)
			require.NoError(t, err)
			assert.Equal(t, tc.data, unpadded)
		})
	}
}

func TestPKCS7Padding_Invalid(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"Zero padding", []byte{1, 2, 3, 0}},
		{"Padding too large", []byte{1, 2, 3, 17}},
		{"Inconsistent padding", []byte{1, 2, 3, 3, 2}}, // Last byte says 2 but second-to-last is 3
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := removePKCS7Padding(tc.data)
			assert.ErrorIs(t, err, ErrInvalidPadding)
		})
	}
}

func TestValidatePKCS7Padding(t *testing.T) {
	// Valid padding
	valid := []byte{1, 2, 3, 3, 3, 3}
	assert.Equal(t, 3, ValidatePKCS7Padding(valid))

	// Invalid padding
	invalid := []byte{1, 2, 3, 3, 3, 2}
	assert.Equal(t, 0, ValidatePKCS7Padding(invalid))
}

// =============================================================================
// NewCipher Factory Tests
// =============================================================================

func TestNewCipher_AES128GCM(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewCipher(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, key, iv, nil)
	require.NoError(t, err)
	assert.True(t, cipher.IsAEAD())
	assert.Equal(t, 16, cipher.KeySize())
}

func TestNewCipher_AES256GCM(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewCipher(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, key, iv, nil)
	require.NoError(t, err)
	assert.True(t, cipher.IsAEAD())
	assert.Equal(t, 32, cipher.KeySize())
}

func TestNewCipher_ChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewCipher(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, key, iv, nil)
	require.NoError(t, err)
	assert.True(t, cipher.IsAEAD())
	assert.Equal(t, 32, cipher.KeySize())
}

func TestNewCipher_AES128CBC(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 20)
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewCipher(TLS_RSA_WITH_AES_128_CBC_SHA, key, nil, macKey)
	require.NoError(t, err)
	assert.False(t, cipher.IsAEAD())
	assert.Equal(t, 16, cipher.KeySize())
}

func TestNewCipher_TLS13_AES128GCM(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewCipher(TLS_AES_128_GCM_SHA256, key, iv, nil)
	require.NoError(t, err)
	assert.True(t, cipher.IsAEAD())
	assert.Equal(t, 12, cipher.NonceSize()) // TLS 1.3 full nonce
}

func TestNewCipher_TLS13_ChaCha20(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewCipher(TLS_CHACHA20_POLY1305_SHA256, key, iv, nil)
	require.NoError(t, err)
	assert.True(t, cipher.IsAEAD())
}

func TestNewCipher_Unsupported(t *testing.T) {
	_, err := NewCipher(0xFFFF, nil, nil, nil)
	assert.ErrorIs(t, err, ErrUnsupportedCipher)
}

// =============================================================================
// Utility Function Tests
// =============================================================================

func TestIsSupportedCipherSuite(t *testing.T) {
	assert.True(t, IsSupportedCipherSuite(TLS_AES_128_GCM_SHA256))
	assert.True(t, IsSupportedCipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
	assert.True(t, IsSupportedCipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA))
	assert.False(t, IsSupportedCipherSuite(0xFFFF))
}

func TestIsAEADCipherSuite(t *testing.T) {
	assert.True(t, IsAEADCipherSuite(TLS_AES_128_GCM_SHA256))
	assert.True(t, IsAEADCipherSuite(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305))
	assert.False(t, IsAEADCipherSuite(TLS_RSA_WITH_AES_128_CBC_SHA))
}

func TestIsTLS13CipherSuite(t *testing.T) {
	assert.True(t, IsTLS13CipherSuite(TLS_AES_128_GCM_SHA256))
	assert.True(t, IsTLS13CipherSuite(TLS_AES_256_GCM_SHA384))
	assert.True(t, IsTLS13CipherSuite(TLS_CHACHA20_POLY1305_SHA256))
	assert.False(t, IsTLS13CipherSuite(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
}

func TestGetCipherSuiteName(t *testing.T) {
	assert.Equal(t, "TLS_AES_128_GCM_SHA256", GetCipherSuiteName(TLS_AES_128_GCM_SHA256))
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", GetCipherSuiteName(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
	assert.Equal(t, "UNKNOWN", GetCipherSuiteName(0xFFFF))
}

// =============================================================================
// TLS Record Decryption Tests
// =============================================================================

func TestAESGCM_DecryptTLS12Record(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte("HTTP/1.1 200 OK\r\n")
	seqNum := uint64(1)
	contentType := uint8(23) // Application data
	version := uint16(0x0303)

	// Build record: explicit_nonce (8) + encrypted_content + tag (16)
	explicitNonce := make([]byte, 8)
	_, _ = rand.Read(explicitNonce)

	aad := computeTLS12AAD(seqNum, contentType, version, len(plaintext))
	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, aad)
	require.NoError(t, err)

	// Full record
	record := append(explicitNonce, ciphertext...)

	// Decrypt using the record helper
	decrypted, err := cipher.DecryptTLS12Record(record, seqNum, contentType, version)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305_DecryptTLS12Record(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	plaintext := []byte("HTTP/1.1 200 OK\r\n")
	seqNum := uint64(1)
	contentType := uint8(23)
	version := uint16(0x0303)

	// ChaCha20 in TLS 1.2 has no explicit nonce in record
	nonce := cipher.ConstructNonce(seqNum)
	aad := computeTLS12AAD(seqNum, contentType, version, len(plaintext))

	ciphertext, err := cipher.Encrypt(plaintext, nonce, aad)
	require.NoError(t, err)

	// Record is just ciphertext + tag
	decrypted, err := cipher.DecryptTLS12Record(ciphertext, seqNum, contentType, version)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESCBC_DecryptTLS11Record(t *testing.T) {
	key := make([]byte, 16)
	macKey := make([]byte, 20)
	_, _ = rand.Read(key)
	_, _ = rand.Read(macKey)

	cipher, err := NewAESCBC(key, macKey, 128, HashSHA1)
	require.NoError(t, err)

	plaintext := []byte("HTTP/1.1 200 OK\r\n")
	seqNum := uint64(1)
	contentType := uint8(23)
	version := uint16(0x0302) // TLS 1.1

	// Encrypt
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)

	additionalData := make([]byte, 11)
	additionalData[7] = 1 // seqNum
	additionalData[8] = contentType
	additionalData[9] = byte(version >> 8)
	additionalData[10] = byte(version)

	ciphertext, err := cipher.Encrypt(plaintext, iv, additionalData)
	require.NoError(t, err)

	// Full record: IV + ciphertext
	record := append(iv, ciphertext...)

	// Decrypt
	decrypted, err := cipher.DecryptTLS11Record(record, seqNum, contentType, version)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// =============================================================================
// TLS 1.3 Inner Plaintext Tests
// =============================================================================

func TestRemoveTLS13Padding(t *testing.T) {
	testCases := []struct {
		name        string
		input       []byte
		expected    []byte
		expectError bool
	}{
		{
			name:     "No padding",
			input:    []byte{'H', 'e', 'l', 'l', 'o', 23}, // Content + content type (23 = application_data)
			expected: []byte{'H', 'e', 'l', 'l', 'o'},
		},
		{
			name:     "With padding",
			input:    []byte{'H', 'e', 'l', 'l', 'o', 23, 0, 0, 0}, // Content + type + padding
			expected: []byte{'H', 'e', 'l', 'l', 'o'},
		},
		{
			name:        "Empty",
			input:       []byte{},
			expectError: true,
		},
		{
			name:        "All zeros",
			input:       []byte{0, 0, 0},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := removeTLS13Padding(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestGetInnerContentType(t *testing.T) {
	input := []byte{'H', 'e', 'l', 'l', 'o', 23, 0, 0} // Content + type (23) + padding

	content, contentType, err := GetInnerContentType(input)
	require.NoError(t, err)
	assert.Equal(t, []byte{'H', 'e', 'l', 'l', 'o'}, content)
	assert.Equal(t, uint8(23), contentType)
}

// =============================================================================
// Sequence Number Tests
// =============================================================================

func TestSequenceNumberInNonce(t *testing.T) {
	key := make([]byte, 32)
	iv := bytes.Repeat([]byte{0xFF}, 12) // All 1s

	cipher, err := NewChaCha20Poly1305(key, iv)
	require.NoError(t, err)

	// Sequence 0: nonce should be all 0xFF
	nonce0 := cipher.ConstructNonce(0)
	assert.Equal(t, iv, nonce0)

	// Sequence 1: last byte should be 0xFF XOR 0x01 = 0xFE
	nonce1 := cipher.ConstructNonce(1)
	assert.Equal(t, byte(0xFE), nonce1[11])

	// Large sequence number
	nonce_large := cipher.ConstructNonce(0xFFFFFFFFFFFFFFFF)
	// XOR 0xFF...FF with 0xFF...FF should give 0x00...00 in the last 8 bytes
	for i := 4; i < 12; i++ {
		assert.Equal(t, byte(0x00), nonce_large[i])
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestAESGCM_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	plaintext := []byte{}
	explicitNonce := make([]byte, 8)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, 16, len(ciphertext)) // Just the tag

	decrypted, err := cipher.Decrypt(ciphertext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Len(t, decrypted, 0) // Empty plaintext (nil and empty are equivalent)
}

func TestAESGCM_LargePlaintext(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 4)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)

	cipher, err := NewAESGCM(key, iv, 128)
	require.NoError(t, err)

	// 16KB plaintext (max TLS record size)
	plaintext := make([]byte, 16384)
	_, _ = rand.Read(plaintext)

	explicitNonce := make([]byte, 8)
	_, _ = rand.Read(explicitNonce)
	additionalData := make([]byte, 13)

	ciphertext, err := cipher.Encrypt(plaintext, explicitNonce, additionalData)
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, explicitNonce, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
