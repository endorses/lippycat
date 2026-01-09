//go:build cli || hunter || tap || tui || all

package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
)

// AESCBC implements AES-CBC with HMAC for TLS 1.0/1.1/1.2.
//
// TLS CBC mode uses MAC-then-Encrypt:
// 1. Compute MAC over: seq_num + content_type + version + length + plaintext
// 2. Append MAC to plaintext
// 3. Add PKCS#7 padding
// 4. Encrypt with AES-CBC
//
// TLS 1.0: Uses implicit IV (last ciphertext block of previous record)
// TLS 1.1+: Uses explicit IV (first block of each record)
//
// Record structure (TLS 1.1+): IV (16) + encrypted(plaintext + MAC + padding)
type AESCBC struct {
	block      cipher.Block
	macKey     []byte
	keySize    int
	macSize    int
	hashAlg    int
	explicitIV bool // TLS 1.1+ uses explicit IV
}

// NewAESCBC creates a new AES-CBC cipher with HMAC.
// keyBits must be 128 or 256.
// hashAlg must be HashSHA1, HashSHA256, or HashSHA384.
func NewAESCBC(key, macKey []byte, keyBits int, hashAlg int) (*AESCBC, error) {
	expectedKeyLen := keyBits / 8
	if len(key) != expectedKeyLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, expectedKeyLen, len(key))
	}

	expectedMACLen := getMACSize(hashAlg)
	if len(macKey) != expectedMACLen {
		return nil, fmt.Errorf("%w: expected %d bytes MAC key for hash algorithm, got %d", ErrInvalidKeySize, expectedMACLen, len(macKey))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AESCBC{
		block:      block,
		macKey:     macKey,
		keySize:    expectedKeyLen,
		macSize:    expectedMACLen,
		hashAlg:    hashAlg,
		explicitIV: true, // Default to TLS 1.1+ behavior
	}, nil
}

// getMACSize returns the MAC output size for the hash algorithm.
func getMACSize(hashAlg int) int {
	switch hashAlg {
	case HashSHA384:
		return 48
	case HashSHA256:
		return 32
	case HashSHA1:
		return 20
	default:
		return 20 // Default to SHA-1
	}
}

// getHashFunc returns the hash function for the algorithm.
func getHashFunc(hashAlg int) func() hash.Hash {
	switch hashAlg {
	case HashSHA384:
		return sha512.New384
	case HashSHA256:
		return sha256.New
	case HashSHA1:
		return sha1.New
	default:
		return sha1.New // Default to SHA-1
	}
}

// SetExplicitIV sets whether to use explicit IV (TLS 1.1+) or implicit IV (TLS 1.0).
func (c *AESCBC) SetExplicitIV(explicit bool) {
	c.explicitIV = explicit
}

// Decrypt decrypts a TLS CBC record.
//
// For TLS 1.1+:
//   - nonce: explicit IV (16 bytes, first block of ciphertext)
//   - ciphertext: encrypted(plaintext + MAC + padding), NOT including IV
//   - additionalData: seq_num (8) + content_type (1) + version (2) for MAC computation
//
// For TLS 1.0:
//   - nonce: IV from previous record (or initial IV)
//   - ciphertext: encrypted(plaintext + MAC + padding)
//   - additionalData: seq_num (8) + content_type (1) + version (2) for MAC computation
//
// Note: The caller should extract the IV from the record before calling this for TLS 1.1+.
func (c *AESCBC) Decrypt(ciphertext, nonce, additionalData []byte) ([]byte, error) {
	if len(nonce) != aes.BlockSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, aes.BlockSize, len(nonce))
	}

	// Ciphertext must be a multiple of block size
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d is not a multiple of block size", ErrInvalidCiphertext, len(ciphertext))
	}

	// Minimum size: at least padding byte + MAC
	minSize := 1 + c.macSize
	if len(ciphertext) < ((minSize/aes.BlockSize)+1)*aes.BlockSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}

	// Decrypt
	decrypter := cipher.NewCBCDecrypter(c.block, nonce)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	// Remove and verify padding (PKCS#7)
	plaintext, err := removePKCS7Padding(plaintext)
	if err != nil {
		return nil, err
	}

	// Extract and verify MAC
	if len(plaintext) < c.macSize {
		return nil, fmt.Errorf("%w: not enough data for MAC", ErrInvalidCiphertext)
	}

	macStart := len(plaintext) - c.macSize
	content := plaintext[:macStart]
	recordMAC := plaintext[macStart:]

	// Compute expected MAC
	// MAC input: seq_num + content_type + version + length + content
	// additionalData should contain: seq_num (8) + content_type (1) + version (2)
	expectedMAC := c.computeMAC(additionalData, content)

	// Constant-time MAC comparison
	if subtle.ConstantTimeCompare(recordMAC, expectedMAC) != 1 {
		return nil, ErrMACVerificationFailed
	}

	return content, nil
}

// Encrypt encrypts a TLS CBC record.
func (c *AESCBC) Encrypt(plaintext, nonce, additionalData []byte) ([]byte, error) {
	if len(nonce) != aes.BlockSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidIVSize, aes.BlockSize, len(nonce))
	}

	// Compute MAC
	mac := c.computeMAC(additionalData, plaintext)

	// Append MAC to plaintext
	withMAC := make([]byte, len(plaintext)+len(mac))
	copy(withMAC, plaintext)
	copy(withMAC[len(plaintext):], mac)

	// Add PKCS#7 padding
	padded := addPKCS7Padding(withMAC, aes.BlockSize)

	// Encrypt
	encrypter := cipher.NewCBCEncrypter(c.block, nonce)
	ciphertext := make([]byte, len(padded))
	encrypter.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// computeMAC computes the HMAC for TLS CBC mode.
// MAC input: seq_num (8) + content_type (1) + version (2) + length (2) + content
func (c *AESCBC) computeMAC(additionalData, content []byte) []byte {
	hashFunc := getHashFunc(c.hashAlg)
	mac := hmac.New(hashFunc, c.macKey)

	// Write seq_num + content_type + version from additionalData
	if len(additionalData) >= 11 {
		mac.Write(additionalData[:11]) // seq_num (8) + content_type (1) + version (2)
	}

	// Write length (2 bytes, big-endian)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(content)))
	mac.Write(lenBytes)

	// Write content
	mac.Write(content)

	return mac.Sum(nil)
}

// TagSize returns the MAC size.
func (c *AESCBC) TagSize() int {
	return c.macSize
}

// KeySize returns the cipher key size.
func (c *AESCBC) KeySize() int {
	return c.keySize
}

// NonceSize returns the IV size (16 bytes for AES).
func (c *AESCBC) NonceSize() int {
	return aes.BlockSize
}

// IsAEAD returns false (CBC is not AEAD).
func (c *AESCBC) IsAEAD() bool {
	return false
}

// DecryptTLS11Record decrypts a TLS 1.1/1.2 AES-CBC record.
// The record structure is: IV (16) + encrypted(plaintext + MAC + padding)
func (c *AESCBC) DecryptTLS11Record(record []byte, seqNum uint64, contentType uint8, version uint16) ([]byte, error) {
	// TLS 1.1+ record: IV (16) + encrypted data
	if len(record) < aes.BlockSize*2 {
		return nil, fmt.Errorf("%w: TLS 1.1+ CBC record too short", ErrInvalidCiphertext)
	}

	// Extract IV (first 16 bytes)
	iv := record[:aes.BlockSize]
	ciphertext := record[aes.BlockSize:]

	// Build additional data for MAC
	additionalData := make([]byte, 11)
	binary.BigEndian.PutUint64(additionalData[:8], seqNum)
	additionalData[8] = contentType
	binary.BigEndian.PutUint16(additionalData[9:11], version)

	return c.Decrypt(ciphertext, iv, additionalData)
}

// DecryptTLS10Record decrypts a TLS 1.0 AES-CBC record.
// TLS 1.0 uses implicit IV from the last ciphertext block of the previous record.
// If prevIV is nil, this is the first record and the initial IV is used.
func (c *AESCBC) DecryptTLS10Record(record, prevIV []byte, seqNum uint64, contentType uint8, version uint16) ([]byte, error) {
	if len(prevIV) != aes.BlockSize {
		return nil, fmt.Errorf("%w: previous IV must be %d bytes", ErrInvalidIVSize, aes.BlockSize)
	}

	// TLS 1.0 record is just encrypted data (no explicit IV)
	if len(record) < aes.BlockSize {
		return nil, fmt.Errorf("%w: TLS 1.0 CBC record too short", ErrInvalidCiphertext)
	}

	// Build additional data for MAC
	additionalData := make([]byte, 11)
	binary.BigEndian.PutUint64(additionalData[:8], seqNum)
	additionalData[8] = contentType
	binary.BigEndian.PutUint16(additionalData[9:11], version)

	return c.Decrypt(record, prevIV, additionalData)
}

// GetLastCiphertextBlock returns the last block of ciphertext for TLS 1.0 IV chaining.
func GetLastCiphertextBlock(ciphertext []byte) []byte {
	if len(ciphertext) < aes.BlockSize {
		return nil
	}
	lastBlock := make([]byte, aes.BlockSize)
	copy(lastBlock, ciphertext[len(ciphertext)-aes.BlockSize:])
	return lastBlock
}

// addPKCS7Padding adds PKCS#7 padding to the plaintext.
func addPKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// removePKCS7Padding removes and validates PKCS#7 padding.
// Implements constant-time padding validation to prevent padding oracle attacks.
func removePKCS7Padding(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrInvalidPadding
	}

	paddingLen := int(plaintext[len(plaintext)-1])

	// Padding length must be 1-16 for AES
	if paddingLen == 0 || paddingLen > aes.BlockSize {
		return nil, ErrInvalidPadding
	}

	if paddingLen > len(plaintext) {
		return nil, ErrInvalidPadding
	}

	// Constant-time padding validation
	paddingStart := len(plaintext) - paddingLen
	valid := byte(0)
	for i := paddingStart; i < len(plaintext); i++ {
		valid |= plaintext[i] ^ byte(paddingLen)
	}

	if valid != 0 {
		return nil, ErrInvalidPadding
	}

	return plaintext[:paddingStart], nil
}

// ValidatePKCS7Padding validates PKCS#7 padding without removing it.
// Returns the padding length if valid, 0 if invalid.
// This is useful for debugging.
func ValidatePKCS7Padding(plaintext []byte) int {
	if len(plaintext) == 0 {
		return 0
	}

	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize || paddingLen > len(plaintext) {
		return 0
	}

	paddingStart := len(plaintext) - paddingLen
	for i := paddingStart; i < len(plaintext); i++ {
		if plaintext[i] != byte(paddingLen) {
			return 0
		}
	}

	return paddingLen
}
