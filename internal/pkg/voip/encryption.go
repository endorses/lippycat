package voip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/viper"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionConfig holds PCAP encryption configuration
type EncryptionConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	KeyFile    string `mapstructure:"key_file"`
	Algorithm  string `mapstructure:"algorithm"`
	KeyDerive  string `mapstructure:"key_derive"`
	Iterations int    `mapstructure:"pbkdf2_iterations"`
}

const (
	// Encryption constants
	AESKeySize   = 32 // AES-256
	NonceSize    = 12 // GCM nonce size
	SaltSize     = 32 // PBKDF2 salt size
	DefaultIters = 100000
)

// EncryptedPCAPWriter wraps a regular PCAP writer with encryption
type EncryptedPCAPWriter struct {
	file      *os.File
	cipher    cipher.AEAD
	nonce     []byte
	nonceBase uint64 // access via sync/atomic only
}

// getEncryptionConfig returns encryption configuration from viper
func getEncryptionConfig() *EncryptionConfig {
	// Set defaults
	viper.SetDefault("voip.encryption.enabled", false)
	viper.SetDefault("voip.encryption.key_file", "")
	viper.SetDefault("voip.encryption.algorithm", "aes-256-gcm")
	viper.SetDefault("voip.encryption.key_derive", "pbkdf2")
	viper.SetDefault("voip.encryption.pbkdf2_iterations", DefaultIters)

	return &EncryptionConfig{
		Enabled:    viper.GetBool("voip.encryption.enabled"),
		KeyFile:    viper.GetString("voip.encryption.key_file"),
		Algorithm:  viper.GetString("voip.encryption.algorithm"),
		KeyDerive:  viper.GetString("voip.encryption.key_derive"),
		Iterations: viper.GetInt("voip.encryption.pbkdf2_iterations"),
	}
}

// deriveKeyFromPassword derives an encryption key from a password using PBKDF2
func deriveKeyFromPassword(password []byte, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, AESKeySize, sha256.New)
}

// readOrGenerateKey reads an encryption key from file or generates a new one
func readOrGenerateKey(keyFile string) ([]byte, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("encryption key file not specified")
	}

	// Try to read existing key
	if _, err := os.Stat(keyFile); err == nil {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", keyFile, err)
		}

		if len(key) < AESKeySize {
			return nil, fmt.Errorf("key file %s contains insufficient key material", keyFile)
		}

		// Use first 32 bytes as key
		return key[:AESKeySize], nil
	}

	// Generate new key if file doesn't exist
	logger.Warn("Encryption key file not found, generating new key",
		"key_file", keyFile)

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Generate random key
	key := make([]byte, AESKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Write key to file with restrictive permissions
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key file %s: %w", keyFile, err)
	}

	logger.Info("Generated new encryption key",
		"key_file", keyFile,
		"permissions", "0600")

	return key, nil
}

// NewEncryptedPCAPWriter creates a new encrypted PCAP writer
func NewEncryptedPCAPWriter(filename string) (*EncryptedPCAPWriter, error) {
	config := getEncryptionConfig()

	if !config.Enabled {
		return nil, fmt.Errorf("PCAP encryption not enabled")
	}

	if config.Algorithm != "aes-256-gcm" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", config.Algorithm)
	}

	// Get or generate encryption key
	key, err := readOrGenerateKey(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Open output file
	file, err := os.Create(filename + ".enc")
	if err != nil {
		return nil, fmt.Errorf("failed to create encrypted file: %w", err)
	}

	// Generate initial nonce base
	nonceBase := make([]byte, 8)
	if _, err := rand.Read(nonceBase); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to generate nonce base: %w", err)
	}

	writer := &EncryptedPCAPWriter{
		file:   file,
		cipher: gcm,
		nonce:  make([]byte, NonceSize),
	}

	// Store nonce base in first 8 bytes of nonce
	copy(writer.nonce[:8], nonceBase)

	// Write file header indicating encryption
	header := fmt.Sprintf("# LIPPYCAT ENCRYPTED PCAP\n# Algorithm: %s\n# Key Derivation: %s\n",
		config.Algorithm, config.KeyDerive)

	if _, err := file.Write([]byte(header)); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write encryption header: %w", err)
	}

	logger.Info("Created encrypted PCAP writer",
		"file", filename+".enc",
		"algorithm", config.Algorithm)

	return writer, nil
}

// WriteData encrypts and writes data to the encrypted PCAP file
func (w *EncryptedPCAPWriter) WriteData(data []byte) error {
	if w.file == nil {
		return fmt.Errorf("encrypted writer is closed")
	}

	// Increment nonce counter (last 4 bytes) atomically
	newNonceBase := atomic.AddUint64(&w.nonceBase, 1)
	for i := 0; i < 4; i++ {
		w.nonce[8+i] = byte(newNonceBase >> (i * 8))
	}

	// Encrypt data
	ciphertext := w.cipher.Seal(nil, w.nonce, data, nil)

	// Write nonce + ciphertext length + ciphertext
	if err := w.writeUint32(uint32(len(ciphertext))); err != nil {
		return fmt.Errorf("failed to write ciphertext length: %w", err)
	}

	if _, err := w.file.Write(w.nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	if _, err := w.file.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return nil
}

// writeUint32 writes a 32-bit integer in little-endian format
func (w *EncryptedPCAPWriter) writeUint32(value uint32) error {
	bytes := make([]byte, 4)
	bytes[0] = byte(value)
	bytes[1] = byte(value >> 8)
	bytes[2] = byte(value >> 16)
	bytes[3] = byte(value >> 24)
	_, err := w.file.Write(bytes)
	return err
}

// Close closes the encrypted PCAP writer
func (w *EncryptedPCAPWriter) Close() error {
	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

// DecryptPCAPFile decrypts an encrypted PCAP file
// This is primarily for recovery/debugging purposes
func DecryptPCAPFile(encryptedFile, outputFile, keyFile string) error {

	// Read encryption key
	key, err := readOrGenerateKey(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read encryption key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Open encrypted file
	inFile, err := os.Open(encryptedFile)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Skip header (read until first binary data)
	scanner := make([]byte, 1)
	for {
		if _, err := inFile.Read(scanner); err != nil {
			return fmt.Errorf("failed to read file header: %w", err)
		}
		if scanner[0] != '#' && scanner[0] != '\n' && scanner[0] != '\r' {
			// Found start of binary data, seek back one byte
			if _, err := inFile.Seek(-1, io.SeekCurrent); err != nil {
				return fmt.Errorf("failed to seek in encrypted file: %w", err)
			}
			break
		}
		// Skip rest of line
		for scanner[0] != '\n' {
			if _, err := inFile.Read(scanner); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
		}
	}

	// Decrypt data blocks
	lengthBytes := make([]byte, 4)
	nonce := make([]byte, NonceSize)

	for {
		// Read ciphertext length
		if _, err := inFile.Read(lengthBytes); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read ciphertext length: %w", err)
		}

		length := uint32(lengthBytes[0]) |
			uint32(lengthBytes[1])<<8 |
			uint32(lengthBytes[2])<<16 |
			uint32(lengthBytes[3])<<24

		// Read nonce
		if _, err := inFile.Read(nonce); err != nil {
			return fmt.Errorf("failed to read nonce: %w", err)
		}

		// Read ciphertext
		ciphertext := make([]byte, length)
		if _, err := inFile.Read(ciphertext); err != nil {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}

		// Decrypt
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}

		// Write decrypted data
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted data: %w", err)
		}
	}

	logger.Info("Successfully decrypted PCAP file",
		"input", encryptedFile,
		"output", outputFile)

	return nil
}

// ValidateEncryptionConfig validates the encryption configuration
func ValidateEncryptionConfig() error {
	config := getEncryptionConfig()

	if !config.Enabled {
		return nil // No validation needed if disabled
	}

	if config.KeyFile == "" {
		return fmt.Errorf("encryption enabled but no key file specified")
	}

	if config.Algorithm != "aes-256-gcm" {
		return fmt.Errorf("unsupported encryption algorithm: %s (supported: aes-256-gcm)", config.Algorithm)
	}

	if config.KeyDerive != "pbkdf2" {
		return fmt.Errorf("unsupported key derivation: %s (supported: pbkdf2)", config.KeyDerive)
	}

	if config.Iterations < 10000 {
		return fmt.Errorf("PBKDF2 iterations too low: %d (minimum: 10000)", config.Iterations)
	}

	// Test key file access
	keyDir := filepath.Dir(config.KeyFile)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("cannot create key directory %s: %w", keyDir, err)
	}

	return nil
}
