//go:build cli || hunter || tap || all

package decrypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// TLS 1.2 Key Derivation
//
// TLS 1.2 uses a PRF (Pseudo-Random Function) based on HMAC to derive:
// 1. Master secret from pre-master secret
// 2. Session keys from master secret
//
// PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//
// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                        HMAC_hash(secret, A(2) + seed) + ...
// where:
//   A(0) = seed
//   A(i) = HMAC_hash(secret, A(i-1))

// MasterSecretLen is the length of the TLS master secret.
const MasterSecretLen = 48

// KeyBlockLabels
const (
	masterSecretLabel = "master secret"
	keyExpansionLabel = "key expansion"
)

// PRF12 implements the TLS 1.2 PRF (Pseudo-Random Function).
// It uses the specified hash function (SHA-256 or SHA-384).
func PRF12(hashAlg int, secret, label, seed []byte, length int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	return pHash(hashAlg, secret, labelAndSeed, length)
}

// pHash implements P_hash from RFC 5246.
func pHash(hashAlg int, secret, seed []byte, length int) []byte {
	result := make([]byte, length)
	written := 0

	// A(0) = seed
	a := seed

	hashFunc := getHashFunc(hashAlg)

	for written < length {
		// A(i) = HMAC_hash(secret, A(i-1))
		mac := hmac.New(hashFunc, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		// P_hash(secret, seed) = HMAC_hash(secret, A(i) + seed)
		mac = hmac.New(hashFunc, secret)
		mac.Write(a)
		mac.Write(seed)
		output := mac.Sum(nil)

		// Copy to result
		toCopy := length - written
		if toCopy > len(output) {
			toCopy = len(output)
		}
		copy(result[written:], output[:toCopy])
		written += toCopy
	}

	return result
}

// getHashFunc returns the hash function for the algorithm.
func getHashFunc(hashAlg int) func() hash.Hash {
	if hashAlg == HashSHA384 {
		return sha512.New384
	}
	return sha256.New
}

// getHashSize returns the hash output size.
func getHashSize(hashAlg int) int {
	if hashAlg == HashSHA384 {
		return 48
	}
	return 32
}

// DeriveMasterSecret derives the TLS 1.2 master secret from the pre-master secret.
// master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]
func DeriveMasterSecret(hashAlg int, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 64)
	copy(seed[:32], clientRandom)
	copy(seed[32:], serverRandom)

	return PRF12(hashAlg, preMasterSecret, []byte(masterSecretLabel), seed, MasterSecretLen)
}

// KeyMaterial holds the derived key material for TLS 1.2.
type KeyMaterial struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
	ClientMACKey   []byte
	ServerMACKey   []byte
}

// DeriveKeyMaterial derives session keys from the master secret.
// key_block = PRF(master_secret, "key expansion", ServerHello.random + ClientHello.random)
//
// The key_block is partitioned as:
//
//	client_write_MAC_key[SecurityParameters.mac_key_length]
//	server_write_MAC_key[SecurityParameters.mac_key_length]
//	client_write_key[SecurityParameters.enc_key_length]
//	server_write_key[SecurityParameters.enc_key_length]
//	client_write_IV[SecurityParameters.fixed_iv_length]
//	server_write_IV[SecurityParameters.fixed_iv_length]
func DeriveKeyMaterial(hashAlg int, masterSecret, clientRandom, serverRandom []byte, cipherSuite *CipherSuiteInfo) *KeyMaterial {
	// Note: For key expansion, server random comes first
	seed := make([]byte, 64)
	copy(seed[:32], serverRandom)
	copy(seed[32:], clientRandom)

	// Calculate total key block length needed
	keyBlockLen := 2*cipherSuite.MACLen + 2*cipherSuite.KeyLen + 2*cipherSuite.IVLen

	// For AEAD ciphers in TLS 1.2, the explicit IV is part of each record
	// The fixed IV (implicit) is derived here
	// For GCM in TLS 1.2: 4 bytes fixed IV + 8 bytes explicit per-record nonce
	if cipherSuite.IsAEAD && !cipherSuite.IsTLS13 && cipherSuite.IVLen == 4 {
		// TLS 1.2 GCM uses 4-byte implicit IV
		keyBlockLen = 2*cipherSuite.KeyLen + 2*cipherSuite.IVLen
	}

	keyBlock := PRF12(hashAlg, masterSecret, []byte(keyExpansionLabel), seed, keyBlockLen)

	km := &KeyMaterial{}
	offset := 0

	// Extract MAC keys (for non-AEAD ciphers)
	if cipherSuite.MACLen > 0 {
		km.ClientMACKey = keyBlock[offset : offset+cipherSuite.MACLen]
		offset += cipherSuite.MACLen
		km.ServerMACKey = keyBlock[offset : offset+cipherSuite.MACLen]
		offset += cipherSuite.MACLen
	}

	// Extract write keys
	km.ClientWriteKey = keyBlock[offset : offset+cipherSuite.KeyLen]
	offset += cipherSuite.KeyLen
	km.ServerWriteKey = keyBlock[offset : offset+cipherSuite.KeyLen]
	offset += cipherSuite.KeyLen

	// Extract IVs
	if cipherSuite.IVLen > 0 {
		km.ClientWriteIV = keyBlock[offset : offset+cipherSuite.IVLen]
		offset += cipherSuite.IVLen
		km.ServerWriteIV = keyBlock[offset : offset+cipherSuite.IVLen]
	}

	return km
}

// DeriveKeysFromPreMaster performs the complete key derivation for TLS 1.2.
// This is a convenience function that derives master secret and then key material.
func DeriveKeysFromPreMaster(preMasterSecret, clientRandom, serverRandom []byte, cipherSuite *CipherSuiteInfo) (*KeyMaterial, []byte) {
	masterSecret := DeriveMasterSecret(cipherSuite.HashAlgorithm, preMasterSecret, clientRandom, serverRandom)
	keyMaterial := DeriveKeyMaterial(cipherSuite.HashAlgorithm, masterSecret, clientRandom, serverRandom, cipherSuite)
	return keyMaterial, masterSecret
}

// ConstructGCMNonce constructs the nonce for AES-GCM in TLS 1.2.
// TLS 1.2 GCM nonce = fixed_iv (4 bytes) + explicit_nonce (8 bytes from record)
func ConstructGCMNonce(fixedIV, explicitNonce []byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], fixedIV)
	copy(nonce[4:], explicitNonce)
	return nonce
}

// ConstructChaCha20Nonce constructs the nonce for ChaCha20-Poly1305 in TLS 1.2.
// ChaCha20-Poly1305 in TLS 1.2 uses: fixed_iv (12 bytes) XOR with padded seq_num
func ConstructChaCha20Nonce(fixedIV []byte, seqNum uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, fixedIV)

	// XOR with padded sequence number (8 bytes, left-padded with zeros)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	// XOR the last 8 bytes
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}

	return nonce
}

// ComputeAdditionalData computes the additional authenticated data for TLS 1.2 AEAD.
// additional_data = seq_num (8) + TLSCompressed.type (1) + TLSCompressed.version (2) + TLSCompressed.length (2)
func ComputeAdditionalData(seqNum uint64, contentType uint8, version uint16, plainLength int) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[:8], seqNum)
	ad[8] = contentType
	binary.BigEndian.PutUint16(ad[9:11], version)
	binary.BigEndian.PutUint16(ad[11:13], uint16(plainLength))
	return ad
}

// VerifyMasterSecretDerivation verifies the master secret derivation with test vectors.
// This is useful for testing the PRF implementation.
func VerifyMasterSecretDerivation(hashAlg int, preMasterSecret, clientRandom, serverRandom, expectedMaster []byte) bool {
	derived := DeriveMasterSecret(hashAlg, preMasterSecret, clientRandom, serverRandom)
	if len(derived) != len(expectedMaster) {
		return false
	}
	for i := range derived {
		if derived[i] != expectedMaster[i] {
			return false
		}
	}
	return true
}
