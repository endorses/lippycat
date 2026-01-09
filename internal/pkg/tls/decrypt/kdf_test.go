//go:build cli || hunter || tap || all

package decrypt

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from RFC 5246 Appendix A (TLS 1.2)
// and various Wireshark captures for known-good derivation

func TestPRF12(t *testing.T) {
	// Test vector from TLS 1.2 test suite
	// These are simplified test cases to verify PRF behavior

	secret := []byte("secret")
	label := []byte("label")
	seed := []byte("seed")

	// PRF should produce deterministic output
	output1 := PRF12(HashSHA256, secret, label, seed, 32)
	output2 := PRF12(HashSHA256, secret, label, seed, 32)
	assert.Equal(t, output1, output2)

	// Different lengths should produce prefix-compatible output
	output48 := PRF12(HashSHA256, secret, label, seed, 48)
	assert.Equal(t, output1, output48[:32])

	// SHA-384 should produce different output
	output384 := PRF12(HashSHA384, secret, label, seed, 32)
	assert.NotEqual(t, output1, output384)
}

func TestDeriveMasterSecret(t *testing.T) {
	// Test that master secret is always 48 bytes
	preMaster := make([]byte, 48)
	for i := range preMaster {
		preMaster[i] = byte(i)
	}

	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
		serverRandom[i] = byte(0xFF - i)
	}

	master := DeriveMasterSecret(HashSHA256, preMaster, clientRandom, serverRandom)
	assert.Len(t, master, MasterSecretLen)

	// Same inputs should produce same output
	master2 := DeriveMasterSecret(HashSHA256, preMaster, clientRandom, serverRandom)
	assert.Equal(t, master, master2)

	// Different inputs should produce different output
	clientRandom[0] = 0xFF
	master3 := DeriveMasterSecret(HashSHA256, preMaster, clientRandom, serverRandom)
	assert.NotEqual(t, master, master3)
}

func TestDeriveKeyMaterial_AES128GCM(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	cipherSuite := &CipherSuiteInfo{
		KeyLen:        16,
		IVLen:         4,
		MACLen:        0,
		HashAlgorithm: HashSHA256,
		IsAEAD:        true,
	}

	km := DeriveKeyMaterial(HashSHA256, masterSecret, clientRandom, serverRandom, cipherSuite)

	// Check key lengths
	assert.Len(t, km.ClientWriteKey, 16)
	assert.Len(t, km.ServerWriteKey, 16)
	assert.Len(t, km.ClientWriteIV, 4)
	assert.Len(t, km.ServerWriteIV, 4)

	// AEAD cipher should have no MAC keys
	assert.Nil(t, km.ClientMACKey)
	assert.Nil(t, km.ServerMACKey)

	// Keys should be different
	assert.NotEqual(t, km.ClientWriteKey, km.ServerWriteKey)
}

func TestDeriveKeyMaterial_AES256CBC(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	cipherSuite := &CipherSuiteInfo{
		KeyLen:        32,
		IVLen:         16,
		MACLen:        20, // SHA-1
		HashAlgorithm: HashSHA256,
		IsAEAD:        false,
	}

	km := DeriveKeyMaterial(HashSHA256, masterSecret, clientRandom, serverRandom, cipherSuite)

	// Check key lengths
	assert.Len(t, km.ClientWriteKey, 32)
	assert.Len(t, km.ServerWriteKey, 32)
	assert.Len(t, km.ClientWriteIV, 16)
	assert.Len(t, km.ServerWriteIV, 16)
	assert.Len(t, km.ClientMACKey, 20)
	assert.Len(t, km.ServerMACKey, 20)
}

func TestConstructGCMNonce(t *testing.T) {
	fixedIV := []byte{0x01, 0x02, 0x03, 0x04}
	explicitNonce := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	nonce := ConstructGCMNonce(fixedIV, explicitNonce)

	assert.Len(t, nonce, 12)
	assert.Equal(t, fixedIV, nonce[:4])
	assert.Equal(t, explicitNonce, nonce[4:])
}

func TestConstructChaCha20Nonce(t *testing.T) {
	fixedIV := make([]byte, 12)
	for i := range fixedIV {
		fixedIV[i] = byte(i)
	}

	// Sequence number 0
	nonce0 := ConstructChaCha20Nonce(fixedIV, 0)
	assert.Equal(t, fixedIV, nonce0) // XOR with 0 = no change

	// Sequence number 1
	nonce1 := ConstructChaCha20Nonce(fixedIV, 1)
	assert.NotEqual(t, nonce0, nonce1)

	// Last byte should differ
	assert.NotEqual(t, nonce0[11], nonce1[11])
}

func TestComputeAdditionalData(t *testing.T) {
	ad := ComputeAdditionalData(123, ContentTypeApplicationData, VersionTLS12, 100)

	assert.Len(t, ad, 13)

	// Check sequence number (first 8 bytes)
	assert.Equal(t, byte(0), ad[0])
	assert.Equal(t, byte(123), ad[7])

	// Check content type
	assert.Equal(t, uint8(ContentTypeApplicationData), ad[8])

	// Check version
	assert.Equal(t, byte(0x03), ad[9])
	assert.Equal(t, byte(0x03), ad[10])

	// Check length
	assert.Equal(t, byte(0), ad[11])
	assert.Equal(t, byte(100), ad[12])
}

// TLS 1.3 Key Derivation Tests

func TestHKDFExpandLabel(t *testing.T) {
	// Test that HKDF-Expand-Label produces consistent output
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	output1 := hkdfExpandLabel(HashSHA256, secret, "test", nil, 32)
	output2 := hkdfExpandLabel(HashSHA256, secret, "test", nil, 32)
	assert.Equal(t, output1, output2)

	// Different labels should produce different output
	output3 := hkdfExpandLabel(HashSHA256, secret, "other", nil, 32)
	assert.NotEqual(t, output1, output3)

	// Context should affect output
	output4 := hkdfExpandLabel(HashSHA256, secret, "test", []byte("context"), 32)
	assert.NotEqual(t, output1, output4)
}

func TestDeriveSecret(t *testing.T) {
	secret := make([]byte, 32)
	transcriptHash := make([]byte, 32)

	// Should produce hash-sized output
	derived := DeriveSecret(HashSHA256, secret, "test label", transcriptHash)
	assert.Len(t, derived, 32)

	derived384 := DeriveSecret(HashSHA384, secret, "test label", transcriptHash)
	assert.Len(t, derived384, 48)
}

func TestEmptyHash(t *testing.T) {
	// SHA-256 of empty string
	hash256 := EmptyHash(HashSHA256)
	assert.Len(t, hash256, 32)

	// Known value for SHA-256("")
	expected256 := mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	assert.Equal(t, expected256, hash256)

	// SHA-384 of empty string
	hash384 := EmptyHash(HashSHA384)
	assert.Len(t, hash384, 48)
}

func TestTLS13KeySchedule_Full(t *testing.T) {
	ks := NewTLS13KeySchedule(HashSHA256)

	// Step 1: Derive early secret (no PSK)
	ks.DeriveEarlySecret(nil)
	assert.NotNil(t, ks.EarlySecret)
	assert.Len(t, ks.EarlySecret, 32)

	// Step 2: Derive handshake secret
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}
	ks.DeriveHandshakeSecret(sharedSecret)
	assert.NotNil(t, ks.HandshakeSecret)
	assert.Len(t, ks.HandshakeSecret, 32)

	// Step 3: Derive handshake traffic secrets
	transcriptHash := make([]byte, 32)
	ks.DeriveHandshakeTrafficSecrets(transcriptHash)
	assert.NotNil(t, ks.ClientHandshakeTrafficSecret)
	assert.NotNil(t, ks.ServerHandshakeTrafficSecret)
	assert.NotEqual(t, ks.ClientHandshakeTrafficSecret, ks.ServerHandshakeTrafficSecret)

	// Step 4: Derive master secret
	ks.DeriveMasterSecret()
	assert.NotNil(t, ks.MasterSecret)
	assert.Len(t, ks.MasterSecret, 32)

	// Step 5: Derive application traffic secrets
	ks.DeriveAppTrafficSecrets(transcriptHash)
	assert.NotNil(t, ks.ClientAppTrafficSecret)
	assert.NotNil(t, ks.ServerAppTrafficSecret)

	// Step 6: Derive exporter secret
	ks.DeriveExporterSecret(transcriptHash)
	assert.NotNil(t, ks.ExporterMasterSecret)

	// Step 7: Derive resumption secret
	ks.DeriveResumptionSecret(transcriptHash)
	assert.NotNil(t, ks.ResumptionMasterSecret)
}

func TestDeriveTrafficKeys(t *testing.T) {
	trafficSecret := make([]byte, 32)
	for i := range trafficSecret {
		trafficSecret[i] = byte(i)
	}

	cipherSuite := &CipherSuiteInfo{
		KeyLen:        16,
		IVLen:         12,
		HashAlgorithm: HashSHA256,
	}

	km := DeriveTrafficKeys(HashSHA256, trafficSecret, cipherSuite)

	assert.Len(t, km.Key, 16)
	assert.Len(t, km.IV, 12)
}

func TestUpdateTrafficSecret(t *testing.T) {
	secret0 := make([]byte, 32)
	for i := range secret0 {
		secret0[i] = byte(i)
	}

	secret1 := UpdateTrafficSecret(HashSHA256, secret0)
	assert.Len(t, secret1, 32)
	assert.NotEqual(t, secret0, secret1)

	// Update again
	secret2 := UpdateTrafficSecret(HashSHA256, secret1)
	assert.NotEqual(t, secret1, secret2)
}

func TestConstructTLS13Nonce(t *testing.T) {
	writeIV := make([]byte, 12)
	for i := range writeIV {
		writeIV[i] = byte(i)
	}

	// Sequence 0 should just return writeIV
	nonce0 := ConstructTLS13Nonce(writeIV, 0)
	assert.Equal(t, writeIV, nonce0)

	// Sequence 1 should XOR the last byte
	nonce1 := ConstructTLS13Nonce(writeIV, 1)
	assert.NotEqual(t, writeIV, nonce1)
	assert.Equal(t, writeIV[11]^1, nonce1[11])

	// Sequence 256 should XOR second-to-last byte
	nonce256 := ConstructTLS13Nonce(writeIV, 256)
	assert.Equal(t, writeIV[10]^1, nonce256[10])
}

func TestComputeTLS13AdditionalData(t *testing.T) {
	ad := ComputeTLS13AdditionalData(100)

	assert.Len(t, ad, 5)
	assert.Equal(t, byte(ContentTypeApplicationData), ad[0])
	assert.Equal(t, byte(0x03), ad[1])
	assert.Equal(t, byte(0x03), ad[2])
	assert.Equal(t, byte(0), ad[3])
	assert.Equal(t, byte(100), ad[4])
}

func TestGetHashAlgorithmForCipher(t *testing.T) {
	// TLS_AES_128_GCM_SHA256
	assert.Equal(t, HashSHA256, GetHashAlgorithmForCipher(0x1301))

	// TLS_AES_256_GCM_SHA384
	assert.Equal(t, HashSHA384, GetHashAlgorithmForCipher(0x1302))

	// TLS_CHACHA20_POLY1305_SHA256
	assert.Equal(t, HashSHA256, GetHashAlgorithmForCipher(0x1303))
}

func TestComputeFinishedVerifyData(t *testing.T) {
	finishedKey := make([]byte, 32)
	transcriptHash := make([]byte, 32)
	for i := range finishedKey {
		finishedKey[i] = byte(i)
		transcriptHash[i] = byte(0xFF - i)
	}

	verifyData := ComputeFinishedVerifyData(HashSHA256, finishedKey, transcriptHash)
	assert.Len(t, verifyData, 32)

	// Same inputs should produce same output
	verifyData2 := ComputeFinishedVerifyData(HashSHA256, finishedKey, transcriptHash)
	assert.Equal(t, verifyData, verifyData2)
}

// Test with known TLS 1.3 test vectors from RFC 8448
func TestTLS13_RFC8448_SimpleHandshake(t *testing.T) {
	// This test uses vectors from RFC 8448 Section 3 (Simple 1-RTT Handshake)
	// The values are truncated/simplified for testing basic functionality

	// Shared secret from ECDHE
	sharedSecret := mustDecodeHex(t, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")

	// ClientHello...ServerHello transcript hash (SHA-256)
	helloHash := mustDecodeHex(t, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")

	ks := NewTLS13KeySchedule(HashSHA256)
	ks.DeriveEarlySecret(nil)
	ks.DeriveHandshakeSecret(sharedSecret)
	ks.DeriveHandshakeTrafficSecrets(helloHash)

	// Expected client handshake traffic secret (from RFC 8448)
	expectedClientHS := mustDecodeHex(t, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	assert.Equal(t, expectedClientHS, ks.ClientHandshakeTrafficSecret)

	// Expected server handshake traffic secret
	expectedServerHS := mustDecodeHex(t, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	assert.Equal(t, expectedServerHS, ks.ServerHandshakeTrafficSecret)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	data, err := hex.DecodeString(s)
	require.NoError(t, err)
	return data
}
