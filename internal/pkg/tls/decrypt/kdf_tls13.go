//go:build cli || hunter || tap || all

package decrypt

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// TLS 1.3 Key Derivation
//
// TLS 1.3 uses HKDF (HMAC-based Key Derivation Function) defined in RFC 5869.
// The key schedule derives traffic secrets at different stages:
//
// 1. Early Secret (0-RTT)
// 2. Handshake Secret (after key exchange)
// 3. Master Secret (after handshake)
//
// Each stage derives traffic secrets which are then used to derive:
// - write_key
// - write_iv
//
// HKDF-Expand-Label is used with TLS 1.3 specific labels.

// TLS 1.3 labels as defined in RFC 8446
const (
	// Labels for HKDF-Expand-Label
	labelDerived               = "derived"
	labelClientHandshake       = "c hs traffic"
	labelServerHandshake       = "s hs traffic"
	labelClientAppTraffic      = "c ap traffic"
	labelServerAppTraffic      = "s ap traffic"
	labelExporter              = "exp master"
	labelResumption            = "res master"
	labelEarlyTraffic          = "c e traffic"
	labelEarlyExporter         = "e exp master"
	labelKey                   = "key"
	labelIV                    = "iv"
	labelTrafficUpdate         = "traffic upd"
	labelFinished              = "finished"
	labelResumptionBinderKey   = "res binder"
	labelExternalBinderKey     = "ext binder"
	labelApplicationTrafficKey = "quic key"
)

// hkdfExtract performs HKDF-Extract.
// HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
func hkdfExtract(hashAlg int, salt, ikm []byte) []byte {
	hashFunc := getHashFunc(hashAlg)
	hashSize := getHashSize(hashAlg)

	if salt == nil || len(salt) == 0 {
		salt = make([]byte, hashSize)
	}

	mac := hmac.New(hashFunc, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel implements HKDF-Expand-Label as defined in RFC 8446.
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//
//	HKDF-Expand(Secret, HkdfLabel, Length)
//
// where HkdfLabel is:
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
func hkdfExpandLabel(hashAlg int, secret []byte, label string, context []byte, length int) []byte {
	// Build HkdfLabel
	fullLabel := "tls13 " + label

	// HkdfLabel structure
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	pos := 0

	// Length (2 bytes)
	binary.BigEndian.PutUint16(hkdfLabel[pos:], uint16(length))
	pos += 2

	// Label length (1 byte) + label
	hkdfLabel[pos] = uint8(len(fullLabel))
	pos++
	copy(hkdfLabel[pos:], fullLabel)
	pos += len(fullLabel)

	// Context length (1 byte) + context
	hkdfLabel[pos] = uint8(len(context))
	pos++
	copy(hkdfLabel[pos:], context)

	// HKDF-Expand
	hashFunc := getHashFunc(hashAlg)
	reader := hkdf.Expand(hashFunc, secret, hkdfLabel)

	output := make([]byte, length)
	_, _ = reader.Read(output)
	return output
}

// DeriveSecret derives a secret using HKDF-Expand-Label.
// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
func DeriveSecret(hashAlg int, secret []byte, label string, transcriptHash []byte) []byte {
	hashSize := getHashSize(hashAlg)
	return hkdfExpandLabel(hashAlg, secret, label, transcriptHash, hashSize)
}

// TranscriptHash computes the transcript hash for the given messages.
// This is a simple wrapper around the hash function.
func TranscriptHash(hashAlg int, messages ...[]byte) []byte {
	hashFunc := getHashFunc(hashAlg)
	h := hashFunc()
	for _, msg := range messages {
		h.Write(msg)
	}
	return h.Sum(nil)
}

// EmptyHash returns the hash of an empty input.
func EmptyHash(hashAlg int) []byte {
	hashFunc := getHashFunc(hashAlg)
	h := hashFunc()
	return h.Sum(nil)
}

// TLS13KeySchedule holds the key schedule state for TLS 1.3.
type TLS13KeySchedule struct {
	HashAlg int

	// Secrets at different stages
	EarlySecret     []byte
	HandshakeSecret []byte
	MasterSecret    []byte

	// Derived secrets
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ClientAppTrafficSecret       []byte
	ServerAppTrafficSecret       []byte
	ExporterMasterSecret         []byte
	ResumptionMasterSecret       []byte
}

// NewTLS13KeySchedule creates a new TLS 1.3 key schedule.
func NewTLS13KeySchedule(hashAlg int) *TLS13KeySchedule {
	return &TLS13KeySchedule{
		HashAlg: hashAlg,
	}
}

// DeriveEarlySecret derives the early secret from PSK (or zeros if no PSK).
// early_secret = HKDF-Extract(0, psk)
// If psk is nil, uses zeros (for non-PSK handshake).
func (ks *TLS13KeySchedule) DeriveEarlySecret(psk []byte) {
	hashSize := getHashSize(ks.HashAlg)

	if psk == nil {
		psk = make([]byte, hashSize)
	}

	// salt = 0 (zeros of hash length)
	salt := make([]byte, hashSize)

	ks.EarlySecret = hkdfExtract(ks.HashAlg, salt, psk)
}

// DeriveHandshakeSecret derives the handshake secret from the shared secret.
// handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", ""), shared_secret)
func (ks *TLS13KeySchedule) DeriveHandshakeSecret(sharedSecret []byte) {
	// Derive salt from early secret
	emptyHash := EmptyHash(ks.HashAlg)
	salt := DeriveSecret(ks.HashAlg, ks.EarlySecret, labelDerived, emptyHash)

	ks.HandshakeSecret = hkdfExtract(ks.HashAlg, salt, sharedSecret)
}

// DeriveHandshakeTrafficSecrets derives the handshake traffic secrets.
// client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", transcript_hash)
// server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", transcript_hash)
func (ks *TLS13KeySchedule) DeriveHandshakeTrafficSecrets(transcriptHash []byte) {
	ks.ClientHandshakeTrafficSecret = DeriveSecret(ks.HashAlg, ks.HandshakeSecret, labelClientHandshake, transcriptHash)
	ks.ServerHandshakeTrafficSecret = DeriveSecret(ks.HashAlg, ks.HandshakeSecret, labelServerHandshake, transcriptHash)
}

// DeriveMasterSecret derives the master secret.
// master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
func (ks *TLS13KeySchedule) DeriveMasterSecret() {
	hashSize := getHashSize(ks.HashAlg)
	emptyHash := EmptyHash(ks.HashAlg)
	salt := DeriveSecret(ks.HashAlg, ks.HandshakeSecret, labelDerived, emptyHash)

	// IKM = zeros
	ikm := make([]byte, hashSize)

	ks.MasterSecret = hkdfExtract(ks.HashAlg, salt, ikm)
}

// DeriveAppTrafficSecrets derives the application traffic secrets.
// client_application_traffic_secret_0 = Derive-Secret(master_secret, "c ap traffic", transcript_hash)
// server_application_traffic_secret_0 = Derive-Secret(master_secret, "s ap traffic", transcript_hash)
func (ks *TLS13KeySchedule) DeriveAppTrafficSecrets(transcriptHash []byte) {
	ks.ClientAppTrafficSecret = DeriveSecret(ks.HashAlg, ks.MasterSecret, labelClientAppTraffic, transcriptHash)
	ks.ServerAppTrafficSecret = DeriveSecret(ks.HashAlg, ks.MasterSecret, labelServerAppTraffic, transcriptHash)
}

// DeriveExporterSecret derives the exporter master secret.
// exporter_master_secret = Derive-Secret(master_secret, "exp master", transcript_hash)
func (ks *TLS13KeySchedule) DeriveExporterSecret(transcriptHash []byte) {
	ks.ExporterMasterSecret = DeriveSecret(ks.HashAlg, ks.MasterSecret, labelExporter, transcriptHash)
}

// DeriveResumptionSecret derives the resumption master secret.
// resumption_master_secret = Derive-Secret(master_secret, "res master", transcript_hash)
func (ks *TLS13KeySchedule) DeriveResumptionSecret(transcriptHash []byte) {
	ks.ResumptionMasterSecret = DeriveSecret(ks.HashAlg, ks.MasterSecret, labelResumption, transcriptHash)
}

// TLS13KeyMaterial holds the derived key and IV for TLS 1.3.
type TLS13KeyMaterial struct {
	Key []byte
	IV  []byte
}

// DeriveTrafficKeys derives the key and IV from a traffic secret.
// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
// [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
func DeriveTrafficKeys(hashAlg int, trafficSecret []byte, cipherSuite *CipherSuiteInfo) *TLS13KeyMaterial {
	key := hkdfExpandLabel(hashAlg, trafficSecret, labelKey, nil, cipherSuite.KeyLen)
	iv := hkdfExpandLabel(hashAlg, trafficSecret, labelIV, nil, cipherSuite.IVLen)

	return &TLS13KeyMaterial{
		Key: key,
		IV:  iv,
	}
}

// UpdateTrafficSecret performs a key update on a traffic secret.
// application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
func UpdateTrafficSecret(hashAlg int, currentSecret []byte) []byte {
	hashSize := getHashSize(hashAlg)
	return hkdfExpandLabel(hashAlg, currentSecret, labelTrafficUpdate, nil, hashSize)
}

// DeriveFinishedKey derives the finished key from a traffic secret.
// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
func DeriveFinishedKey(hashAlg int, baseKey []byte) []byte {
	hashSize := getHashSize(hashAlg)
	return hkdfExpandLabel(hashAlg, baseKey, labelFinished, nil, hashSize)
}

// ComputeFinishedVerifyData computes the Finished verify_data.
// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
func ComputeFinishedVerifyData(hashAlg int, finishedKey, transcriptHash []byte) []byte {
	hashFunc := getHashFunc(hashAlg)
	mac := hmac.New(hashFunc, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

// DeriveKeysFromTrafficSecret is a convenience function to derive keys from a traffic secret.
func DeriveKeysFromTrafficSecret(trafficSecret []byte, cipherSuite *CipherSuiteInfo) *TLS13KeyMaterial {
	return DeriveTrafficKeys(cipherSuite.HashAlgorithm, trafficSecret, cipherSuite)
}

// ConstructTLS13Nonce constructs the nonce for TLS 1.3 AEAD.
// The nonce is XORed with the sequence number (padded to iv_length).
// nonce = write_iv XOR pad_to_iv_length(seq_num)
func ConstructTLS13Nonce(writeIV []byte, seqNum uint64) []byte {
	nonce := make([]byte, len(writeIV))
	copy(nonce, writeIV)

	// XOR with sequence number (right-aligned in nonce)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seqNum)

	// XOR the last 8 bytes of nonce with seqBytes
	ivLen := len(writeIV)
	for i := 0; i < 8; i++ {
		nonce[ivLen-8+i] ^= seqBytes[i]
	}

	return nonce
}

// ComputeTLS13AdditionalData computes the additional data for TLS 1.3 AEAD.
// For TLS 1.3, the additional data is:
// additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
// Where opaque_type is always 23 (application_data) and version is always 0x0303.
func ComputeTLS13AdditionalData(ciphertextLength int) []byte {
	ad := make([]byte, 5)
	ad[0] = ContentTypeApplicationData // opaque_type
	ad[1] = 0x03                       // legacy_record_version high byte
	ad[2] = 0x03                       // legacy_record_version low byte
	binary.BigEndian.PutUint16(ad[3:5], uint16(ciphertextLength))
	return ad
}

// GetHashAlgorithmForCipher returns the hash algorithm for a cipher suite.
// TLS 1.3 cipher suites use SHA-256 or SHA-384 based on the suite.
func GetHashAlgorithmForCipher(cipherSuiteID uint16) int {
	switch cipherSuiteID {
	case 0x1302: // TLS_AES_256_GCM_SHA384
		return HashSHA384
	default: // TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
		return HashSHA256
	}
}

// GetHashFunc returns the hash function for public use
func GetHashFunc(hashAlg int) func() hash.Hash {
	return getHashFunc(hashAlg)
}

// GetHashSize returns the hash size for public use
func GetHashSize(hashAlg int) int {
	return getHashSize(hashAlg)
}
