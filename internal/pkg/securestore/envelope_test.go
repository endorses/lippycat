package securestore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func cryptoKey(t *testing.T, id string, fill byte) KeyRef {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{fill}, 32), 0600))
	return KeyRef{ID: id, File: path}
}

func cryptoRing(t *testing.T, cfg KeyConfig) *Keyring {
	t.Helper()
	r, err := LoadKeyring(cfg)
	require.NoError(t, err)
	return r
}

func cryptoUsage(t *testing.T, ring *Keyring) (*Dir, *Usage, *Writer, Binding) {
	t.Helper()
	path := t.TempDir()
	require.NoError(t, os.Chmod(path, 0700))
	dir, err := OpenDir(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dir.Close()) })
	binding := Binding{Store: [16]byte{1, 2, 3, 4}, Object: "synthetic-sensitive-identity"}
	outcome, err := InitializeUsage(dir, ring, binding.Store)
	require.NoError(t, err)
	require.Equal(t, Committed, outcome)
	usage, err := OpenUsage(dir, ring, binding.Store)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, usage.Close()) })
	writer, err := NewWriter(usage)
	require.NoError(t, err)
	return dir, usage, writer, binding
}

func TestEnvelopeAuthenticatesEveryByteAndBinding(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 42)})
	dir, _, writer, binding := cryptoUsage(t, ring)
	payload := []byte("synthetic target and content; must never appear in encrypted files")
	encoded, err := writer.Seal(X3Product, binding, payload)
	require.NoError(t, err)
	plain, err := ring.Open(X3Product, binding, encoded, len(payload))
	require.NoError(t, err)
	require.Equal(t, payload, plain)
	for i := range encoded {
		changed := bytes.Clone(encoded)
		changed[i] ^= 1
		_, err := ring.Open(X3Product, binding, changed, len(payload))
		require.Error(t, err, "tampered byte %d authenticated", i)
	}
	for size := range len(encoded) {
		_, err := ring.Open(X3Product, binding, encoded[:size], len(payload))
		require.Error(t, err, "truncated length %d authenticated", size)
	}
	_, err = ring.Open(X2Product, binding, encoded, len(payload))
	require.Error(t, err)
	other := binding
	other.Store[0]++
	_, err = ring.Open(X3Product, other, encoded, len(payload))
	require.ErrorIs(t, err, ErrBinding)
	other = binding
	other.Object = "synthetic-sensitive-identitZ"
	_, err = ring.Open(X3Product, other, encoded, len(payload))
	require.ErrorIs(t, err, ErrBinding)
	_, err = ring.Open(X3Product, binding, encoded, len(payload)-1)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = ring.Open(X3Product, binding, append(bytes.Clone(encoded), 0), len(payload))
	require.ErrorIs(t, err, ErrEnvelope)
	outcome, err := dir.Replace("encrypted", encoded)
	require.NoError(t, err)
	require.Equal(t, Committed, outcome)
	disk, err := dir.Read("encrypted", MaxEnvelopeBytes)
	require.NoError(t, err)
	require.NotContains(t, string(disk), string(payload))
	require.NotContains(t, string(disk), binding.Object)
}

func TestEnvelopeKnownWireContractAndUntrustedLengthBounds(t *testing.T) {
	ref := cryptoKey(t, "write-key", 9)
	ring := cryptoRing(t, KeyConfig{Active: ref})
	_, _, writer, binding := cryptoUsage(t, ring)
	encoded, err := writer.Seal(FilterSnapshot, binding, []byte("payload"))
	require.NoError(t, err)
	require.Equal(t, "LCS1", string(encoded[:4]))
	require.Equal(t, []byte{1, 1, 0, 1, 0, 9, 0, 12}, encoded[4:12])
	require.Equal(t, uint64(18+len(binding.Object)+7+16), binary.BigEndian.Uint64(encoded[12:20]))
	// Independent standard-library decoding verifies the public wire contract.
	block, err := aes.NewCipher(bytes.Repeat([]byte{9}, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	head := 20 + 9 + 12
	plain, err := aead.Open(nil, encoded[head-12:head], encoded[head:], encoded[:head])
	require.NoError(t, err)
	require.Equal(t, binding.Store[:], plain[:16])
	require.Equal(t, binding.Object, string(plain[18:18+len(binding.Object)]))
	require.Equal(t, "payload", string(plain[18+len(binding.Object):]))
	for _, size := range []uint64{0, 15, MaxEnvelopeBytes, 1 << 63, ^uint64(0)} {
		malformed := bytes.Clone(encoded)
		binary.BigEndian.PutUint64(malformed[12:20], size)
		_, err := ring.Open(FilterSnapshot, binding, malformed, 10)
		require.ErrorIs(t, err, ErrEnvelope)
	}
	_, err = ring.Open(FilterSnapshot, binding, encoded, MaxPlaintextBytes)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = writer.Seal(Purpose(0), binding, nil)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = writer.Seal(FilterSnapshot, Binding{}, nil)
	require.ErrorIs(t, err, ErrEnvelope)
	_, err = writer.SealControl(X3Product, binding, nil)
	require.Error(t, err)
}

func TestEnvelopeKeyRotationAndExplicitLegacySelection(t *testing.T) {
	old := cryptoKey(t, "old", 12)
	newKey := cryptoKey(t, "new", 13)
	oldRing := cryptoRing(t, KeyConfig{Active: old})
	_, _, writer, binding := cryptoUsage(t, oldRing)
	encoded, err := writer.Seal(AdministrativeState, binding, []byte("state"))
	require.NoError(t, err)
	rotated := cryptoRing(t, KeyConfig{Active: newKey, Prior: []KeyRef{old}, LegacyID: old.ID})
	plain, err := rotated.Open(AdministrativeState, binding, encoded, 5)
	require.NoError(t, err)
	require.Equal(t, "state", string(plain))
	wrong := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "old", 14)})
	_, err = wrong.Open(AdministrativeState, binding, encoded, 5)
	require.ErrorIs(t, err, ErrAuthentication)
	missing := cryptoRing(t, KeyConfig{Active: newKey})
	_, err = missing.Open(AdministrativeState, binding, encoded, 5)
	require.ErrorIs(t, err, ErrAuthentication)
	nonce := bytes.Repeat([]byte{1}, 12)
	aad := []byte("LCX2\x01")
	legacy := oldRing.active.aead.Seal(nil, nonce, []byte("legacy"), aad)
	_, err = oldRing.OpenLegacy(nonce, legacy, aad, 100)
	require.Error(t, err, "unmapped legacy key must be rejected")
	plain, err = rotated.OpenLegacy(nonce, legacy, aad, 100)
	require.NoError(t, err)
	require.Equal(t, "legacy", string(plain))
	_, err = rotated.OpenLegacy(nonce, legacy, aad, 5)
	require.ErrorIs(t, err, ErrEnvelope)
}

func TestKeyConfigurationBoundsAndIndependentStores(t *testing.T) {
	ref := cryptoKey(t, "one", 20)
	for _, cfg := range []KeyConfig{
		{}, {Active: KeyRef{ID: "bad/id", File: ref.File}},
		{Active: ref, Prior: []KeyRef{ref}},
		{Active: ref, Prior: []KeyRef{{ID: "different", File: ref.File}}},
		{Active: ref, Prior: make([]KeyRef, 5)},
		{Active: ref, LegacyID: "absent"},
	} {
		_, err := LoadKeyring(cfg)
		require.Error(t, err)
	}
	for _, size := range []int{0, 31, 33, 4096} {
		path := filepath.Join(t.TempDir(), "key")
		require.NoError(t, os.WriteFile(path, make([]byte, size), 0600))
		_, err := LoadKeyring(KeyConfig{Active: KeyRef{ID: "key", File: path}})
		require.Error(t, err)
	}
	a := cryptoRing(t, KeyConfig{Active: ref})
	b := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "other-id", 20)})
	require.Error(t, CheckIndependent(a, b))
	c := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "other", 21)})
	require.NoError(t, CheckIndependent(a, nil, c))
	parsed, err := ParseReadKey("one=/private/key=part")
	require.NoError(t, err)
	require.Equal(t, "/private/key=part", parsed.File)
	for _, input := range []string{"key", "key=", "=file", "bad/id=file"} {
		_, err := ParseReadKey(input)
		require.Error(t, err)
	}
}

func TestConcurrentEncryptionUsesFreshNoncesAndSerializedReservations(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 35)})
	_, usage, writer, binding := cryptoUsage(t, ring)
	var wg sync.WaitGroup
	var mu sync.Mutex
	nonces := make(map[string]bool)
	for range 16 {
		wg.Go(func() {
			for range 32 {
				encoded, err := writer.Seal(X3Product, binding, []byte("packet"))
				if err != nil {
					t.Error(err)
					return
				}
				nonce := string(encoded[20+len("active") : 20+len("active")+12])
				mu.Lock()
				if nonces[nonce] {
					t.Error("repeated nonce")
				}
				nonces[nonce] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	require.Len(t, nonces, 512)
	require.Equal(t, invocationReservation, usage.Stats().Invocations)
	require.NoError(t, usage.Close())
	_, err := writer.Seal(X3Product, binding, nil)
	require.True(t, errors.Is(err, ErrUsageFault))
}

func TestEnvelopeMaximumSizesAndRejectedInputsDoNotConsumeUsage(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, strings.Repeat("a", MaxKeyIDBytes), 71)})
	_, usage, writer, binding := cryptoUsage(t, ring)
	binding.Object = strings.Repeat("x", MaxObjectIDBytes)
	maxPayload := MaxPlaintextBytes - bindingFixedBytes - len(binding.Object)
	payload := bytes.Repeat([]byte{0xaa}, maxPayload)
	encoded, err := writer.Seal(X3Product, binding, payload)
	require.NoError(t, err)
	require.Len(t, encoded, MaxEnvelopeBytes)
	decoded, err := ring.Open(X3Product, binding, encoded, maxPayload)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, decoded))
	before := usage.Stats()
	_, err = writer.Seal(X3Product, binding, append(payload, 0))
	require.ErrorIs(t, err, ErrEnvelope)
	for _, object := range []string{"", strings.Repeat("a", MaxObjectIDBytes+1), "contains\x00nul", string([]byte{0xff})} {
		bad := binding
		bad.Object = object
		_, err := writer.Seal(X3Product, bad, nil)
		require.ErrorIs(t, err, ErrEnvelope)
	}
	require.Equal(t, before, usage.Stats())
}

func TestAuthenticatedMalformedBindingFrames(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 72)})
	_, _, writer, binding := cryptoUsage(t, ring)
	encoded, err := writer.Seal(X3Product, binding, []byte("payload"))
	require.NoError(t, err)
	headerLength := fixedHeaderBytes + len("active") + nonceBytes
	plain, err := ring.active.aead.Open(nil, encoded[headerLength-nonceBytes:headerLength], encoded[headerLength:], encoded[:headerLength])
	require.NoError(t, err)
	for _, badLength := range []uint16{0, 1, MaxObjectIDBytes, 65535} {
		malformed := bytes.Clone(plain)
		binary.BigEndian.PutUint16(malformed[16:18], badLength)
		header := bytes.Clone(encoded[:headerLength])
		// Synthetic authenticated malformed input, independent of production Seal.
		binary.BigEndian.PutUint16(header[headerLength-2:], badLength)
		ciphertext := ring.active.aead.Seal(nil, header[headerLength-nonceBytes:], malformed, header)
		_, err := ring.Open(X3Product, binding, append(header, ciphertext...), len("payload"))
		require.Error(t, err)
	}
}

func TestKeyringMaximumPriorKeysAndCrossStorePriorCollision(t *testing.T) {
	active := cryptoKey(t, "active", 80)
	prior := []KeyRef{cryptoKey(t, "prior1", 81), cryptoKey(t, "prior2", 82), cryptoKey(t, "prior3", 83), cryptoKey(t, "prior4", 84)}
	ring := cryptoRing(t, KeyConfig{Active: active, Prior: prior, LegacyID: "prior4"})
	require.Len(t, ring.keys, 5)
	other := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new-active", 85), Prior: []KeyRef{cryptoKey(t, "different-id", 84)}})
	require.Error(t, CheckIndependent(ring, other), "prior keys across stores must also be independent")
	_, err := LoadKeyring(KeyConfig{Active: active, Prior: append(prior, cryptoKey(t, "prior5", 86))})
	require.Error(t, err)
}
