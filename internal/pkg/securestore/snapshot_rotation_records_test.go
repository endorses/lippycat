package securestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func rotationRecordFixture(t *testing.T) (snapshotRotationRequest, *Keyring, *Keyring) {
	t.Helper()
	source := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "old-active", 81), Prior: []KeyRef{cryptoKey(t, "old-read", 82)}})
	target := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new-active", 83)})
	commitment, err := snapshotRotationRingCommitment(source, target)
	require.NoError(t, err)
	return snapshotRotationRequest{
		Purpose: FilterSnapshot, Store: [16]byte{1, 2, 3, 4},
		Parent: FileIdentity{Device: 1, Inode: 2}, Source: FileIdentity{Device: 1, Inode: 3},
		SourcePath: [32]byte{1}, DestinationPath: [32]byte{2},
		SourceCiphertext: [32]byte{3}, Payload: [32]byte{4}, SourceRing: commitment,
		PredecessorBootstrap: [32]byte{5}, PredecessorProgress: [32]byte{6},
		SourceEnvelopeBytes: 180, PayloadBytes: 79,
		Object: "filters", SourceName: "source.enc", DestinationName: "destination.enc",
		SourceKeyID: source.ActiveID(), NewKeyID: target.ActiveID(),
	}, source, target
}

func TestSnapshotRotationRequestCanonicalAndEntireCommitment(t *testing.T) {
	r, _, target := rotationRecordFixture(t)
	b, err := r.marshal()
	require.NoError(t, err)
	// Independently constructed with Python struct.pack and hmac/hashlib.
	sum := sha256.Sum256(b)
	require.Len(t, b, 358)
	require.Equal(t, "f603246939ceb5358bd841ae41fc04bbec60d0a3f4f94779137284b2504f910b", hex.EncodeToString(sum[:]))
	require.Equal(t, "6771a132b7ff15f5368fe8037fddb125d22047caa80275cc55ce31946ee5f5ca", hex.EncodeToString(r.SourceRing[:]))
	require.LessOrEqual(t, len(b), snapshotRotationRequestMax)
	got, err := parseSnapshotRotationRequest(b)
	require.NoError(t, err)
	require.Equal(t, r, got)
	token, err := snapshotRotationToken(r, target)
	require.NoError(t, err)
	require.Equal(t, "026a4539e44e30218ae8c3205c0b2dfd01578657264fc97d19722fd7f8be8042", hex.EncodeToString(token[:]))
	for i := range b {
		mutant := bytes.Clone(b)
		mutant[i] ^= 1
		decoded, err := parseSnapshotRotationRequest(mutant)
		if err != nil {
			continue
		}
		changed, err := snapshotRotationToken(decoded, target)
		if err != nil {
			continue
		}
		require.NotEqual(t, token, changed, "request byte %d was not committed", i)
	}
	for n := range len(b) {
		_, err := parseSnapshotRotationRequest(b[:n])
		require.Error(t, err, "truncation at %d", n)
	}
	_, err = parseSnapshotRotationRequest(append(bytes.Clone(b), 0))
	require.Error(t, err)
	_, err = parseSnapshotRotationRequest(make([]byte, snapshotRotationRequestMax+1))
	require.Error(t, err)
	_, err = snapshotRotationToken(r, nil)
	require.Error(t, err)
}

func TestSnapshotRotationRequestRejectsInvalidIdentitiesAndBounds(t *testing.T) {
	original, _, _ := rotationRecordFixture(t)
	cases := map[string]func(*snapshotRotationRequest){
		"purpose":             func(r *snapshotRotationRequest) { r.Purpose = X3Product },
		"store":               func(r *snapshotRotationRequest) { r.Store = [16]byte{} },
		"parent":              func(r *snapshotRotationRequest) { r.Parent.Inode = 0 },
		"source":              func(r *snapshotRotationRequest) { r.Source.Inode = 0 },
		"source-path":         func(r *snapshotRotationRequest) { r.SourcePath = [32]byte{} },
		"destination-path":    func(r *snapshotRotationRequest) { r.DestinationPath = [32]byte{} },
		"ciphertext":          func(r *snapshotRotationRequest) { r.SourceCiphertext = [32]byte{} },
		"payload":             func(r *snapshotRotationRequest) { r.Payload = [32]byte{} },
		"source-ring":         func(r *snapshotRotationRequest) { r.SourceRing = [32]byte{} },
		"partial-predecessor": func(r *snapshotRotationRequest) { r.PredecessorProgress = [32]byte{} },
		"same-id":             func(r *snapshotRotationRequest) { r.NewKeyID = r.SourceKeyID },
		"id-size":             func(r *snapshotRotationRequest) { r.SourceKeyID = strings.Repeat("a", MaxKeyIDBytes+1) },
		"id-syntax":           func(r *snapshotRotationRequest) { r.NewKeyID = "new key" },
		"object-size":         func(r *snapshotRotationRequest) { r.Object = strings.Repeat("a", MaxObjectIDBytes+1) },
		"name-utf8":           func(r *snapshotRotationRequest) { r.SourceName = "\xff" },
		"name-path":           func(r *snapshotRotationRequest) { r.DestinationName = "../other" },
		"implicit-replace":    func(r *snapshotRotationRequest) { r.DestinationName = r.SourceName },
		"wrong-in-place":      func(r *snapshotRotationRequest) { r.InPlace = true },
		"cipher-size":         func(r *snapshotRotationRequest) { r.SourceEnvelopeBytes = MaxEnvelopeBytes + 1 },
		"cipher-small":        func(r *snapshotRotationRequest) { r.SourceEnvelopeBytes = 1 },
		"payload-overflow":    func(r *snapshotRotationRequest) { r.PayloadBytes = ^uint64(0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := original
			mutate(&r)
			_, err := r.marshal()
			require.ErrorIs(t, err, errSnapshotRotationRecord)
		})
	}
	r := original
	r.InPlace, r.DestinationName = true, r.SourceName
	r.PredecessorBootstrap, r.PredecessorProgress = [32]byte{}, [32]byte{}
	_, err := r.marshal()
	require.NoError(t, err)
	// Untrusted length prefixes cannot allocate an oversized string.
	b, err := original.marshal()
	require.NoError(t, err)
	binary.BigEndian.PutUint16(b[296:298], 65535)
	_, err = parseSnapshotRotationRequest(b)
	require.Error(t, err)
}

func TestSnapshotRotationRingFreshnessAndImmutableMaterial(t *testing.T) {
	_, source, target := rotationRecordFixture(t)
	first, err := snapshotRotationRingCommitment(source, target)
	require.NoError(t, err)
	for _, cfg := range []KeyConfig{
		{Active: cryptoKey(t, "fresh-id", 81)},
		{Active: cryptoKey(t, "fresh-id", 82)},
		{Active: cryptoKey(t, "old-read", 89)},
		{Active: cryptoKey(t, "different-new", 89), Prior: []KeyRef{cryptoKey(t, "extra", 90)}},
	} {
		_, err := snapshotRotationRingCommitment(source, cryptoRing(t, cfg))
		require.Error(t, err)
	}
	active, prior := cryptoKey(t, "old-active", 81), cryptoKey(t, "old-read", 82)
	same := cryptoRing(t, KeyConfig{Active: active, Prior: []KeyRef{prior}})
	second, err := snapshotRotationRingCommitment(same, target)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.NoError(t, os.WriteFile(active.File, bytes.Repeat([]byte{91}, KeyBytes), 0600))
	second, err = snapshotRotationRingCommitment(same, target)
	require.NoError(t, err)
	require.Equal(t, first, second, "loaded material must not be reread")
	changed := cryptoRing(t, KeyConfig{Active: active, Prior: []KeyRef{prior}})
	second, err = snapshotRotationRingCommitment(changed, target)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	_, err = snapshotRotationRingCommitment(nil, target)
	require.Error(t, err)
}

func TestSnapshotRotationBootstrapAuthenticationAndDomains(t *testing.T) {
	r, _, target := rotationRecordFixture(t)
	token, err := snapshotRotationToken(r, target)
	require.NoError(t, err)
	bootstrap := snapshotRotationBootstrap{snapshotRotationRequired, r.Purpose, r.Store, token}
	b, err := bootstrap.marshal(target)
	require.NoError(t, err)
	require.Equal(t, "4c5255310102000101020304000000000000000000000000026a4539e44e30218ae8c3205c0b2dfd01578657264fc97d19722fd7f8be80426e72ea4542f9386606f3d97e2eaf5ce0605acae4b8c7d0c2f59fe47118ebf921", hex.EncodeToString(b))
	require.Len(t, b, snapshotRotationBootstrapBytes)
	got, err := parseSnapshotRotationBootstrap(b, target)
	require.NoError(t, err)
	require.Equal(t, bootstrap, got)
	for i := range b {
		mutant := bytes.Clone(b)
		mutant[i] ^= 1
		_, err := parseSnapshotRotationBootstrap(mutant, target)
		require.Error(t, err, "tampered bootstrap byte %d", i)
	}
	for n := range len(b) {
		_, err := parseSnapshotRotationBootstrap(b[:n], target)
		require.Error(t, err)
	}
	_, err = parseSnapshotRotationBootstrap(append(bytes.Clone(b), 0), target)
	require.Error(t, err)
	other := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new-active", 84)})
	_, err = parseSnapshotRotationBootstrap(b, other)
	require.ErrorIs(t, err, ErrAuthentication)
	mutant := bytes.Clone(b)
	copy(mutant[56:], target.active.mac(usageMACDomain, mutant[:56]))
	_, err = parseSnapshotRotationBootstrap(mutant, target)
	require.ErrorIs(t, err, ErrAuthentication)
	for _, stage := range []byte{0, 3, 255} {
		mutant := bytes.Clone(b)
		mutant[5] = stage
		copy(mutant[56:], target.active.mac("lippycat/securestore/rotation/bootstrap/v1\x00", mutant[:56]))
		_, err := parseSnapshotRotationBootstrap(mutant, target)
		require.ErrorIs(t, err, errSnapshotRotationRecord)
	}
	for _, secret := range []string{r.SourceName, r.DestinationName, r.SourceKeyID, r.NewKeyID, r.Object} {
		require.NotContains(t, string(b), secret)
	}
}

func TestSnapshotRotationProgressStrictStagesAndBinding(t *testing.T) {
	r, _, target := rotationRecordFixture(t)
	_, usage, writer, binding := cryptoUsage(t, target)
	r.Store = binding.Store
	token, err := snapshotRotationToken(r, target)
	require.NoError(t, err)
	bootstrap := snapshotRotationBootstrap{snapshotRotationRequired, r.Purpose, r.Store, token}
	for _, stage := range []snapshotRotationProgressStage{snapshotRotationPlanned, snapshotRotationPrepared, snapshotRotationComplete} {
		p := snapshotRotationProgress{Stage: stage, Request: r}
		if stage != snapshotRotationPlanned {
			p.CandidateBytes = uint64(fixedHeaderBytes+len(r.NewKeyID)+nonceBytes+tagBytes+bindingFixedBytes+len(r.Object)) + r.PayloadBytes
			p.CandidateHash = [32]byte{99}
		}
		encrypted, err := sealSnapshotRotationProgress(p, target, writer)
		require.NoError(t, err)
		require.LessOrEqual(t, len(encrypted), snapshotRotationRecordMax)
		got, err := openSnapshotRotationProgress(encrypted, target, bootstrap, r.DestinationPath)
		require.NoError(t, err)
		require.Equal(t, p, got)
		_, err = openSnapshotRotationProgress(encrypted, target, bootstrap, [32]byte{88})
		require.Error(t, err)
		for _, mutate := range []func(*snapshotRotationBootstrap){
			func(b *snapshotRotationBootstrap) { b.Purpose = AdministrativeState },
			func(b *snapshotRotationBootstrap) { b.Store[0]++ },
			func(b *snapshotRotationBootstrap) { b.Token[0]++ },
			func(b *snapshotRotationBootstrap) { b.Stage = snapshotRotationUninitialized },
		} {
			bad := bootstrap
			mutate(&bad)
			_, err := openSnapshotRotationProgress(encrypted, target, bad, r.DestinationPath)
			require.Error(t, err)
		}
		plain, err := p.marshal()
		require.NoError(t, err)
		for n := range len(plain) {
			_, err := parseSnapshotRotationProgress(plain[:n])
			require.Error(t, err)
		}
		for _, index := range []int{4, 6, 7, 8, 12} {
			bad := bytes.Clone(plain)
			bad[index] ^= 128
			_, err := parseSnapshotRotationProgress(bad)
			require.Error(t, err)
		}
		_, err = parseSnapshotRotationProgress(append(bytes.Clone(plain), 0))
		require.Error(t, err)
		wrong := p
		wrong.CandidateHash = [32]byte{}
		wrong.CandidateBytes++
		_, err = wrong.marshal()
		require.Error(t, err)
		// Authenticated progress under a mismatched committed request still fails.
		wrong = p
		wrong.Request.SourceCiphertext[0]++
		plain, err = wrong.marshal()
		require.NoError(t, err)
		encrypted, err = writer.Seal(r.Purpose, snapshotRotationProgressBinding(r.Store, r.DestinationPath, token), plain)
		require.NoError(t, err)
		_, err = openSnapshotRotationProgress(encrypted, target, bootstrap, r.DestinationPath)
		require.ErrorIs(t, err, ErrBinding)
	}
	usage.mu.Lock()
	usage.usedSeals = MaxKeyInvocations * 9 / 10
	usage.mu.Unlock()
	_, err = sealSnapshotRotationProgress(snapshotRotationProgress{Stage: snapshotRotationPlanned, Request: r}, target, writer)
	require.ErrorIs(t, err, ErrKeyExhausted, "rotation must not consume the control reserve")
}
