package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// These frozen bytes are assembled independently from the pre-extraction media
// field numbers and protobuf varint rules, not EncodeRule/SnapshotChunks. The v2
// Ed25519 signature was generated independently over the v2 domain separator and
// the unsigned protobuf bytes. The fixed 00..1f seed is public test data.
const (
	legacyV1SnapshotHex         = "0801120d0a0970726f636573736f72100718032001280132550a0472756c65120d0a0970726f636573736f7210071803221c080b100c1a0463616c6c2201612a016230043a0873656c65637465642a080a0668756e746572321012093139322e302e322e3118a01f200238024063"
	legacyV2SnapshotHex         = "0802120d0a0970726f636573736f721007180320012801329b010a0472756c65120d0a0970726f636573736f72100718032220080b100c1a0463616c6c2201612a0162300440094a0a0a066f706171756510052a080a0668756e746572321012093139322e302e322e3118a01f2002380240634a4037a8d541c507a99839a8fbd803cfe9147280ec2c5222b6b2d01d47d47b26bcc4688ca9e0fa60d082a82c697f674bbc2bfaa4a69088b31d18e97f83d3def94e01"
	legacyV2HistoricalPacketHex = "82019b010a0472756c65120d0a0970726f636573736f72100718032220080b100c1a0463616c6c2201612a0162300440094a0a0a066f706171756510052a080a0668756e746572321012093139322e302e322e3118a01f2002380240634a4037a8d541c507a99839a8fbd803cfe9147280ec2c5222b6b2d01d47d47b26bcc4688ca9e0fa60d082a82c697f674bbc2bfaa4a69088b31d18e97f83d3def94e01"
	legacyV2ArtifactHex         = "0a0472756c65120d0a0970726f636573736f72100718032220080b100c1a0463616c6c2201612a0162300440094a0a0a066f706171756510052a080a0668756e746572321012093139322e302e322e3118a01f2002380240634a4037a8d541c507a99839a8fbd803cfe9147280ec2c5222b6b2d01d47d47b26bcc4688ca9e0fa60d082a82c697f674bbc2bfaa4a69088b31d18e97f83d3def94e01"
)

type legacyFixtureClock struct{}

func (legacyFixtureClock) Now() time.Time         { return time.Unix(0, 50) }
func (legacyFixtureClock) Elapsed() time.Duration { return 0 }
func fixtureHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	require.NoError(t, err)
	return decoded
}

func TestFrozenLegacyV1V2SnapshotsRetainExactMediaContract(t *testing.T) {
	for _, test := range []struct {
		name, vector string
		version      uint32
		protected    bool
	}{{"ordinary v1", legacyV1SnapshotHex, 1, false}, {"protected v2", legacyV2SnapshotHex, 2, true}} {
		t.Run(test.name, func(t *testing.T) {
			bytes := fixtureHex(t, test.vector)
			update := &management.MediaRuleUpdate{}
			require.NoError(t, proto.Unmarshal(bytes, update))
			require.Equal(t, test.version, update.ProtocolVersion)
			store, err := mediarules.New(mediarules.Config{ProcessorID: "processor", HunterID: "hunter", Domains: []mediaadmission.DomainID{0}, MaxRules: 4, MaxBytes: 32768, MaxEndpoints: 8, MaxEndpointsPerRule: 4, MaxSubscribers: 2, SubscriptionBuffer: 4, MaxLifetime: time.Hour, Clock: legacyFixtureClock{}})
			require.NoError(t, err)
			defer func() { require.NoError(t, store.Close()) }()
			receiver, err := NewReceiver(store, "processor", Limits{MaxMessageBytes: 1024, MaxSnapshotBytes: 4096, MaxRules: 4})
			require.NoError(t, err)
			require.NoError(t, receiver.Apply(update))
			rules := store.ActiveRules()
			require.Len(t, rules, 1)
			rule := rules[0]
			require.EqualValues(t, 3, rule.Revision)
			require.EqualValues(t, 11, rule.Call.Lifetime.Session)
			require.EqualValues(t, 12, rule.Call.Lifetime.Generation)
			require.Equal(t, "call", rule.Call.CallID)
			require.Equal(t, mediarules.RTPAndRTCP, rule.Endpoints[0].Kind)
			require.Equal(t, time.Unix(0, 2), rule.NotBefore)
			require.Equal(t, time.Unix(0, 99), rule.ExpiresAt)
			if test.protected {
				require.EqualValues(t, 9, rule.Call.CapturePolicyRevision)
				require.Equal(t, []mediarules.SelectionRef{{ID: "opaque", Revision: 5}}, rule.Call.SelectionGrants)
				require.Equal(t, fixtureHex(t, legacyV2ArtifactHex), store.Core().ActiveRules()[0].Proof)
			} else {
				require.Equal(t, []string{"selected"}, rule.Call.FilterIDs)
				require.Empty(t, rule.CaptureSignature)
				require.Empty(t, store.Core().ActiveRules()[0].Proof)
			}
			encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(EncodeRule(rule))
			require.NoError(t, err)
			original, err := (proto.MarshalOptions{Deterministic: true}).Marshal(update.Rules[0])
			require.NoError(t, err)
			require.Equal(t, original, encoded)
			roundtrip, err := (proto.MarshalOptions{Deterministic: true}).Marshal(update)
			require.NoError(t, err)
			require.Equal(t, bytes, roundtrip)
		})
	}
}

func TestFrozenHistoricalField16ProofAuthenticatesWithoutLiveBinding(t *testing.T) {
	require.Equal(t, filterpolicy.MaxMediaRuleBytes, learnedwire.DefaultEvidenceLimits.MaxProofBytes, "typed evidence preserves the established per-artifact legacy bound")
	packet := &data.CapturedPacket{}
	require.NoError(t, proto.Unmarshal(fixtureHex(t, legacyV2HistoricalPacketHex), packet))
	require.Equal(t, fixtureHex(t, legacyV2ArtifactHex), packet.CaptureSelectionProof)
	require.Nil(t, packet.LearnedCaptureEvidence)
	artifact := &management.MediaRule{}
	require.NoError(t, proto.Unmarshal(packet.CaptureSelectionProof, artifact))
	// Install the historical authority, then replace its entire epoch and remove
	// the relationship. Original capture authenticity must remain independent.
	store, err := mediarules.New(mediarules.Config{ProcessorID: "processor", HunterID: "hunter", Domains: []mediaadmission.DomainID{0}, MaxRules: 4, MaxBytes: 32768, MaxEndpoints: 8, MaxEndpointsPerRule: 4, MaxSubscribers: 2, SubscriptionBuffer: 4, MaxLifetime: time.Hour, Clock: legacyFixtureClock{}})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	receiver, err := NewReceiver(store, "processor", Limits{MaxMessageBytes: 1024, MaxSnapshotBytes: 4096, MaxRules: 4})
	require.NoError(t, err)
	update := &management.MediaRuleUpdate{}
	require.NoError(t, proto.Unmarshal(fixtureHex(t, legacyV2SnapshotHex), update))
	require.NoError(t, receiver.Apply(update))
	require.Len(t, store.ActiveRules(), 1)
	control, err := store.StartSession("processor", mediarules.Session{ProcessorID: "processor", Generation: 8})
	require.NoError(t, err)
	require.NoError(t, store.ApplySnapshot(control, 1, nil))
	require.Empty(t, store.ActiveRules())
	require.EqualValues(t, 8, store.Status().Session.Generation)

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	private := ed25519.NewKeyFromSeed(seed)
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, private.Public(), private)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fixture-public.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	verifier, err := filterpolicy.NewVerifier(filterpolicy.Config{Mode: "shared", Domain: "capture", AuthorityID: "fixture", TrustedCertFile: certFile, StateFile: filepath.Join(dir, "unused.state")})
	require.NoError(t, err)
	require.True(t, time.Unix(0, artifact.ExpiresAtNs).Before(now))
	require.NoError(t, verifier.VerifyMediaRule(artifact), "historical authenticity does not require any live store, control epoch, or unexpired lease")
	mutated := proto.Clone(artifact).(*management.MediaRule)
	mutated.Endpoints[0].Port++
	require.ErrorIs(t, verifier.VerifyMediaRule(mutated), filterpolicy.ErrInvalid)
	replay, err := (proto.MarshalOptions{Deterministic: true}).Marshal(packet)
	require.NoError(t, err)
	require.Equal(t, fixtureHex(t, legacyV2HistoricalPacketHex), replay, "field16 and original signed bytes remain exact")
}
