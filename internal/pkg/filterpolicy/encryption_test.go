package filterpolicy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLICapturePolicyRequiresExplicitEncryptedInitializationAndPreservesSignedState(t *testing.T) {
	cfg, signer := policyfixture.Config(t)
	cfg.Owner = "li"
	_, err := filterpolicy.Open(cfg)
	require.ErrorContains(t, err, "encrypted")
	cfg = policyfixture.Encrypted(t, cfg)
	state, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	require.False(t, state.Ready())
	require.Nil(t, state.Latest())
	require.NotNil(t, state.Keyring())
	signed, err := state.Verifier().SignSnapshot(signer, &management.PolicySnapshot{ProtocolVersion: 1, Domain: cfg.Domain, AuthorityId: cfg.AuthorityID, Revision: 1, OwnerKind: "li", Filters: []*management.Filter{{Id: "li-original-task", Type: management.FilterType_FILTER_SIP_USER, Pattern: "private-edge-target", Enabled: true}}, CaptureAuthority: []byte("private-signed-authority"), ValidFromNs: 1, ValidUntilNs: 2})
	require.NoError(t, err)
	require.NoError(t, state.Accept(signed, nil))
	require.NoError(t, state.Close())
	encoded, err := os.ReadFile(cfg.StateFile)
	require.NoError(t, err)
	require.False(t, bytes.Contains(encoded, []byte("private-edge-target")))
	require.False(t, bytes.Contains(encoded, []byte("private-signed-authority")))
	require.False(t, bytes.Contains(encoded, []byte("li-original-task")))
	require.Error(t, filterpolicy.Initialize(cfg), "offline initialization cannot reset an existing identity or ledger")
	recovered, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	require.True(t, proto.Equal(signed.Snapshot, recovered.Latest().Snapshot))
	require.False(t, recovered.Ready(), "encrypted desired state still requires effective reconciliation")
	require.NoError(t, recovered.Accept(signed, nil))
	require.True(t, recovered.Ready())
	require.NoError(t, recovered.Close())
	wrongBinding := cfg
	wrongBinding.Domain = "other-domain"
	_, err = filterpolicy.Open(wrongBinding)
	require.ErrorIs(t, err, securestore.ErrBinding)
	encoded[len(encoded)-1] ^= 1
	require.NoError(t, os.WriteFile(cfg.StateFile, encoded, 0600))
	_, err = filterpolicy.Open(cfg)
	require.ErrorIs(t, err, securestore.ErrAuthentication)
}

func TestEncryptedPolicyNeverRecreatesMissingIdentityLedgerOrSnapshot(t *testing.T) {
	for _, missing := range []string{"identity", "ledger", "snapshot"} {
		t.Run(missing, func(t *testing.T) {
			cfg, _ := policyfixture.Config(t)
			cfg.Owner = "li"
			cfg = policyfixture.Encrypted(t, cfg)
			ring, err := securestore.LoadKeyring(cfg.StorageKeys)
			require.NoError(t, err)
			name := cfg.StateFile
			switch missing {
			case "identity":
				files, err := filepath.Glob(filepath.Join(filepath.Dir(cfg.StateFile), ".capture-policy-identity-*"))
				require.NoError(t, err)
				require.Len(t, files, 1)
				name = files[0]
			case "ledger":
				name = filepath.Join(filepath.Dir(cfg.StateFile), ring.UsageFileName())
			}
			require.NoError(t, os.Remove(name))
			_, err = filterpolicy.Open(cfg)
			require.Error(t, err)
			require.Error(t, filterpolicy.Initialize(cfg), "remaining store evidence forbids reinitialization")
			_, err = os.Stat(name)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestEncryptedPolicyReserveOnlyAllowsAuthenticatedEmptyWithdrawal(t *testing.T) {
	cfg, signer := policyfixture.Config(t)
	cfg.Owner = "li"
	cfg = policyfixture.Encrypted(t, cfg)
	state, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	verifier := state.Verifier()
	previous, err := verifier.Sign(signer, 1, []*management.Filter{{Id: "li-original-task", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true}})
	require.NoError(t, err)
	require.NoError(t, state.Accept(previous, nil))
	require.NoError(t, state.Close())
	ring, err := securestore.LoadKeyring(cfg.StorageKeys)
	require.NoError(t, err)
	dir, err := securestore.OpenDir(filepath.Dir(cfg.StateFile))
	require.NoError(t, err)
	usage, err := securestore.OpenUsage(dir, ring, [16]byte{})
	require.NoError(t, err)
	// Consume the ordinary range through the existing durable offline allocator;
	// no fake or unaccounted encryption operation is introduced by this fixture.
	require.NoError(t, usage.ReserveAttempt(usage.Stats().OrdinaryInvocationsRemaining, 1, dir.Replace))
	require.NoError(t, usage.Close())
	require.NoError(t, dir.Close())
	state, err = filterpolicy.Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, state.Close()) }()
	product, err := verifier.Sign(signer, 2, []*management.Filter{{Id: "li-original-task", Type: management.FilterType_FILTER_SIP_USER, Pattern: "bob", Enabled: true}})
	require.NoError(t, err)
	require.ErrorIs(t, state.Accept(product, nil), securestore.ErrKeyExhausted)
	opaque, err := verifier.SignSnapshot(signer, &management.PolicySnapshot{ProtocolVersion: 1, Domain: cfg.Domain, AuthorityId: cfg.AuthorityID, Revision: 3, OwnerKind: "li", CaptureAuthority: []byte("new authority cannot use withdrawal reserve")})
	require.NoError(t, err)
	require.ErrorIs(t, state.Accept(opaque, nil), securestore.ErrKeyExhausted)
	empty, err := verifier.Sign(signer, 4, nil)
	require.NoError(t, err)
	tampered := proto.Clone(empty).(*management.SignedPolicySnapshot)
	tampered.Signature = []byte("invalid")
	require.ErrorIs(t, state.Accept(tampered, nil), filterpolicy.ErrInvalid)
	require.NoError(t, state.Accept(empty, nil))
	require.Empty(t, state.Latest().Snapshot.Filters)
	require.Equal(t, uint64(4), state.Latest().Snapshot.Revision)
}

func TestEncryptedPolicyPartialInitializationEvidenceIsNeverRecreated(t *testing.T) {
	for _, remaining := range []string{"identity", "ledger"} {
		t.Run(remaining, func(t *testing.T) {
			cfg, _ := policyfixture.Config(t)
			cfg.Owner = "li"
			cfg = policyfixture.Encrypted(t, cfg)
			ring, err := securestore.LoadKeyring(cfg.StorageKeys)
			require.NoError(t, err)
			identities, err := filepath.Glob(filepath.Join(filepath.Dir(cfg.StateFile), ".capture-policy-identity-*"))
			require.NoError(t, err)
			require.Len(t, identities, 1)
			ledger := filepath.Join(filepath.Dir(cfg.StateFile), ring.UsageFileName())
			require.NoError(t, os.Remove(cfg.StateFile))
			missing := ledger
			if remaining == "ledger" {
				missing = identities[0]
			}
			require.NoError(t, os.Remove(missing))
			_, err = filterpolicy.Open(cfg)
			require.Error(t, err)
			require.Error(t, filterpolicy.Initialize(cfg), "orphaned initialization evidence forbids a fresh store identity or ledger")
			_, err = os.Stat(missing)
			require.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Stat(cfg.StateFile)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}
