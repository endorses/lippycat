package filterpolicy_test

import (
	"errors"
	"os"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSignedPolicyRejectsTamperAndWrongAuthority(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	verifier, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	signer, err := verifier.ReadSigner(cfg.SigningKeyFile)
	require.NoError(t, err)
	require.True(t, filterpolicy.PublicKeysEqual(key.Public(), signer.Public()))
	snapshot, err := verifier.Sign(signer, 1, []*management.Filter{{Id: "shared/capture/bpf", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}})
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(snapshot))
	tampered := proto.Clone(snapshot).(*management.SignedPolicySnapshot)
	tampered.Snapshot.Filters[0].Pattern = "tcp"
	require.ErrorIs(t, verifier.Verify(tampered), filterpolicy.ErrInvalid)
	wrong, _ := policyfixture.Config(t)
	another, err := filterpolicy.NewVerifier(wrong)
	require.NoError(t, err)
	require.ErrorIs(t, another.Verify(snapshot), filterpolicy.ErrInvalid)
	_, err = verifier.Sign(signer, 2, []*management.Filter{{Id: "operator-local", Type: management.FilterType_FILTER_BPF, Pattern: "udp"}})
	require.ErrorIs(t, err, filterpolicy.ErrInvalid)
}

func TestSignedEmptySnapshotDeletionAndRollbackSurviveRestart(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	state, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	verifier := state.Verifier()
	first, err := verifier.Sign(key, 1, []*management.Filter{{Id: "shared/capture/ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.1", Enabled: true}})
	require.NoError(t, err)
	empty, err := verifier.Sign(key, 2, nil)
	require.NoError(t, err)
	channel, err := state.Subscribe()
	require.NoError(t, err)
	var effective []*management.Filter
	apply := func(snapshot *management.PolicySnapshot) error { effective = snapshot.Filters; return nil }
	require.NoError(t, state.Accept(first, apply))
	require.Len(t, effective, 1)
	require.NoError(t, state.Accept(empty, apply))
	require.Empty(t, effective)
	require.Equal(t, uint64(2), (<-channel).Snapshot.Revision, "coalescing retains complete latest empty state")
	require.ErrorIs(t, state.Accept(first, apply), filterpolicy.ErrRollback)
	conflict, err := verifier.Sign(key, 2, first.Snapshot.Filters)
	require.NoError(t, err)
	require.ErrorIs(t, state.Accept(conflict, apply), filterpolicy.ErrRollback)
	require.NoError(t, state.Close())
	recovered, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, recovered.Close()) }()
	require.False(t, recovered.Ready(), "a durable signature alone is not effective-policy readiness")
	require.ErrorIs(t, recovered.Check(first), filterpolicy.ErrRollback)
	require.NoError(t, recovered.Accept(recovered.Latest(), apply))
	require.Empty(t, effective)
	require.True(t, recovered.Ready())
}

func TestCommittedPolicyInstallationFailureRecoversSameRevision(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	state, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	snapshot, err := state.Verifier().Sign(key, 1, nil)
	require.NoError(t, err)
	require.ErrorIs(t, state.Accept(snapshot, func(*management.PolicySnapshot) error { return errors.New("capture install failed") }), filterpolicy.ErrNotReady)
	require.False(t, state.Ready())
	require.Equal(t, uint64(1), state.Latest().Snapshot.Revision)
	require.NoError(t, state.Close())
	recovered, err := filterpolicy.Open(cfg)
	require.NoError(t, err)
	require.NoError(t, recovered.Accept(snapshot, func(*management.PolicySnapshot) error { return nil }))
	require.NoError(t, recovered.Close())
	info, err := os.Stat(cfg.StateFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NoError(t, os.WriteFile(cfg.StateFile, []byte("corrupt state"), 0600))
	_, err = filterpolicy.Open(cfg)
	require.Error(t, err, "corrupt watermark cannot become empty authoritative policy")
}

func TestPolicyOwnerPreservesOriginalLIIDsAndSeparatesGenericAuthority(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	cfg.Owner = "li"
	cfg = policyfixture.Encrypted(t, cfg)
	verifier, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	snapshot, err := verifier.SignSnapshot(key, &management.PolicySnapshot{ProtocolVersion: 1, Domain: cfg.Domain, AuthorityId: cfg.AuthorityID, Revision: 1, OwnerKind: "li", Filters: []*management.Filter{{Id: "li-original-task", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true}}, CaptureAuthority: []byte("opaque-signed-grant"), ValidFromNs: 1, ValidUntilNs: 2, AllowOfflineCapture: true, SourceIds: []string{"edge"}})
	require.NoError(t, err)
	require.Equal(t, "li-original-task", snapshot.Snapshot.Filters[0].Id)
	cfg.Owner = "shared"
	generic, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	require.ErrorIs(t, generic.Verify(snapshot), filterpolicy.ErrInvalid)
	_, err = generic.SignSnapshot(key, &management.PolicySnapshot{ProtocolVersion: 1, Domain: cfg.Domain, AuthorityId: cfg.AuthorityID, Revision: 1, OwnerKind: "shared", AllowOfflineCapture: true})
	require.ErrorIs(t, err, filterpolicy.ErrInvalid, "ordinary shared policy cannot grant disconnected LI capture")
}
