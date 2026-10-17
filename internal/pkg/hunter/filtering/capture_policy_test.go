//go:build hunter || all

package filtering

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type captureLeaseFixture struct {
	manager *Manager
	config  filterpolicy.Config
	signer  crypto.Signer
}

func newCaptureLeaseFixture(t *testing.T) *captureLeaseFixture {
	t.Helper()
	config, signer := policyfixture.Config(t)
	config.Owner, config.StorageProtection = "li", "encrypted"
	key := make([]byte, securestore.KeyBytes)
	_, err := rand.Read(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "capture-policy-key")
	require.NoError(t, os.WriteFile(path, key, 0600))
	clear(key)
	config.StorageKeys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "capture-policy-test", File: path}}
	require.NoError(t, filterpolicy.Initialize(config))
	config.SigningKeyFile = ""
	manager := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.NoError(t, manager.InitializeSharedPolicy(config, []string{"bpf"}))
	t.Cleanup(func() { require.NoError(t, manager.CloseSharedPolicy()) })
	return &captureLeaseFixture{manager: manager, config: config, signer: signer}
}

func (f *captureLeaseFixture) sign(t *testing.T, revision uint64, offline bool) *management.SignedPolicySnapshot {
	t.Helper()
	now := time.Now()
	snapshot, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, &management.PolicySnapshot{
		ProtocolVersion: 1, Domain: f.config.Domain, AuthorityId: f.config.AuthorityID,
		OwnerKind: "li", Revision: revision,
		Filters:          []*management.Filter{{Id: "li-original-task-0", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}},
		CaptureAuthority: []byte("opaque-authority-verified-by-central"),
		ValidFromNs:      time.Now().Add(-time.Minute).UnixNano(), ValidUntilNs: now.Add(time.Minute).UnixNano(),
		AllowOfflineCapture: offline, SourceIds: []string{"edge"},
	})
	require.NoError(t, err)
	return snapshot
}

func (f *captureLeaseFixture) install(t *testing.T, signed *management.SignedPolicySnapshot) {
	t.Helper()
	require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{snapshot: signed}))
}

func TestCapturePolicyOrdinaryCaptureNeedsNoLILease(t *testing.T) {
	local := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.True(t, local.CaptureAllowed(time.Now()))
	require.Empty(t, local.EffectiveCapturePolicy())
	local.PolicyDisconnected()
	require.True(t, local.CaptureAllowed(time.Now().Add(24*time.Hour)))
	shared := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	shared.sharedPolicy = &sharedPolicyConsumer{config: filterpolicy.Config{Mode: "shared", Owner: "shared"}}
	require.True(t, shared.CaptureAllowed(time.Now()))
	shared.PolicyDisconnected()
	require.True(t, shared.CaptureAllowed(time.Now().Add(24*time.Hour)), "ordinary shared policy has no offline interception lease")
}

func TestCapturePolicyLIRequiresFreshRevisionAfterRestart(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	require.False(t, f.manager.CaptureAllowed(time.Now()), "a protected empty store is not capture authority")
	first := f.sign(t, 7, false)
	f.install(t, first)
	require.True(t, f.manager.CaptureAllowed(time.Now()))
	require.NoError(t, f.manager.CloseSharedPolicy())
	restarted := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.NoError(t, restarted.InitializeSharedPolicy(f.config, []string{"bpf"}))
	t.Cleanup(func() { require.NoError(t, restarted.CloseSharedPolicy()) })
	require.False(t, restarted.CaptureAllowed(time.Now()))
	require.ErrorContains(t, restarted.InitializePolicy(t.Context(), snapshotConnection{snapshot: first}), "fresh authority revision")
	require.False(t, restarted.CaptureAllowed(time.Now()), "receiving cached bytes remotely cannot renew a restart")
	next := f.sign(t, 8, false)
	require.NoError(t, restarted.InitializePolicy(t.Context(), snapshotConnection{snapshot: next}))
	require.True(t, restarted.CaptureAllowed(time.Now()))
	for _, startup := range []string{"cached", "local"} {
		config := f.config
		config.Startup = startup
		candidate := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
		require.ErrorContains(t, candidate.InitializeSharedPolicy(config, []string{"bpf"}), "startup wait")
	}
}

func TestCapturePolicyFiniteLeaseAndDisconnectedPermission(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{false: "online-only", true: "explicit-offline"}[offline], func(t *testing.T) {
			f := newCaptureLeaseFixture(t)
			snapshot := f.sign(t, 1, offline)
			f.install(t, snapshot)
			require.True(t, f.manager.CaptureAllowed(time.Now()))
			f.manager.PolicyDisconnected()
			require.Equal(t, offline, f.manager.CaptureAllowed(time.Now()))
			require.False(t, f.manager.CaptureAllowed(time.Unix(0, snapshot.Snapshot.ValidUntilNs)), "offline permission cannot extend the signed lease")
		})
	}
}

func TestCapturePolicyClockRollbackStaysClosedUntilFreshRevision(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	first := f.sign(t, 3, true)
	f.install(t, first)
	now := time.Now()
	require.True(t, f.manager.CaptureAllowed(now.Add(time.Second)))
	require.False(t, f.manager.CaptureAllowed(now.Add(500*time.Millisecond)))
	require.False(t, f.manager.CaptureAllowed(now.Add(2*time.Second)), "catching up the wall clock cannot clear rollback")
	require.ErrorContains(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{snapshot: first}), "fresh signed capture revision")
	f.install(t, f.sign(t, 4, true))
	require.True(t, f.manager.CaptureAllowed(time.Now()))
}

func TestCapturePolicyRejectsOtherSourcesAndExpiredAuthority(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	for _, test := range []struct {
		name   string
		change func(*management.PolicySnapshot)
	}{
		{"source", func(s *management.PolicySnapshot) { s.SourceIds = []string{"different-edge"} }},
		{"expired", func(s *management.PolicySnapshot) {
			s.ValidFromNs, s.ValidUntilNs = time.Now().Add(-time.Minute).UnixNano(), time.Now().Add(-time.Second).UnixNano()
		}},
		{"future", func(s *management.PolicySnapshot) {
			s.ValidFromNs, s.ValidUntilNs = time.Now().Add(time.Minute).UnixNano(), time.Now().Add(2*time.Minute).UnixNano()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := f.sign(t, 1, true).Snapshot
			test.change(snapshot)
			signed, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
			require.NoError(t, err)
			require.Error(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{snapshot: signed}))
			require.False(t, f.manager.CaptureAllowed(time.Now()))
			require.Empty(t, f.manager.EffectiveCapturePolicy())
		})
	}
}

func TestCapturePolicyEmptyOrOtherHunterFiltersCannotBroadenCapture(t *testing.T) {
	for _, kind := range []string{"empty", "disabled", "other-hunter"} {
		t.Run(kind, func(t *testing.T) {
			f := newCaptureLeaseFixture(t)
			snapshot := f.sign(t, 1, true).Snapshot
			switch kind {
			case "empty":
				snapshot.Filters = nil
			case "disabled":
				snapshot.Filters[0].Enabled = false
			case "other-hunter":
				snapshot.Filters[0].TargetHunters = []string{"different-edge"}
			}
			signed, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
			require.NoError(t, err)
			f.install(t, signed)
			require.False(t, f.manager.CaptureAllowed(time.Now()), "a valid lease without applicable filters cannot authorize capture-all")
		})
	}
}

func TestCapturePolicyAuthenticatedSourceRevocationStopsOfflineCapture(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	f.install(t, f.sign(t, 1, true))
	require.True(t, f.manager.CaptureAllowed(time.Now()))
	snapshot := f.sign(t, 2, true).Snapshot
	snapshot.SourceIds = []string{"different-edge"}
	revocation, err := f.manager.sharedPolicy.state.Verifier().SignSnapshot(f.signer, snapshot)
	require.NoError(t, err)
	// Before authentication, changing source claims must not retire authority or
	// advance the durable revision watermark.
	forged := proto.Clone(revocation).(*management.SignedPolicySnapshot)
	forged.Signature[0] ^= 1
	require.Error(t, f.manager.installSharedPolicy(forged, false))
	require.Equal(t, uint64(1), f.manager.sharedPolicy.state.Latest().Snapshot.Revision)
	require.True(t, f.manager.CaptureAllowed(time.Now()))
	if err := f.manager.installSharedPolicy(revocation, false); err != nil {
		t.Logf("source withdrawal returned an explicit capture-readiness error: %v", err)
	}
	require.False(t, f.manager.CaptureAllowed(time.Now()), "known source withdrawal must stop capture even when the previous lease allowed disconnection")
	require.Equal(t, uint64(2), f.manager.sharedPolicy.state.Latest().Snapshot.Revision, "authenticated withdrawal must prevent old policy from returning after restart")
}

type rejectingCaptureBoundary struct{}

func (rejectingCaptureBoundary) ApplyPolicyChange(func() error) error {
	return errors.New("capture boundary cannot drain")
}

func (rejectingCaptureBoundary) ApplyCaptureSnapshot([]byte, func() error) error {
	return errors.New("capture boundary cannot drain")
}

func TestCapturePolicyFailedBoundaryCannotKeepStaleEffectiveAuthority(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	first := f.sign(t, 1, true)
	f.install(t, first)
	require.True(t, f.manager.CaptureAllowed(time.Now()))
	previous, err := proto.MarshalOptions{Deterministic: true}.Marshal(first)
	require.NoError(t, err)
	require.Equal(t, previous, f.manager.EffectiveCapturePolicy())
	f.manager.SetPolicyChangeCoordinator(rejectingCaptureBoundary{})
	require.NoError(t, f.manager.InitializePolicy(t.Context(), snapshotConnection{snapshot: f.sign(t, 2, true)}))
	require.ErrorIs(t, f.manager.ApplyPendingInitialE(), filterpolicy.ErrNotReady)
	require.False(t, f.manager.sharedPolicy.state.Ready())
	require.False(t, f.manager.CaptureAllowed(time.Now()), "unreconciled durable desired policy must block the lifetime producer")
	require.Empty(t, f.manager.EffectiveCapturePolicy(), "old matchers may remain diagnostic, but no token may be effective")
	require.Equal(t, uint64(2), f.manager.sharedPolicy.state.Latest().Snapshot.Revision)
}

type quiescingCaptureRestarter struct {
	recordingRestarter
	quiesced int
}

func (r *quiescingCaptureRestarter) Quiesce(context.Context) error {
	r.quiesced++
	return nil
}

func TestCapturePolicyQuiescesDeviceAfterOnlineOnlyDisconnect(t *testing.T) {
	f := newCaptureLeaseFixture(t)
	restarter := &quiescingCaptureRestarter{}
	f.manager.captureRestarter = restarter
	f.install(t, f.sign(t, 1, false))
	require.NoError(t, f.manager.QuiesceExpiredPolicy(t.Context()))
	require.Zero(t, restarter.quiesced)
	f.manager.PolicyDisconnected()
	require.NoError(t, f.manager.QuiesceExpiredPolicy(t.Context()))
	require.Equal(t, 1, restarter.quiesced)
}
