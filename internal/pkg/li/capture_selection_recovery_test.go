//go:build li

package li

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCentralSelectionRecoveryRequiresTaskConfirmation(t *testing.T) {
	m := newStateTestManager(t, ManagerConfig{Enabled: true, TaskFilterDistributionScope: "local_only", StateFile: filepath.Join(t.TempDir(), "state.enc")}, nil)
	require.NoError(t, m.PrepareAdministrativeStorage())
	require.NoError(t, m.SetDurableRevoker(&administrativeTestRevoker{}))
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true}))
	now := time.Now().UTC()
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:private@example.test"}}, DeliveryType: DeliveryX2andX3, DestinationIDs: []uuid.UUID{did}, EndTime: now.Add(time.Hour), ImplicitDeactivationAllowed: true}
	require.NoError(t, m.ActivateTask(task))
	active, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	c := HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{"edge-a"}}
	filters, grants, encoded := publishSelectionTest(t, m, c, now)
	refs := []*management.CaptureSelectionRef{{Id: grants[0].Id, Revision: grants[0].Revision}}
	incarnation := m.StateIncarnation()
	restarted := restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
	require.Equal(t, incarnation, restarted.StateIncarnation())
	require.Zero(t, restarted.FilterCount(), "protected state alone must not rearm capture")
	_, err = restarted.ValidateCaptureSelectionAuthority(encoded, filters, grants, refs, "edge-a", 0, now.Add(time.Second), now.Add(time.Second), c)
	require.ErrorIs(t, err, ErrCaptureAuthority)
	require.NoError(t, restarted.applySnapshotDefinition(conflictSnapshot(active)))
	privateIDs := restarted.filters.GetFiltersForXID(task.XID)
	require.Len(t, privateIDs, 1)
	private, found := restarted.filters.GetFilter(privateIDs[0])
	require.True(t, found)
	require.Equal(t, management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY, private.DistributionScope)
	require.Equal(t, grants[0].Revision, private.Revision)
	_, err = restarted.ValidateCaptureSelectionAuthority(encoded, filters, grants, refs, "edge-a", 0, now.Add(time.Second), now.Add(time.Second), c)
	require.NoError(t, err, "confirmed unchanged owner and generation preserve historical facts")
	public, renewed, authority := publishSelectionTest(t, restarted, c, now.Add(time.Second))
	require.Empty(t, public)
	require.Equal(t, grants[0].Id, renewed[0].Id)
	require.Equal(t, grants[0].Revision, renewed[0].Revision)
	require.NotContains(t, string(authority), "private@example.test")
	// Another task owner must not inherit the opaque reference even if the
	// authenticated target definition and selection revision happen to match.
	restarted.stateIdentity.Store(&administrativeIdentity{incarnation: uuid.New()})
	_, err = restarted.ValidateCaptureSelectionAuthority(encoded, filters, grants, refs, "edge-a", 0, now.Add(time.Second), now.Add(time.Second), c)
	require.ErrorIs(t, err, ErrCaptureAuthority)
}
