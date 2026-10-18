//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func selectionAuthorityFixture(t *testing.T) (*Manager, *InterceptTask, HandoverConfig, time.Time) {
	t.Helper()
	m := NewManager(ManagerConfig{Enabled: true, TaskFilterDistributionScope: "local_only"}, nil)
	m.stateIdentity.Store(&administrativeIdentity{incarnation: uuid.New()})
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example.test", Port: 9443, X2Enabled: true, X3Enabled: true}))
	now := time.Now().UTC()
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:invented-private-target@example.test"}}, DeliveryType: DeliveryX2andX3, DestinationIDs: []uuid.UUID{did}, EndTime: now.Add(10 * time.Minute), ImplicitDeactivationAllowed: true}
	require.NoError(t, m.ActivateTask(task))
	return m, task, HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{"edge-a"}}, now
}

func publishSelectionTest(t *testing.T, m *Manager, c HandoverConfig, now time.Time) ([]*management.Filter, []*management.CaptureSelectionGrant, []byte) {
	t.Helper()
	var filters []*management.Filter
	var grants []*management.CaptureSelectionGrant
	var encoded []byte
	require.NoError(t, m.PublishCaptureSelectionAuthority(c, "central", []*management.CaptureSelectionScope{{HunterId: "edge-a", Domain: 0}}, now, func(f []*management.Filter, g []*management.CaptureSelectionGrant, a []byte) error {
		filters, grants, encoded = f, g, a
		return nil
	}))
	return filters, grants, encoded
}

func TestCentralTaskSelectionPrivacyAndChangedTarget(t *testing.T) {
	m, task, c, now := selectionAuthorityFixture(t)
	filters, grants, encoded := publishSelectionTest(t, m, c, now)
	require.Empty(t, filters)
	require.Len(t, grants, 1)
	public, err := m.HandoverFilters()
	require.NoError(t, err)
	require.Empty(t, public)
	private, ok := m.filters.GetFilter(grants[0].Id)
	require.True(t, ok)
	require.Equal(t, management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY, private.DistributionScope)
	require.Contains(t, private.Pattern, "invented-private-target")
	wire, err := json.Marshal(grants)
	require.NoError(t, err)
	for _, data := range [][]byte{wire, encoded} {
		require.NotContains(t, string(data), "invented-private-target")
		require.NotContains(t, string(data), "filter_sha256")
		require.NotContains(t, string(data), "description")
	}
	digest, err := captureFilterDigest(private)
	require.NoError(t, err)
	require.False(t, bytes.Contains(encoded, []byte(digest)))
	refs := []*management.CaptureSelectionRef{{Id: grants[0].Id, Revision: grants[0].Revision}}
	validate := func(source string, domain uint32, at, later time.Time) error {
		_, err := m.ValidateCaptureSelectionAuthority(encoded, filters, grants, refs, source, domain, at, later, c)
		return err
	}
	require.NoError(t, validate("edge-a", 0, now.Add(time.Second), now.Add(2*time.Minute)), "capture lease expiry alone does not invalidate historical delivery")
	require.Error(t, validate("edge-b", 0, now.Add(time.Second), now))
	require.Error(t, validate("edge-a", 1, now.Add(time.Second), now))
	require.Error(t, validate("edge-a", 0, now.Add(time.Minute), now))
	targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:another-invented-target@example.test"}}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	require.ErrorIs(t, validate("edge-a", 0, now.Add(time.Second), now.Add(2*time.Second)), ErrCaptureAuthority)
	_, updated, _ := publishSelectionTest(t, m, c, now.Add(time.Second))
	require.Equal(t, grants[0].Id, updated[0].Id)
	require.Greater(t, updated[0].Revision, grants[0].Revision)
}

func TestCentralTaskSelectionDeactivationAndScopeFailure(t *testing.T) {
	m, task, c, now := selectionAuthorityFixture(t)
	filters, grants, encoded := publishSelectionTest(t, m, c, now)
	refs := []*management.CaptureSelectionRef{{Id: grants[0].Id, Revision: grants[0].Revision}}
	require.NoError(t, m.DeactivateTask(task.XID))
	_, err := m.ValidateCaptureSelectionAuthority(encoded, filters, grants, refs, "edge-a", 0, now.Add(time.Second), now.Add(2*time.Second), c)
	require.ErrorIs(t, err, ErrCaptureAuthority)
	f, g, _ := publishSelectionTest(t, m, c, now.Add(time.Second))
	require.Empty(t, f)
	require.Empty(t, g)
	require.NoError(t, m.ActivateTask(task))
	_, updated, _ := publishSelectionTest(t, m, c, now.Add(time.Second))
	require.Greater(t, updated[0].Revision, grants[0].Revision)
	require.Error(t, m.PublishCaptureSelectionAuthority(c, "central", []*management.CaptureSelectionScope{{HunterId: "other", Domain: 0}}, now, func([]*management.Filter, []*management.CaptureSelectionGrant, []byte) error {
		t.Fatal("must not publish unscoped local authority")
		return nil
	}))
}

func TestCentralTaskSelectionRejectsUnsupportedAndUnknownSetting(t *testing.T) {
	m, task, _, _ := selectionAuthorityFixture(t)
	for _, kind := range []TargetType{TargetTypeNAI, TargetTypeMACAddress, TargetTypeIMSI, TargetTypeIMEI} {
		candidate := cloneInterceptTask(task)
		candidate.XID = uuid.New()
		candidate.Targets = []TargetIdentity{{Type: kind, Value: "private"}}
		require.Error(t, m.ActivateTask(candidate))
		_, err := m.registry.GetTaskDetails(candidate.XID)
		require.ErrorIs(t, err, ErrTaskNotFound)
	}
	invalid := NewManager(ManagerConfig{Enabled: true, TaskFilterDistributionScope: "unknown"}, nil)
	require.Error(t, invalid.ValidateConfiguration())
}

func TestTaskTargetReorderingInvalidatesOpaqueIndexBinding(t *testing.T) {
	m, task, c, now := selectionAuthorityFixture(t)
	targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:first@example.test"}, {Type: TargetTypeSIPURI, Value: "sip:second@example.test"}}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	_, grants, _ := publishSelectionTest(t, m, c, now)
	targets[0], targets[1] = targets[1], targets[0]
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	_, updated, _ := publishSelectionTest(t, m, c, now)
	require.Greater(t, updated[0].Revision, grants[0].Revision, "canonical equivalence cannot rebind a position-based reference")
}

func TestLocalSIPSelectionTokenCannotRebindChangedTarget(t *testing.T) {
	m, task, _, now := selectionAuthorityFixture(t)
	event, err := sip.Parse([]byte("INVITE sip:invented-private-target@example.test SIP/2.0\r\nFrom: <sip:caller@example.test>\r\nTo: <sip:invented-private-target@example.test>\r\nCall-ID: local-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"), sip.ParseOptions{Timestamp: now})
	require.NoError(t, err)
	ids, authority, err := m.SelectLocalSIP(event, "edge-a")
	require.NoError(t, err)
	require.Len(t, ids, 1)
	count := 0
	m.SetPacketProcessor(func(*InterceptTask, *types.PacketDisplay) { count++ })
	pkt := &types.PacketDisplay{NodeID: "edge-a", Timestamp: now}
	provenance := PacketFilterProvenance{DirectFilterIDs: ids, CaptureAuthority: authority}
	m.ProcessPacketWithProvenance(pkt, provenance)
	require.Equal(t, 1, count)
	targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:replacement@example.test"}}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	m.ProcessPacketWithProvenance(pkt, provenance)
	require.Equal(t, 1, count, "already selected local IDs cannot inherit a new task generation")
}
