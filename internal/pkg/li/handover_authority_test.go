//go:build li

package li

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func handoverFixture(t *testing.T, implicit bool) (*Manager, *InterceptTask, []*management.Filter, HandoverConfig, time.Time) {
	t.Helper()
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	// These tests isolate generation semantics; production requires the actual
	// authenticated administrative store to establish this identity.
	m.stateIdentity.Store(&administrativeIdentity{incarnation: uuid.New()})
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example.test", Port: 9443, X2Enabled: true, X3Enabled: true}))
	now := time.Now().UTC()
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:alice@example.test"}}, DeliveryType: DeliveryX2andX3, DestinationIDs: []uuid.UUID{did}, EndTime: now.Add(time.Minute), ImplicitDeactivationAllowed: implicit}
	require.NoError(t, m.ActivateTask(task))
	filters, err := m.HandoverFilters()
	require.NoError(t, err)
	require.Len(t, filters, 1)
	config := HandoverConfig{Enabled: true, LeaseDuration: 2 * time.Minute, SourceIDs: []string{"edge-a"}}
	return m, task, filters, config, now
}

func TestLIHandoverLeaseRespectsImplicitDeactivation(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-deactivation", true: "implicit-expiry"}[implicit], func(t *testing.T) {
			m, task, filters, config, now := handoverFixture(t, implicit)
			encoded, err := m.BuildHandoverAuthority(filters, config, now)
			require.NoError(t, err)
			authority, err := DecodeHandoverAuthority(encoded)
			require.NoError(t, err)
			until := now.Add(config.LeaseDuration)
			if implicit {
				until = task.EndTime
			}
			require.Equal(t, until.UnixNano(), authority.Grants[0].ValidUntilNS)
			require.False(t, config.AllowOffline, "offline capture is never implicit")
			require.NoError(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, "edge-a", now.Add(time.Second), now.Add(2*time.Second), config))
		})
	}
}

func TestLIHandoverRejectsChangedTaskAndReusedFilterID(t *testing.T) {
	m, task, filters, config, now := handoverFixture(t, true)
	encoded, err := m.BuildHandoverAuthority(filters, config, now)
	require.NoError(t, err)
	authority, err := DecodeHandoverAuthority(encoded)
	require.NoError(t, err)
	count := 0
	m.SetPacketProcessor(func(*InterceptTask, *types.PacketDisplay) { count++ })
	packet := &types.PacketDisplay{NodeID: "edge-a", Timestamp: now.Add(time.Second)}
	provenance := PacketFilterProvenance{DirectFilterIDs: []string{filters[0].Id}, CaptureAuthority: authority}
	m.ProcessPacketWithProvenance(packet, provenance)
	require.Equal(t, 1, count)
	targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:bob@example.test"}}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	current, err := m.HandoverFilters()
	require.NoError(t, err)
	require.Equal(t, filters[0].Id, current[0].Id, "ID intentionally reused across policy change")
	require.ErrorIs(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, "edge-a", now.Add(time.Second), now.Add(2*time.Second), config), ErrCaptureAuthority)
	// Exercise the actual task-lookup boundary independently of ingress checks.
	m.ProcessPacketWithProvenance(packet, provenance)
	require.Equal(t, 1, count, "old capture grant cannot bind to the new task state")
}

func TestLIHandoverCaptureScopeValidityAndRevocation(t *testing.T) {
	m, task, filters, config, now := handoverFixture(t, true)
	config.ClockUncertainty = time.Second
	encoded, err := m.BuildHandoverAuthority(filters, config, now)
	require.NoError(t, err)
	for _, test := range []struct {
		name   string
		source string
		at     time.Time
	}{
		{"other-source", "edge-b", now.Add(5 * time.Second)},
		{"before-start", "edge-a", now.Add(-time.Second)},
		{"uncertain-start", "edge-a", now},
		{"uncertain-end", "edge-a", task.EndTime.Add(-time.Second)},
		{"expired", "edge-a", task.EndTime.Add(time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorIs(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, test.source, test.at, now.Add(10*time.Second), config), ErrCaptureAuthority)
		})
	}
	require.NoError(t, m.DeactivateTask(task.XID))
	require.ErrorIs(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, "edge-a", now.Add(5*time.Second), now.Add(10*time.Second), config), ErrCaptureAuthority)
	remaining, err := m.HandoverFilters()
	require.NoError(t, err)
	require.Empty(t, remaining)
}

func TestLIHandoverReactivationCannotReuseOldCaptureAuthority(t *testing.T) {
	m, task, filters, config, now := handoverFixture(t, false)
	encoded, err := m.BuildHandoverAuthority(filters, config, now)
	require.NoError(t, err)
	before, err := DecodeHandoverAuthority(encoded)
	require.NoError(t, err)
	require.NoError(t, m.DeactivateTask(task.XID))
	require.NoError(t, m.ActivateTask(task))
	current, err := m.HandoverFilters()
	require.NoError(t, err)
	require.Equal(t, filters[0].Id, current[0].Id)
	refreshed, err := m.BuildHandoverAuthority(current, config, now)
	require.NoError(t, err)
	after, err := DecodeHandoverAuthority(refreshed)
	require.NoError(t, err)
	require.Greater(t, after.Grants[0].ActivationGeneration, before.Grants[0].ActivationGeneration)
	require.ErrorIs(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, "edge-a", now.Add(time.Second), now.Add(2*time.Second), config), ErrCaptureAuthority)
	require.NoError(t, m.ValidateHandoverAuthority(refreshed, current, []string{current[0].Id}, "edge-a", now.Add(time.Second), now.Add(2*time.Second), config))
}

func TestLIHandoverRequiresPersistentIncarnationAndCanonicalAuthority(t *testing.T) {
	m, _, filters, config, now := handoverFixture(t, false)
	encoded, err := m.BuildHandoverAuthority(filters, config, now)
	require.NoError(t, err)
	_, err = DecodeHandoverAuthority(append(encoded, byte(' ')))
	require.ErrorIs(t, err, ErrCaptureAuthority)
	var authority HandoverAuthority
	require.NoError(t, json.Unmarshal(encoded, &authority))
	authority.Grants = append(authority.Grants, authority.Grants[0])
	conflict, err := json.Marshal(authority)
	require.NoError(t, err)
	_, err = DecodeHandoverAuthority(conflict)
	require.ErrorIs(t, err, ErrCaptureAuthority)
	m.stateIdentity.Store(&administrativeIdentity{incarnation: uuid.New()})
	require.ErrorIs(t, m.ValidateHandoverAuthority(encoded, filters, []string{filters[0].Id}, "edge-a", now.Add(time.Second), now.Add(2*time.Second), config), ErrCaptureAuthority)
	m.stateIdentity.Store(nil)
	_, err = m.BuildHandoverAuthority(filters, config, now)
	require.ErrorIs(t, err, ErrCaptureAuthority)
}

func TestLIHandoverConfigurationRequiresExplicitBounds(t *testing.T) {
	_, err := (HandoverConfig{Enabled: true}).Normalize()
	require.Error(t, err)
	_, err = (HandoverConfig{LeaseDuration: time.Minute}).Normalize()
	require.Error(t, err)
	_, err = (HandoverConfig{Enabled: true, LeaseDuration: time.Minute, ClockUncertainty: time.Minute, SourceIDs: []string{"a"}}).Normalize()
	require.Error(t, err)
	_, err = (HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{"a", "a"}}).Normalize()
	require.Error(t, err)
}
