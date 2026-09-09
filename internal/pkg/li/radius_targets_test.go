//go:build li

package li

import (
	"encoding/hex"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func radiusTargetTask() *InterceptTask {
	return &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "alice@example.test"}, {Type: TargetTypeMACAddress, Value: "020000000001"}, {Type: TargetTypeRADIUSAttribute, Value: "57086C696E652D61"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2Only, ActivationGeneration: 7, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "profile-1"}, RADIUSMACProfile: radius.MACProfileUppercaseHyphen}
}
func TestRADIUSTargetConjunctionAndGeneration(t *testing.T) {
	task := radiusTargetTask()
	fm := NewFilterManager(nil)
	ids, err := fm.CreateFiltersForTask(task)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	f, ok := fm.GetFilter(ids[0])
	require.True(t, ok)
	require.Equal(t, management.FilterType_FILTER_RADIUS_COMPOUND, f.Type)
	require.Equal(t, uint64(7), f.Revision)
	g, ok := fm.LookupRADIUSGroup(ids[0])
	require.True(t, ok)
	raw := make([]byte, 20)
	raw[0] = 1
	for _, v := range []string{"0114616C696365406578616D706C652E74657374", "1F1330322D30302D30302D30302D30302D3031", "57086C696E652D61"} {
		b, err := hex.DecodeString(v)
		require.NoError(t, err)
		raw = append(raw, b...)
	}
	raw[3] = byte(len(raw))
	msg, err := radius.Decode(raw)
	require.NoError(t, err)
	scope := radius.CaptureScope{OperatorScope: "operator-a", ProfileRevision: "profile-1", OriginNodeID: "hunter", SourceID: "eth0", Epoch: [16]byte{1}}
	obs := &radius.Observation{Scope: scope, Message: msg}
	obs.Capture.ID.Epoch = scope.Epoch
	obs.Capture.ID.Sequence = 1
	ref, matched, err := g.Match(obs)
	require.NoError(t, err)
	require.True(t, matched)
	require.Len(t, ref.Criteria, 3)
	require.True(t, g.CurrentReference(ref))
	obs.Scope.OperatorScope = "operator-b"
	_, matched, err = g.Match(obs)
	require.NoError(t, err)
	require.False(t, matched)
	task.ActivationGeneration++
	require.NoError(t, fm.UpdateFiltersForTask(task))
	next, ok := fm.LookupRADIUSGroup(ids[0])
	require.True(t, ok)
	require.False(t, next.CurrentReference(ref))
	obs.Scope = scope
	obs.Message.Raw = obs.Message.Raw[:len(obs.Message.Raw)-8]
	obs.Message.Raw[3] = byte(len(obs.Message.Raw))
	_, matched, err = next.Match(obs)
	require.NoError(t, err)
	require.False(t, matched)
}
func TestRADIUSTaskValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*InterceptTask)
	}{
		{"x3", func(t *InterceptTask) { t.DeliveryType = DeliveryX3Only }},
		{"combined", func(t *InterceptTask) { t.DeliveryType = DeliveryX2andX3 }},
		{"scope", func(t *InterceptTask) { t.RADIUSScope.OperatorScope = "" }},
		{"profile", func(t *InterceptTask) { t.RADIUSMACProfile = "" }},
		{"mixed", func(t *InterceptTask) {
			t.Targets = append(t.Targets, TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.test"})
		}},
		{"avp", func(t *InterceptTask) { t.Targets[2].Value = "020361" }},
		{"nai", func(t *InterceptTask) { t.Targets[0].Value = "alice@@example.test" }},
		{"mac", func(t *InterceptTask) { t.Targets[1].Value = "02000000000100" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := radiusTargetTask()
			tc.change(task)
			require.Error(t, NewRegistry(nil).validateTask(task))
			_, err := NewFilterManager(nil).CreateFiltersForTask(task)
			require.Error(t, err)
		})
	}
	task := radiusTargetTask()
	require.NoError(t, NewRegistry(nil).validateTask(task))
	require.Error(t, validateDestinationDelivery(task, []*Destination{{DID: task.DestinationIDs[0]}}))
	require.Error(t, validateDestinationDelivery(task, []*Destination{{X3Enabled: true, ProtocolType: "X3Only"}}))
	require.NoError(t, validateDestinationDelivery(task, []*Destination{{X2Enabled: true, ProtocolType: "X2Only"}}))
	changed := *task
	changed.RADIUSScope.ProfileRevision = "profile-2"
	require.False(t, equivalentDeliveryDefinition(task, &changed))
	require.False(t, equivalentReactivationIdentity(task, &changed))
	require.False(t, sipIdentityMatches(TargetIdentity{Type: TargetTypeNAI, Value: "alice@example.test"}, "sip:alice@example.test"))
}

func TestRADIUSRegistryModificationRevokesEvidence(t *testing.T) {
	r := NewRegistry(nil)
	task := radiusTargetTask()
	require.NoError(t, r.CreateDestination(&Destination{DID: task.DestinationIDs[0], Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
	require.NoError(t, r.ActivateTask(task))
	previous, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	scope := task.RADIUSScope
	scope.ProfileRevision = "profile-2"
	require.NoError(t, r.ModifyTask(task.XID, &TaskModification{RADIUSScope: &scope}))
	changed, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Greater(t, changed.ActivationGeneration, previous.ActivationGeneration)
	require.Equal(t, scope, changed.RADIUSScope)
	delivery := DeliveryX3Only
	require.Error(t, r.ModifyTask(task.XID, &TaskModification{DeliveryType: &delivery}))
	unchanged, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, changed, unchanged)
	enabled := true
	require.NoError(t, r.ModifyTask(task.XID, &TaskModification{ImplicitDeactivationAllowed: &enabled}))
	changedAgain, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Greater(t, changedAgain.ActivationGeneration, changed.ActivationGeneration)
}
