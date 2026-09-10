//go:build li

package li

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRADIUSX1LifecycleAndADMFConversion(t *testing.T) {
	scope := radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "profile-v1", OriginNodeID: "hunter-a", SourceID: "mirror-a"}
	m := NewManager(ManagerConfig{Enabled: true, RADIUSScope: scope, RADIUSMACProfile: radius.MACProfileUppercaseHyphen}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	avp := " 0104ff00 "
	mac := schema.MACAddress("02:ab:00:00:00:01")
	nai := schema.NAI("Alice@Example.test")
	identifiers := []*schema.TargetIdentifier{{Nai: &nai}, {MacAddress: &mac}, {RadiusAttribute: &avp}}
	targets := make([]x1.TargetIdentity, 0, len(identifiers))
	for _, input := range identifiers {
		target, err := x1.ParseRADIUSTarget(input)
		require.NoError(t, err)
		targets = append(targets, *target)
	}
	xid := uuid.New()
	task := &x1.Task{XID: xid, Targets: targets, DestinationIDs: []uuid.UUID{did}, DeliveryType: x1.DeliveryX2Only}
	require.NoError(t, m.ActivateTaskX1(task))
	stored, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, scope, stored.RADIUSScope)
	require.Equal(t, radius.MACProfileUppercaseHyphen, stored.RADIUSMACProfile)
	require.Len(t, stored.Targets, 3)
	initialGeneration := stored.ActivationGeneration
	unsupportedDelivery := x1.DeliveryX3Only
	require.Error(t, m.ModifyTaskX1(xid, &x1.TaskModification{DeliveryType: &unsupportedDelivery}))
	mixedTargets := append(append([]x1.TargetIdentity(nil), targets...), x1.TargetIdentity{Type: x1.TargetTypeSIPURI, Value: "sip:alice@example.test"})
	require.Error(t, m.ModifyTaskX1(xid, &x1.TaskModification{Targets: &mixedTargets}))
	unchanged, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, initialGeneration, unchanged.ActivationGeneration)
	require.Equal(t, stored.Targets, unchanged.Targets)
	reply, err := m.GetTaskDetailsX1(xid)
	require.NoError(t, err)
	require.Equal(t, targets, reply.Targets)
	require.Equal(t, x1.DeliveryX2Only, reply.DeliveryType)
	avp = "57086c696e652d61"
	parsed, err := x1.ParseRADIUSTarget(&schema.TargetIdentifier{RadiusAttribute: &avp})
	require.NoError(t, err)
	modifiedTargets := []x1.TargetIdentity{*parsed}
	require.NoError(t, m.ModifyTaskX1(xid, &x1.TaskModification{Targets: &modifiedTargets}))
	stored, err = m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Greater(t, stored.ActivationGeneration, initialGeneration)
	require.Equal(t, scope, stored.RADIUSScope)
	require.Equal(t, TargetTypeRADIUSAttribute, stored.Targets[0].Type)
	require.Equal(t, "57086C696E652D61", stored.Targets[0].Value)
	reply, err = m.GetTaskDetailsX1(xid)
	require.NoError(t, err)
	require.Equal(t, modifiedTargets, reply.Targets)
	schemaXID := schema.UUID(xid.String())
	schemaDID := schema.UUID(did.String())
	restored, err := TaskResponseDetailsToInterceptTask(&schema.TaskResponseDetails{TaskDetails: &schema.TaskDetails{XId: &schemaXID, TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{RadiusAttribute: &avp}}}, DeliveryType: "X2Only", ListOfDIDs: &schema.ListOfDids{DId: []*schema.UUID{&schemaDID}}}})
	require.NoError(t, err)
	m.bindRADIUSDeployment(restored)
	require.Equal(t, stored.Targets, restored.Targets)
	require.Equal(t, scope, restored.RADIUSScope)
	// The authoritative ADMF replacement uses the same generation-changing lifecycle.
	avp = "0104ff00"
	restored.Targets[0].Value = "0104FF00"
	handled, err := m.reconcileRADIUSTask(restored)
	require.NoError(t, err)
	require.True(t, handled)
	reconciled, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Greater(t, reconciled.ActivationGeneration, stored.ActivationGeneration)
	require.Equal(t, "0104FF00", reconciled.Targets[0].Value)
	require.NoError(t, m.DeactivateTaskX1(xid))
	_, admitted := m.AcquireTaskAdmission(xid, reconciled.ActivationGeneration)
	require.False(t, admitted)
}

func TestRADIUSADMFRejectsDiscardedScopeAndCriteria(t *testing.T) {
	xid := schema.UUID(uuid.NewString())
	nai := schema.NAI("alice@example.test")
	sip := schema.SIPURI("sip:alice@example.test")
	for _, testCase := range []struct {
		name string
		edit func(*schema.TaskDetails)
	}{
		{"nil criterion", func(td *schema.TaskDetails) {
			td.TargetIdentifiers.TargetIdentifier = append(td.TargetIdentifiers.TargetIdentifier, nil)
		}},
		{"mixed families", func(td *schema.TaskDetails) {
			td.TargetIdentifiers.TargetIdentifier = append(td.TargetIdentifiers.TargetIdentifier, &schema.TargetIdentifier{SipUri: &sip})
		}},
		{"service scope", func(td *schema.TaskDetails) { value := schema.UUID(uuid.NewString()); td.ProductID = &value }},
		{"combined delivery", func(td *schema.TaskDetails) { td.DeliveryType = "X2andX3" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			td := &schema.TaskDetails{XId: &xid, DeliveryType: "X2Only", TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{Nai: &nai}}}}
			testCase.edit(td)
			_, err := TaskResponseDetailsToInterceptTask(&schema.TaskResponseDetails{TaskDetails: td})
			require.Error(t, err)
		})
	}
}
