//go:build li

package li

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func radiusSnapshotDetails(xid, did uuid.UUID, radiusTask bool) *schema.TaskResponseDetails {
	nai, sip := schema.NAI("alice@example.test"), schema.SIPURI("sip:alice@example.test")
	target := schema.TargetIdentifier{SipUri: &sip}
	if radiusTask {
		target = schema.TargetIdentifier{Nai: &nai}
	}
	details := makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{target})
	details.TaskDetails.DeliveryType = "X2Only"
	return details
}

func TestSnapshotRADIUSLifecycleRouting(t *testing.T) {
	for _, scenario := range []struct {
		name           string
		previous       bool
		previousRADIUS bool
		incomingRADIUS bool
		changedStart   bool
	}{
		{name: "new_radius", incomingRADIUS: true},
		{name: "radius_to_generic", previous: true, previousRADIUS: true},
		{name: "generic_to_radius", previous: true, incomingRADIUS: true},
		{name: "reject_radius_to_generic", previous: true, previousRADIUS: true, changedStart: true},
		{name: "reject_generic_to_radius", previous: true, incomingRADIUS: true, changedStart: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			scope := radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1"}
			m := NewManager(ManagerConfig{Enabled: true, RADIUSScope: scope, FilterPusher: newStubFilterStore()}, nil)
			t.Cleanup(m.Stop)
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
			var previousGeneration uint64
			if scenario.previous {
				converted, err := ConvertSnapshotTask(radiusSnapshotDetails(xid, did, scenario.previousRADIUS))
				require.NoError(t, err)
				m.bindRADIUSDeployment(converted.Task)
				converted.Task.Definition = authoritativeDefinition(converted.Task)
				require.NoError(t, m.ActivateTask(converted.Task))
				previous, err := m.GetTaskDetails(xid)
				require.NoError(t, err)
				previousGeneration = previous.ActivationGeneration
			}
			incoming := radiusSnapshotDetails(xid, did, scenario.incomingRADIUS)
			if scenario.changedStart {
				start := schema.QualifiedMicrosecondDateTime("2021-01-01T00:00:00.000000Z")
				incoming.TaskDetails.ListOfMediationDetails.MediationDetails[0].StartTime = &start
			}
			response := &schema.GetAllDetailsResponse{
				ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{DestinationResponseDetails: []*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}},
				ListOfTaskResponseDetails:        &schema.ListOfTaskResponseDetails{TaskResponseDetails: []*schema.TaskResponseDetails{incoming}},
			}
			m.snapshotMu.Lock()
			snapshot, taskCount, _ := m.applyADMFSnapshotEntries(response, false)
			m.snapshotMu.Unlock()
			current, err := m.GetTaskDetails(xid)
			require.NoError(t, err, "new RADIUS entries must actually activate")
			if scenario.previous {
				_, admitted := m.AcquireTaskAdmission(xid, previousGeneration)
				require.False(t, admitted, "replacement must revoke the previous authorization")
			}
			if scenario.changedStart {
				require.Equal(t, 0, taskCount)
				require.EqualValues(t, 1, snapshot.status.TaskFailures)
				require.Equal(t, TaskStatusFailed, current.Status)
				require.Empty(t, m.filters.GetFiltersForXID(xid), "rejected RADIUS replacements must withdraw old filters")
				return
			}
			require.Equal(t, 1, taskCount)
			require.Zero(t, snapshot.status.TotalFailures)
			require.Equal(t, TaskStatusActive, current.Status)
			require.False(t, current.Definition.Conflict)
			require.Equal(t, scenario.incomingRADIUS, IsRADIUSTask(current))
			ids := m.filters.GetFiltersForXID(xid)
			require.Len(t, ids, 1)
			filter, exists := m.filters.GetFilter(ids[0])
			require.True(t, exists)
			_, hasRADIUSGroup := m.filters.LookupRADIUSGroup(ids[0])
			require.Equal(t, scenario.incomingRADIUS, hasRADIUSGroup)
			if scenario.incomingRADIUS {
				require.Equal(t, scope, current.RADIUSScope)
				require.Equal(t, management.FilterType_FILTER_RADIUS_COMPOUND, filter.Type)
			} else {
				require.Equal(t, management.FilterType_FILTER_SIP_URI, filter.Type)
			}
		})
	}
}
