//go:build li

package li

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

func radiusAdmissionFixture(t *testing.T) (*Manager, *radius.Observation, *radius.Observation, uuid.UUID) {
	t.Helper()
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	generator, err := radius.NewIDGenerator()
	require.NoError(t, err)
	scope := radius.CaptureScope{OriginNodeID: "hunter", SourceID: "eth0", Epoch: generator.Epoch(), OperatorScope: "operator", ProfileRevision: "v1"}
	var observations []*radius.Observation
	for range 2 {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		id, err := generator.Next()
		require.NoError(t, err)
		o, _, err := radius.DecodePacket(raw, reader.LinkType(), ci, scope, id)
		require.NoError(t, err)
		observations = append(observations, o)
	}
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	return m, observations[0], observations[1], did
}
func activateRadiusAdmissionTask(t *testing.T, m *Manager, o *radius.Observation, did uuid.UUID) *InterceptTask {
	t.Helper()
	var username string
	for _, a := range o.Message.Attributes {
		if a.Type == 1 {
			username = string(a.Value)
			break
		}
	}
	task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: username}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only, RADIUSScope: radius.ScopeBinding{OperatorScope: o.Scope.OperatorScope, ProfileRevision: o.Scope.ProfileRevision}}
	require.NoError(t, m.ActivateTask(task))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	group, ok := m.filters.LookupRADIUSGroup(m.filters.GetFiltersForXID(task.XID)[0])
	require.True(t, ok)
	ref, match, err := group.Match(o)
	require.NoError(t, err)
	require.True(t, match)
	o.Direct = append(o.Direct, ref)
	return current
}
func radiusAdmissionDisplay(o *radius.Observation) *types.PacketDisplay {
	return &types.PacketDisplay{Protocol: "RADIUS", RawData: o.Packet, Timestamp: o.Capture.Timestamp}
}

func TestRADIUSAdmissionOwnersGenerationsAndGenericBypass(t *testing.T) {
	m, request, response, did := radiusAdmissionFixture(t)
	first := activateRadiusAdmissionTask(t, m, request, did)
	second := activateRadiusAdmissionTask(t, m, request, did)
	response.Association = radius.Association{Status: radius.AssociationUnique, RequestInstanceID: request.Capture.ID, RequestObservationID: request.Capture.ID, RequestFirstSeen: request.Capture.Timestamp}
	response.Inherited = request.Clone().Direct
	var got []uuid.UUID
	m.SetPacketProcessor(func(task *InterceptTask, _ *types.PacketDisplay) { got = append(got, task.XID) })
	send := func(o *radius.Observation) {
		m.ProcessPacketWithProvenance(radiusAdmissionDisplay(o), PacketFilterProvenance{RADIUS: o, RADIUSTrusted: true})
	}
	send(request)
	require.ElementsMatch(t, []uuid.UUID{first.XID, second.XID}, got)
	got = nil
	send(response)
	require.ElementsMatch(t, []uuid.UUID{first.XID, second.XID}, got)
	require.NoError(t, m.DeactivateTask(first.XID))
	got = nil
	send(response)
	require.Equal(t, []uuid.UUID{second.XID}, got)
	got = nil
	m.ProcessPacket(&types.PacketDisplay{Protocol: "SIP"}, m.filters.GetFiltersForXID(second.XID))
	require.Empty(t, got)
	m.ProcessPacketWithProvenance(radiusAdmissionDisplay(response), PacketFilterProvenance{RADIUS: response})
	require.Empty(t, got)
	stale := request.Clone()
	stale.Direct[1].TaskGeneration++
	stale.Direct = stale.Direct[1:]
	send(stale)
	require.Empty(t, got)
	require.NoError(t, m.DeactivateTask(second.XID))
	require.NoError(t, m.ActivateTask(second))
	send(response)
	require.Empty(t, got, "reused filter ID must not revive stale request evidence")
}

func TestRADIUSAdmissionRejectsPartialScopeAndAmbiguousEvidence(t *testing.T) {
	m, request, response, did := radiusAdmissionFixture(t)
	activateRadiusAdmissionTask(t, m, request, did)
	got := 0
	m.SetPacketProcessor(func(_ *InterceptTask, _ *types.PacketDisplay) { got++ })
	for _, mutate := range []func(*radius.Observation){
		func(o *radius.Observation) { o.Direct[0].Criteria = nil },
		func(o *radius.Observation) { o.Direct[0].Scope.OperatorScope = "other" },
		func(o *radius.Observation) { o.Direct[0].Criteria[0].FilterRevision++ },
		func(o *radius.Observation) { o.Direct[0].Criteria[0].Value = []byte("wrong") },
	} {
		o := request.Clone()
		mutate(o)
		m.ProcessPacketWithProvenance(radiusAdmissionDisplay(o), PacketFilterProvenance{RADIUS: o, RADIUSTrusted: true})
	}
	response.Inherited = request.Direct
	response.Association.Status = radius.AssociationAmbiguous
	m.ProcessPacketWithProvenance(radiusAdmissionDisplay(response), PacketFilterProvenance{RADIUS: response, RADIUSTrusted: true})
	require.Zero(t, got)
}

func TestRADIUSAdmissionConjunctionCannotCombineOwners(t *testing.T) {
	m, request, _, did := radiusAdmissionFixture(t)
	first := activateRadiusAdmissionTask(t, m, request, did)
	second := activateRadiusAdmissionTask(t, m, request, did)
	// Model two conjunctive criteria in each installed task. The same AVP can
	// satisfy both criteria, but transported groups still must remain complete.
	for _, task := range []*InterceptTask{first, second} {
		task.Targets = append(task.Targets, task.Targets[0])
		require.NoError(t, m.filters.RemoveFiltersForTask(task.XID))
		_, err := m.filters.CreateFiltersForTask(task)
		require.NoError(t, err)
	}
	request.Direct = nil
	for _, task := range []*InterceptTask{first, second} {
		group, ok := m.filters.LookupRADIUSGroup(m.filters.GetFiltersForXID(task.XID)[0])
		require.True(t, ok)
		ref, matched, err := group.Match(request)
		require.NoError(t, err)
		require.True(t, matched)
		request.Direct = append(request.Direct, ref)
	}
	got := 0
	m.SetPacketProcessor(func(_ *InterceptTask, _ *types.PacketDisplay) { got++ })
	send := func(o *radius.Observation) {
		m.ProcessPacketWithProvenance(radiusAdmissionDisplay(o), PacketFilterProvenance{RADIUS: o, RADIUSTrusted: true})
	}
	send(request)
	require.Equal(t, 2, got)
	got = 0
	partial := request.Clone()
	partial.Direct[0].Criteria = partial.Direct[0].Criteria[:1]
	partial.Direct[1].Criteria = partial.Direct[1].Criteria[1:]
	send(partial)
	require.Zero(t, got)
}

func TestRADIUSAdmissionDestinationChangeBetweenMatchAndEnqueue(t *testing.T) {
	m, request, _, did := radiusAdmissionFixture(t)
	task := activateRadiusAdmissionTask(t, m, request, did)
	replacement := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: replacement, Address: "other-mdf.invalid", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}))
	callbacks := 0
	m.SetPacketProcessor(func(matched *InterceptTask, _ *types.PacketDisplay) {
		callbacks++
		destinations := []uuid.UUID{replacement}
		require.NoError(t, m.ModifyTask(task.XID, &TaskModification{DestinationIDs: &destinations}))
		admission, ok := m.AcquireTaskAdmission(matched.XID, matched.ActivationGeneration)
		require.False(t, ok)
		require.Nil(t, admission)
	})
	m.ProcessPacketWithProvenance(radiusAdmissionDisplay(request), PacketFilterProvenance{RADIUS: request, RADIUSTrusted: true})
	require.Equal(t, 1, callbacks)
	m.ProcessPacketWithProvenance(radiusAdmissionDisplay(request), PacketFilterProvenance{RADIUS: request, RADIUSTrusted: true})
	require.Equal(t, 1, callbacks, "queued old group must not reach callback after destination change")
}

func TestRADIUSAdmissionSanitizesConflictingVoIPMetadataWithoutMutatingInput(t *testing.T) {
	m, request, _, did := radiusAdmissionFixture(t)
	activateRadiusAdmissionTask(t, m, request, did)
	packet := radiusAdmissionDisplay(request)
	packet.Protocol = "SIP"
	packet.VoIPData = &types.VoIPMetadata{Method: "INVITE", CallID: "spurious"}
	calls := 0
	m.SetPacketProcessor(func(_ *InterceptTask, admitted *types.PacketDisplay) {
		calls++
		require.NotSame(t, packet, admitted)
		require.Nil(t, admitted.VoIPData)
		require.Equal(t, "RADIUS", admitted.Protocol)
		require.NotNil(t, admitted.RADIUSData)
		require.Equal(t, request.Packet, admitted.RawData)
	})
	m.ProcessPacketWithProvenance(packet, PacketFilterProvenance{RADIUS: request, RADIUSTrusted: true})
	require.Equal(t, 1, calls)
	require.Equal(t, "SIP", packet.Protocol)
	require.Equal(t, "spurious", packet.VoIPData.CallID)
	require.Nil(t, packet.RADIUSData)
}
