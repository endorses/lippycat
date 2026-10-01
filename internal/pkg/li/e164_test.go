//go:build li

package li

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestE164ConversionValidationAndMatching(t *testing.T) {
	for _, value := range []string{"1", "15551234567", "123456789012345", "", "+15551234567", "1234567890123456", "12 34"} {
		t.Run(value, func(t *testing.T) {
			number := schema.InternationalE164(value)
			target, err := convertTargetIdentifier(&schema.TargetIdentifier{E164Number: &number})
			candidate := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeE164, Value: value}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3}
			validationErr := (&Registry{}).validateTask(candidate)
			if !schema.ValidE164Number(value) {
				require.Error(t, err)
				require.ErrorIs(t, validationErr, ErrInvalidTask)
				_, _, filterErr := NewFilterManager(nil).mapTargetToFilterType(candidate.Targets[0])
				require.Error(t, filterErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, validationErr)
			require.Equal(t, TargetTypeE164, target.Type)
			require.Equal(t, TargetTypeE164, convertTargetType(x1.TargetTypeE164))
			require.Equal(t, x1.TargetTypeE164, convertTargetTypeToX1(TargetTypeE164))
			kind, pattern, err := NewFilterManager(nil).mapTargetToFilterType(*target)
			require.NoError(t, err)
			require.Equal(t, management.FilterType_FILTER_PHONE_NUMBER, kind)
			require.Equal(t, value, pattern)
			require.True(t, sipIdentityMatches(*target, "<sip:+"+value+"@example.invalid>"))
			require.False(t, sipIdentityMatches(*target, "<sip:+"+value+"9@example.invalid>"))
			require.True(t, isSIPIdentityTarget(target.Type))
		})
	}
}

func TestE164LegacyStateCanonicalIdentity(t *testing.T) {
	// Preserve every earlier numeric enum, including RADIUS targets.
	require.Equal(t, TargetType(2), TargetTypeTELURI)
	require.Equal(t, TargetType(12), TargetTypeRADIUSAttribute)
	require.Equal(t, TargetType(13), TargetTypeE164)
	legacy := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeTELURI, Value: "15551234567"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3}
	modern := *legacy
	modern.Targets = []TargetIdentity{{Type: TargetTypeE164, Value: "15551234567"}}
	require.True(t, equivalentTaskDefinition(legacy, &modern))
	require.True(t, equivalentReactivationIdentity(legacy, &modern))
	require.True(t, equivalentDeliveryDefinition(legacy, &modern))
	require.Equal(t, TargetTypeTELURI, legacy.Targets[0].Type, "comparison does not mutate historical state")
	modern.Targets[0].Value = "15551234568"
	require.False(t, equivalentTaskDefinition(legacy, &modern))
	modern.Targets[0] = TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551234567"}
	require.False(t, equivalentTaskDefinition(legacy, &modern), "migration equivalence is restricted to collapsed legacy E.164")
	for _, target := range []TargetIdentity{legacy.Targets[0], {Type: TargetTypeE164, Value: "15551234567"}} {
		s := stateFixture(t)
		s.Tasks[0].Targets = []TargetIdentity{target}
		encoded, err := MarshalStateSnapshot(s)
		require.NoError(t, err)
		restored, err := UnmarshalStateSnapshot(encoded)
		require.NoError(t, err)
		require.Equal(t, target, restored.Tasks[0].Targets[0])
	}
	invalid := stateFixture(t)
	invalid.Tasks[0].Targets = []TargetIdentity{{Type: TargetTypeE164, Value: "+15551234567"}}
	_, err := MarshalStateSnapshot(invalid)
	require.ErrorIs(t, err, ErrStateSnapshot)
}

func TestE164SignallingAndMediaDirection(t *testing.T) {
	target := TargetIdentity{Type: TargetTypeE164, Value: "15551230000"}
	xid := uuid.New()
	r := newTestResolver(t, MediaDirectionConfig{})
	offer := inviteRequest(testCallID, remoteURI, targetURI, sdpBody(coreAddr, corePort))
	answer := inviteOK(testCallID, remoteURI, targetURI, sdpBody(gwAddr, gwPort))
	require.Equal(t, x2x3.PayloadDirectionToTarget, PayloadDirectionForTarget(target, offer))
	r.ObserveSIP(xid, target, offer)
	r.ObserveSIP(xid, target, answer)
	require.Equal(t, x2x3.PayloadDirectionToTarget, r.PayloadDirection(xid, target, rtpPkt(testCallID, ssrcToTarget, coreAddr, corePort, gwAddr, gwPort)))
	require.Equal(t, x2x3.PayloadDirectionToTarget, r.PayloadDirection(xid, target, rtpPkt(testCallID, ssrcToTarget, gwAddr, gwPort, ueAddr, uePort)))
	require.Equal(t, x2x3.PayloadDirectionFromTarget, r.PayloadDirection(xid, target, rtpPkt(testCallID, ssrcFromTarget, gwAddr, gwPort, coreAddr, corePort)))
}

func TestE164CompleteSnapshotConfirmsLegacyReplayIdentity(t *testing.T) {
	did, xid := uuid.New(), uuid.New()
	number := schema.InternationalE164("15551234567")
	details := makeTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{E164Number: &number}})
	start := schema.QualifiedMicrosecondDateTime(time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z"))
	liid := schema.LIID("synthetic-e164-replay")
	details.TaskDetails.ListOfMediationDetails = &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{StartTime: &start, LIID: &liid, DeliveryType: "HI2andHI3"}}}
	restored, err := TaskResponseDetailsToInterceptTask(details)
	require.NoError(t, err)
	restored.ActivationGeneration = 7
	restored.Targets[0].Type = TargetTypeTELURI
	response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{details})
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, err := fmt.Fprint(w, response)
		require.NoError(t, err)
	})
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true}, nil)
	m.persistedActive[xid] = restored
	require.NoError(t, m.Start())
	defer m.Stop()
	active, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TargetTypeE164, active.Targets[0].Type)
	require.Equal(t, uint64(7), active.ActivationGeneration)
	require.True(t, m.ReplayTaskAuthorized(xid, 7))
}
