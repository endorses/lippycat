//go:build li

package x1

import (
	"encoding/xml"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/stretchr/testify/require"
)

func TestRADIUSTargetRoundTrip(t *testing.T) {
	cases := []struct {
		xml, value string
		kind       TargetType
	}{
		{`<targetIdentifier><nai>Alice@Example.test</nai></targetIdentifier>`, "Alice@Example.test", TargetTypeNAI},
		{`<targetIdentifier><nai>@example.test</nai></targetIdentifier>`, "@example.test", TargetTypeNAI},
		{`<targetIdentifier><macAddress>02:ab:00:00:00:01</macAddress></targetIdentifier>`, "02AB00000001", TargetTypeMACAddress},
		{`<targetIdentifier><radiusAttribute> 0104ff00 </radiusAttribute></targetIdentifier>`, "0104FF00", TargetTypeRADIUSAttribute},
		{`<targetIdentifier><radiusAttribute>57086c696e652d61</radiusAttribute></targetIdentifier>`, "57086C696E652D61", TargetTypeRADIUSAttribute},
		{`<targetIdentifier><radiusAttribute>1a1100000de9010b636972637569742d61</radiusAttribute></targetIdentifier>`, "1A1100000DE9010B636972637569742D61", TargetTypeRADIUSAttribute},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			var input schema.TargetIdentifier
			require.NoError(t, xml.Unmarshal([]byte(tc.xml), &input))
			target, err := parseTargetIdentifier(&input)
			require.NoError(t, err)
			require.Equal(t, tc.value, target.Value)
			require.Equal(t, tc.kind, target.Type)
			wire, err := xml.Marshal(targetIdentifierResponse(*target))
			require.NoError(t, err)
			var restored schema.TargetIdentifier
			require.NoError(t, xml.Unmarshal(wire, &restored))
			result, err := parseTargetIdentifier(&restored)
			require.NoError(t, err)
			require.Equal(t, target, result)
		})
	}
}

func TestRADIUSTargetRejectsInvalid(t *testing.T) {
	for _, value := range []string{"", "0102", "010441", "010341010342", "020341", "1A0900000001010341", "1A0B00000DE90103410202", "0x010341", "01 0341", "0103GG"} {
		_, err := ParseRADIUSTarget(&schema.TargetIdentifier{RadiusAttribute: &value})
		require.Error(t, err, value)
	}
	for _, value := range []schema.MACAddress{"02-00-00-00-00-01", "020000000001", "02:AB:00:00:00:01", "02:00:00:00:00:01:ssid"} {
		_, err := ParseRADIUSTarget(&schema.TargetIdentifier{MacAddress: &value})
		require.Error(t, err, value)
	}
	nai := schema.NAI("alice@example.test")
	sip := schema.SIPURI("sip:alice@example.test")
	_, err := ParseRADIUSTarget(&schema.TargetIdentifier{Nai: &nai, SipUri: &sip})
	require.Error(t, err)
}

func TestRADIUSCapabilitiesConjunction(t *testing.T) {
	nai := schema.NAI("alice@example.test")
	avp := "57086C696E652D61"
	sip := schema.SIPURI("sip:alice@example.test")
	details := &schema.TaskDetails{DeliveryType: "X2Only", TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{Nai: &nai}, {RadiusAttribute: &avp}}}}
	require.Nil(t, validateTaskCapabilities(details, false))
	for _, delivery := range []string{"X3Only", "X2andX3"} {
		details.DeliveryType = delivery
		require.NotNil(t, validateTaskCapabilities(details, false))
	}
	details.DeliveryType = "X2Only"
	details.TargetIdentifiers.TargetIdentifier = append(details.TargetIdentifiers.TargetIdentifier, &schema.TargetIdentifier{SipUri: &sip})
	require.NotNil(t, validateTaskCapabilities(details, false))
}

func TestRADIUSMediationDelivery(t *testing.T) {
	nai := schema.NAI("alice@example.test")
	for _, delivery := range []string{"HI2Only", "HI3Only", "HI2andHI3", "X2Only", "X3Only", "X2andX3"} {
		t.Run(delivery, func(t *testing.T) {
			details := &schema.TaskDetails{DeliveryType: "X2Only", TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{Nai: &nai}}}, ListOfMediationDetails: &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{DeliveryType: delivery}}}}
			err := validateTaskCapabilities(details, false)
			if delivery == "HI2Only" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
			}
			require.Equal(t, delivery != "HI2Only", ValidateRADIUSTaskDetails(details) != nil)
			// Omitting targets on modification retains the existing RADIUS family.
			manager := newMockTaskManager()
			xid := uuid.New()
			schemaXID := schema.UUID(xid.String())
			manager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: string(nai)}}, DeliveryType: DeliveryX2Only}
			server := NewServer(ServerConfig{}, nil, manager)
			details.XId = &schemaXID
			details.TargetIdentifiers = nil
			details.DeliveryType = ""
			response := server.handleModifyTask(&schema.ModifyTaskRequest{TaskDetails: details})
			_, rejected := response.(*schema.ErrorResponse)
			require.Equal(t, delivery != "HI2Only", rejected)
		})
	}
}

func TestRADIUSModificationRejectsChangedStartTime(t *testing.T) {
	start := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		name   string
		start  *schema.QualifiedMicrosecondDateTime
		reject bool
	}{
		{"end only", nil, false},
		{"same start", radiusTestTime(start), false},
		{"later start", radiusTestTime(start.Add(time.Hour)), true},
		{"earlier start", radiusTestTime(start.Add(-time.Hour)), true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			manager := newMockTaskManager()
			xid := uuid.New()
			schemaXID := schema.UUID(xid.String())
			manager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "alice@example.test"}}, StartTime: start, DeliveryType: DeliveryX2Only}
			server := NewServer(ServerConfig{}, nil, manager)
			details := &schema.TaskDetails{XId: &schemaXID, ListOfMediationDetails: &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{DeliveryType: "HI2Only", StartTime: testCase.start, EndTime: radiusTestTime(start.Add(24 * time.Hour))}}}}
			response := server.handleModifyTask(&schema.ModifyTaskRequest{TaskDetails: details})
			_, rejected := response.(*schema.ErrorResponse)
			require.Equal(t, testCase.reject, rejected)
			require.Equal(t, start, manager.tasks[xid].StartTime)
		})
	}
}

func radiusTestTime(value time.Time) *schema.QualifiedMicrosecondDateTime {
	result := schema.QualifiedMicrosecondDateTime(value.Format(time.RFC3339Nano))
	return &result
}
