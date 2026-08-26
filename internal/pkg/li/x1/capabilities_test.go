//go:build li

package x1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func TestCapabilityMatrix_TargetIdentifiers(t *testing.T) {
	sip := schema.SIPURI("sip:alice@example.net")
	ipv4 := schema.IPv4Address("192.0.2.10")
	imsi := schema.IMSI("001010123456789")
	email := schema.EmailAddress("alice@example.net")
	tests := []struct {
		name     string
		target   *schema.TargetIdentifier
		wantCode int
	}{
		{"sip supported", &schema.TargetIdentifier{SipUri: &sip}, 0},
		{"IPv4 rejected until raw-IP sessions are implemented", &schema.TargetIdentifier{Ipv4Address: &ipv4}, ErrorCodeTargetNotSupported},
		{"IMSI rejected", &schema.TargetIdentifier{Imsi: &imsi}, ErrorCodeTargetNotSupported},
		{"email rejected", &schema.TargetIdentifier{EmailAddress: &email}, ErrorCodeTargetNotSupported},
		{"empty choice invalid", &schema.TargetIdentifier{}, ErrorCodeRequestSyntaxError},
		{"multiple choices invalid", &schema.TargetIdentifier{SipUri: &sip, Ipv4Address: &ipv4}, ErrorCodeRequestSyntaxError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetChoice(tt.target)
			if tt.wantCode == 0 {
				require.Nil(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantCode, err.code)
		})
	}
}

func TestCapabilityMatrix_CoversEveryAcceptedSchemaElement(t *testing.T) {
	// Every generated request field must be deliberately classified here. The
	// equality checks make schema regeneration fail this test until new fields
	// receive a supported, rejected, or response-only decision.
	task := map[string]string{
		"XId": "supported", "TargetIdentifiers": "supported", "DeliveryType": "supported",
		"ListOfDIDs": "supported", "ListOfMediationDetails": "supported-partially",
		"CorrelationID": "rejected", "ImplicitDeactivationAllowed": "supported",
		"ProductID": "rejected", "ListOfServiceTypes": "rejected",
		"TaskDetailsExtensions": "rejected", "ListOfTrafficPolicyReferences": "rejected",
	}
	destination := map[string]string{
		"DId": "supported", "FriendlyName": "supported", "DeliveryType": "supported",
		"DeliveryAddress": "supported-partially", "DestinationDetailsExtensions": "rejected",
	}
	mediation := map[string]string{
		"LIID": "rejected", "DeliveryType": "rejected", "StartTime": "supported",
		"EndTime": "supported", "ListOfDIDs": "rejected", "MediationDetailsExtensions": "rejected",
		"ServiceScopingOptions": "rejected", "ListOfTrafficPolicyReferences": "rejected",
	}
	assertStructMatrixComplete(t, reflect.TypeOf(schema.TaskDetails{}), task)
	assertStructMatrixComplete(t, reflect.TypeOf(schema.DestinationDetails{}), destination)
	assertStructMatrixComplete(t, reflect.TypeOf(schema.MediationDetails{}), mediation)

	targets := map[string]string{
		"E164Number": "supported", "SipUri": "supported", "TelUri": "supported", "Nai": "supported",
		"Imsi": "rejected", "Imei": "rejected", "MacAddress": "rejected",
		"Ipv4Address": "rejected", "Ipv6Address": "rejected", "Ipv4Cidr": "rejected", "Ipv6Cidr": "rejected",
		"TcpPort": "rejected", "TcpPortRange": "rejected", "TcpPortList": "rejected",
		"UdpPort": "rejected", "UdpPortRange": "rejected", "UdpPortList": "rejected",
		"EmailAddress": "rejected", "InternationalizedEmailAddress": "rejected",
		"H323Uri": "rejected", "Impu": "rejected", "Impi": "rejected", "RadiusAttribute": "rejected",
		"GtpuTunnelId": "rejected", "GtpcTunnelId": "rejected", "CallPartyRole": "rejected",
		"NonLocalIdentifier": "rejected", "Supiimsi": "rejected", "Supinai": "rejected", "Suci": "rejected",
		"PeiImei": "rejected", "PeiImeiCheckDigit": "rejected", "PeiImeisv": "rejected",
		"GpsiMsisdn": "rejected", "GpsiNai": "rejected", "Eui64": "rejected",
		"ServiceAccessIdentifier": "rejected", "HashedIdentifier": "rejected",
		"TargetIdentifierExtension": "rejected", "Vrf": "rejected",
	}
	targetType := reflect.TypeOf(schema.TargetIdentifier{})
	assertStructMatrixComplete(t, targetType, targets)
}

func assertStructMatrixComplete(t *testing.T, typ reflect.Type, matrix map[string]string) {
	t.Helper()
	assert.Equal(t, typ.NumField(), len(matrix), "%s capability matrix is stale", typ.Name())
	for i := 0; i < typ.NumField(); i++ {
		classification, ok := matrix[typ.Field(i).Name]
		assert.True(t, ok, "%s.%s is unclassified", typ.Name(), typ.Field(i).Name)
		assert.Contains(t, []string{"supported", "supported-partially", "rejected", "response-only"}, classification)
	}
}

func TestCapabilityValidation_RejectsUnsupportedTaskSemantics(t *testing.T) {
	sip := schema.SIPURI("sip:alice@example.net")
	policy := schema.UUID("4d9980dd-3b74-444d-a8fb-f3ee63fb9d5c")
	var policyRef schema.GenericObjectID = &policy
	details := &schema.TaskDetails{
		TargetIdentifiers:             &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{SipUri: &sip}}},
		ListOfTrafficPolicyReferences: &schema.ListOfTrafficPolicyReferences{TrafficPolicyReference: []*schema.GenericObjectID{&policyRef}},
	}
	err := validateTaskCapabilities(details, false)
	require.Error(t, err)
	assert.Equal(t, ErrorCodeTargetNotSupported, err.code)
	assert.Contains(t, err.Error(), "traffic policy")
}

func TestCapabilityValidation_RejectsMediationLevelOverrides(t *testing.T) {
	liid := schema.LIID("LIID-1")
	did := schema.UUID("4d9980dd-3b74-444d-a8fb-f3ee63fb9d5c")
	tests := []struct {
		name      string
		mediation *schema.MediationDetails
		contains  string
	}{
		{"LIID", &schema.MediationDetails{LIID: &liid}, "LIID"},
		{"delivery type", &schema.MediationDetails{DeliveryType: "X2Only"}, "delivery type"},
		{"destination IDs", &schema.MediationDetails{ListOfDIDs: &schema.ListOfDids{DId: []*schema.UUID{&did}}}, "destination IDs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTaskCapabilities(&schema.TaskDetails{ListOfMediationDetails: &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{tt.mediation}}}, false)
			require.Error(t, err)
			assert.Equal(t, ErrorCodeTargetNotSupported, err.code)
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func TestCapabilityValidation_DestinationChoices(t *testing.T) {
	address := "192.0.2.20"
	tcp := 9443
	uri := "https://mdf.example.net"
	valid := &schema.DestinationDetails{DeliveryType: "X2andX3", DeliveryAddress: &schema.DeliveryAddress{
		IpAddressAndPort: &schema.IPAddressPort{Address: &schema.IPAddress{IPv4Address: &address}, Port: &schema.Port{TCPPort: &tcp}},
	}}
	require.Nil(t, validateDestinationCapabilities(valid, false))

	invalidType := *valid
	invalidType.DeliveryType = "HI2"
	err := validateDestinationCapabilities(&invalidType, false)
	require.Error(t, err)
	assert.Equal(t, ErrorCodeDeliveryTypeNotSupport, err.code)

	conflicting := *valid
	copyAddress := *valid.DeliveryAddress
	conflicting.DeliveryAddress = &copyAddress
	conflicting.DeliveryAddress.Uri = &uri
	err = validateDestinationCapabilities(&conflicting, false)
	require.Error(t, err)
	assert.Equal(t, ErrorCodeRequestSyntaxError, err.code)

	unsupported := &schema.DestinationDetails{DeliveryType: "X2Only", DeliveryAddress: &schema.DeliveryAddress{Uri: &uri}}
	err = validateDestinationCapabilities(unsupported, false)
	require.Error(t, err)
	assert.Equal(t, ErrorCodeDeliveryNotPossible, err.code)
}
