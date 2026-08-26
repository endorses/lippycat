//go:build li

package x1

import (
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
