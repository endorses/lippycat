//go:build li

package li

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func TestTaskResponseDetailsToInterceptTask_FullyPopulated(t *testing.T) {
	xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	did1Str := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	did2Str := schema.UUID("d2d2d2d2-0000-0000-0000-000000000002")
	implicitDeact := true

	sipURI := schema.SIPURI("sip:alice@example.com")
	telURI := schema.TELURI("tel:+15551234567")
	e164 := schema.InternationalE164("+15559876543")
	ipv4 := schema.IPv4Address("192.168.1.100")
	ipv6 := schema.IPv6Address("2001:db8::1")
	ipv4CIDR := "10.0.0.0/8"
	ipv6CIDR := schema.IPv6CIDR("2001:db8::/32")
	nai := schema.NAI("user@realm.example.com")

	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId: &xidStr,
			TargetIdentifiers: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{SipUri: &sipURI},
					{TelUri: &telURI},
					{E164Number: &e164},
					{Ipv4Address: &ipv4},
					{Ipv6Address: &ipv6},
					{Ipv4Cidr: &schema.IPCIDR{IPv4CIDR: &ipv4CIDR}},
					{Ipv6Cidr: &ipv6CIDR},
					{Nai: &nai},
				},
			},
			DeliveryType: "X2andX3",
			ListOfDIDs: &schema.ListOfDids{
				DId: []*schema.UUID{&did1Str, &did2Str},
			},
			ImplicitDeactivationAllowed: &implicitDeact,
		},
		TaskStatus: &schema.TaskStatus{
			ProvisioningStatus: "active",
		},
	}

	task, err := TaskResponseDetailsToInterceptTask(details)
	require.NoError(t, err)
	require.NotNil(t, task)

	// Verify XID.
	assert.Equal(t, uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890"), task.XID)

	// Verify targets.
	require.Len(t, task.Targets, 8)
	assert.Equal(t, TargetTypeSIPURI, task.Targets[0].Type)
	assert.Equal(t, "sip:alice@example.com", task.Targets[0].Value)

	assert.Equal(t, TargetTypeTELURI, task.Targets[1].Type)
	assert.Equal(t, "tel:+15551234567", task.Targets[1].Value)

	// E.164 maps to TEL URI type.
	assert.Equal(t, TargetTypeTELURI, task.Targets[2].Type)
	assert.Equal(t, "+15559876543", task.Targets[2].Value)

	assert.Equal(t, TargetTypeIPv4Address, task.Targets[3].Type)
	assert.Equal(t, "192.168.1.100", task.Targets[3].Value)

	assert.Equal(t, TargetTypeIPv6Address, task.Targets[4].Type)
	assert.Equal(t, "2001:db8::1", task.Targets[4].Value)

	assert.Equal(t, TargetTypeIPv4CIDR, task.Targets[5].Type)
	assert.Equal(t, "10.0.0.0/8", task.Targets[5].Value)

	assert.Equal(t, TargetTypeIPv6CIDR, task.Targets[6].Type)
	assert.Equal(t, "2001:db8::/32", task.Targets[6].Value)

	assert.Equal(t, TargetTypeNAI, task.Targets[7].Type)
	assert.Equal(t, "user@realm.example.com", task.Targets[7].Value)

	// Verify delivery type.
	assert.Equal(t, DeliveryX2andX3, task.DeliveryType)

	// Verify destination IDs.
	require.Len(t, task.DestinationIDs, 2)
	assert.Equal(t, uuid.MustParse("d1d1d1d1-0000-0000-0000-000000000001"), task.DestinationIDs[0])
	assert.Equal(t, uuid.MustParse("d2d2d2d2-0000-0000-0000-000000000002"), task.DestinationIDs[1])

	// Verify implicit deactivation.
	assert.True(t, task.ImplicitDeactivationAllowed)

	// Verify status.
	assert.Equal(t, TaskStatusActive, task.Status)
}

func TestTaskResponseDetailsToInterceptTask_MinimalFields(t *testing.T) {
	xidStr := schema.UUID("11111111-2222-3333-4444-555555555555")
	sipURI := schema.SIPURI("sip:bob@example.com")
	did1Str := schema.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId: &xidStr,
			TargetIdentifiers: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{SipUri: &sipURI},
				},
			},
			DeliveryType: "X2Only",
			ListOfDIDs: &schema.ListOfDids{
				DId: []*schema.UUID{&did1Str},
			},
		},
	}

	task, err := TaskResponseDetailsToInterceptTask(details)
	require.NoError(t, err)
	require.NotNil(t, task)

	assert.Equal(t, uuid.MustParse("11111111-2222-3333-4444-555555555555"), task.XID)
	assert.Len(t, task.Targets, 1)
	assert.Equal(t, DeliveryX2Only, task.DeliveryType)
	assert.False(t, task.ImplicitDeactivationAllowed)
	assert.Equal(t, TaskStatus(0), task.Status) // Default pending (zero value)
}

func TestTaskResponseDetailsToInterceptTask_NilDetails(t *testing.T) {
	_, err := TaskResponseDetailsToInterceptTask(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestTaskResponseDetailsToInterceptTask_NilTaskDetails(t *testing.T) {
	details := &schema.TaskResponseDetails{}
	_, err := TaskResponseDetailsToInterceptTask(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "task details is nil")
}

func TestTaskResponseDetailsToInterceptTask_NilXID(t *testing.T) {
	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			DeliveryType: "X2Only",
		},
	}
	_, err := TaskResponseDetailsToInterceptTask(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "XID is nil")
}

func TestTaskResponseDetailsToInterceptTask_InvalidXID(t *testing.T) {
	badXID := schema.UUID("not-a-uuid")
	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId:          &badXID,
			DeliveryType: "X2Only",
		},
	}
	_, err := TaskResponseDetailsToInterceptTask(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse XID")
}

func TestTaskResponseDetailsToInterceptTask_InvalidDeliveryType(t *testing.T) {
	xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId:          &xidStr,
			DeliveryType: "InvalidType",
		},
	}
	_, err := TaskResponseDetailsToInterceptTask(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported delivery type")
}

func TestTaskResponseDetailsToInterceptTask_DeliveryTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected DeliveryType
	}{
		{"X2Only", "X2Only", DeliveryX2Only},
		{"X3Only", "X3Only", DeliveryX3Only},
		{"X2andX3", "X2andX3", DeliveryX2andX3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
			details := &schema.TaskResponseDetails{
				TaskDetails: &schema.TaskDetails{
					XId:          &xidStr,
					DeliveryType: tt.input,
				},
			}
			task, err := TaskResponseDetailsToInterceptTask(details)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, task.DeliveryType)
		})
	}
}

func TestTaskResponseDetailsToInterceptTask_ProvisioningStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected TaskStatus
	}{
		{"active", "active", TaskStatusActive},
		{"pending", "pending", TaskStatusPending},
		{"suspended", "suspended", TaskStatusSuspended},
		{"deactivated", "deactivated", TaskStatusDeactivated},
		{"failed", "failed", TaskStatusFailed},
		{"unknown defaults to pending", "unknown", TaskStatusPending},
		{"empty defaults to pending", "", TaskStatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
			details := &schema.TaskResponseDetails{
				TaskDetails: &schema.TaskDetails{
					XId:          &xidStr,
					DeliveryType: "X2Only",
				},
				TaskStatus: &schema.TaskStatus{
					ProvisioningStatus: tt.status,
				},
			}
			task, err := TaskResponseDetailsToInterceptTask(details)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, task.Status)
		})
	}
}

func TestTaskResponseDetailsToInterceptTask_TargetIdentifierTypes(t *testing.T) {
	sipURI := schema.SIPURI("sip:alice@example.com")
	telURI := schema.TELURI("tel:+15551234567")
	e164 := schema.InternationalE164("+15559876543")
	ipv4 := schema.IPv4Address("192.168.1.100")
	ipv6 := schema.IPv6Address("2001:db8::1")
	ipv4CIDR := "10.0.0.0/8"
	ipv6CIDR := schema.IPv6CIDR("2001:db8::/32")
	nai := schema.NAI("user@realm.example.com")

	tests := []struct {
		name         string
		identifier   *schema.TargetIdentifier
		expectedType TargetType
		expectedVal  string
	}{
		{"SIP URI", &schema.TargetIdentifier{SipUri: &sipURI}, TargetTypeSIPURI, "sip:alice@example.com"},
		{"TEL URI", &schema.TargetIdentifier{TelUri: &telURI}, TargetTypeTELURI, "tel:+15551234567"},
		{"E164", &schema.TargetIdentifier{E164Number: &e164}, TargetTypeTELURI, "+15559876543"},
		{"IPv4", &schema.TargetIdentifier{Ipv4Address: &ipv4}, TargetTypeIPv4Address, "192.168.1.100"},
		{"IPv6", &schema.TargetIdentifier{Ipv6Address: &ipv6}, TargetTypeIPv6Address, "2001:db8::1"},
		{"IPv4 CIDR", &schema.TargetIdentifier{Ipv4Cidr: &schema.IPCIDR{IPv4CIDR: &ipv4CIDR}}, TargetTypeIPv4CIDR, "10.0.0.0/8"},
		{"IPv6 CIDR", &schema.TargetIdentifier{Ipv6Cidr: &ipv6CIDR}, TargetTypeIPv6CIDR, "2001:db8::/32"},
		{"NAI", &schema.TargetIdentifier{Nai: &nai}, TargetTypeNAI, "user@realm.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
			details := &schema.TaskResponseDetails{
				TaskDetails: &schema.TaskDetails{
					XId: &xidStr,
					TargetIdentifiers: &schema.ListOfTargetIdentifiers{
						TargetIdentifier: []*schema.TargetIdentifier{tt.identifier},
					},
					DeliveryType: "X2Only",
				},
			}
			task, err := TaskResponseDetailsToInterceptTask(details)
			require.NoError(t, err)
			require.Len(t, task.Targets, 1)
			assert.Equal(t, tt.expectedType, task.Targets[0].Type)
			assert.Equal(t, tt.expectedVal, task.Targets[0].Value)
		})
	}
}

func TestTaskResponseDetailsToInterceptTask_UnsupportedTargetType(t *testing.T) {
	xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	// An empty TargetIdentifier has no supported fields set.
	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId: &xidStr,
			TargetIdentifiers: &schema.ListOfTargetIdentifiers{
				TargetIdentifier: []*schema.TargetIdentifier{
					{}, // No fields set
				},
			},
			DeliveryType: "X2Only",
		},
	}
	_, err := TaskResponseDetailsToInterceptTask(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported target identifier type")
}

func TestTaskResponseDetailsToInterceptTask_NilTargetsAndDIDs(t *testing.T) {
	xidStr := schema.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	details := &schema.TaskResponseDetails{
		TaskDetails: &schema.TaskDetails{
			XId:          &xidStr,
			DeliveryType: "X2Only",
		},
	}
	task, err := TaskResponseDetailsToInterceptTask(details)
	require.NoError(t, err)
	assert.Nil(t, task.Targets)
	assert.Nil(t, task.DestinationIDs)
}

func TestDestinationResponseDetailsToDestination_FullyPopulated(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	friendlyName := "Test MDF Endpoint"
	ipv4Addr := "10.0.0.50"
	tcpPort := 9999

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			FriendlyName: &friendlyName,
			DeliveryType: "X2andX3",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{
						IPv4Address: &ipv4Addr,
					},
					Port: &schema.Port{
						TCPPort: &tcpPort,
					},
				},
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	require.NotNil(t, dest)

	assert.Equal(t, uuid.MustParse("d1d1d1d1-0000-0000-0000-000000000001"), dest.DID)
	assert.Equal(t, "10.0.0.50", dest.Address)
	assert.Equal(t, 9999, dest.Port)
	assert.True(t, dest.X2Enabled)
	assert.True(t, dest.X3Enabled)
	assert.Equal(t, "Test MDF Endpoint", dest.Description)
}

func TestDestinationResponseDetailsToDestination_X2Only(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	ipv4Addr := "10.0.0.50"
	tcpPort := 9999

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2Only",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{IPv4Address: &ipv4Addr},
					Port:    &schema.Port{TCPPort: &tcpPort},
				},
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	assert.True(t, dest.X2Enabled)
	assert.False(t, dest.X3Enabled)
}

func TestDestinationResponseDetailsToDestination_X3Only(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	ipv4Addr := "10.0.0.50"
	tcpPort := 9999

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X3Only",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{IPv4Address: &ipv4Addr},
					Port:    &schema.Port{TCPPort: &tcpPort},
				},
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	assert.False(t, dest.X2Enabled)
	assert.True(t, dest.X3Enabled)
}

func TestDestinationResponseDetailsToDestination_IPv6(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	ipv6Addr := "2001:db8::1"
	tcpPort := 8443

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2andX3",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{IPv6Address: &ipv6Addr},
					Port:    &schema.Port{TCPPort: &tcpPort},
				},
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", dest.Address)
	assert.Equal(t, 8443, dest.Port)
}

func TestDestinationResponseDetailsToDestination_URIAddress(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	uri := "https://mdf.example.com/delivery"

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2andX3",
			DeliveryAddress: &schema.DeliveryAddress{
				Uri: &uri,
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	assert.Equal(t, "https://mdf.example.com/delivery", dest.Address)
	assert.Equal(t, 443, dest.Port)
}

func TestDestinationResponseDetailsToDestination_NilDetails(t *testing.T) {
	_, err := DestinationResponseDetailsToDestination(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestDestinationResponseDetailsToDestination_NilDestinationDetails(t *testing.T) {
	details := &schema.DestinationResponseDetails{}
	_, err := DestinationResponseDetailsToDestination(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination details is nil")
}

func TestDestinationResponseDetailsToDestination_NilDID(t *testing.T) {
	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DeliveryType: "X2Only",
		},
	}
	_, err := DestinationResponseDetailsToDestination(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DID is nil")
}

func TestDestinationResponseDetailsToDestination_InvalidDID(t *testing.T) {
	badDID := schema.UUID("not-a-uuid")
	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &badDID,
			DeliveryType: "X2Only",
		},
	}
	_, err := DestinationResponseDetailsToDestination(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse DID")
}

func TestDestinationResponseDetailsToDestination_MissingDeliveryAddress(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2Only",
		},
	}
	_, err := DestinationResponseDetailsToDestination(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delivery address")
}

func TestDestinationResponseDetailsToDestination_MissingPort(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	ipv4Addr := "10.0.0.50"

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2Only",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{IPv4Address: &ipv4Addr},
					// No port
				},
			},
		},
	}
	_, err := DestinationResponseDetailsToDestination(details)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing port")
}

func TestDestinationResponseDetailsToDestination_NoFriendlyName(t *testing.T) {
	didStr := schema.UUID("d1d1d1d1-0000-0000-0000-000000000001")
	ipv4Addr := "10.0.0.50"
	tcpPort := 9999

	details := &schema.DestinationResponseDetails{
		DestinationDetails: &schema.DestinationDetails{
			DId:          &didStr,
			DeliveryType: "X2Only",
			DeliveryAddress: &schema.DeliveryAddress{
				IpAddressAndPort: &schema.IPAddressPort{
					Address: &schema.IPAddress{IPv4Address: &ipv4Addr},
					Port:    &schema.Port{TCPPort: &tcpPort},
				},
			},
		},
	}

	dest, err := DestinationResponseDetailsToDestination(details)
	require.NoError(t, err)
	assert.Equal(t, "", dest.Description)
}
