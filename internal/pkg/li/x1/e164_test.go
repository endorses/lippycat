//go:build li

package x1

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestE164WireValidation(t *testing.T) {
	for _, value := range []string{"1", "15551234567", "123456789012345", "", "+15551234567", "1234567890123456", "12 34", "１２３"} {
		t.Run(value, func(t *testing.T) {
			number := schema.InternationalE164(value)
			target := &schema.TargetIdentifier{E164Number: &number}
			parsed, err := parseTargetIdentifier(target)
			if schema.ValidE164Number(value) {
				require.NoError(t, err)
				require.Equal(t, TargetIdentity{Type: TargetTypeE164, Value: value}, *parsed)
				require.Nil(t, validateTargetChoice(target))
			} else {
				require.Error(t, err)
				capabilityErr := validateTargetChoice(target)
				require.NotNil(t, capabilityErr)
				require.Equal(t, ErrorCodeRequestSyntaxError, capabilityErr.code)
			}
		})
	}
}

func TestE164TaskReadbackBundledSchema(t *testing.T) {
	for _, test := range []struct {
		name   string
		target TargetIdentity
		xml    string
	}{
		{"E164", TargetIdentity{Type: TargetTypeE164, Value: "15551234567"}, "<e164Number>15551234567</e164Number>"},
		{"TEL URI", TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551234567"}, "<telUri>tel:+15551234567</telUri>"},
		{"legacy bare-digit TEL URI", TargetIdentity{Type: TargetTypeTELURI, Value: "15551234567"}, "<e164Number>15551234567</e164Number>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			taskManager := newMockTaskManager()
			xid := uuid.New()
			start := time.Now().UTC().Truncate(time.Microsecond)
			taskManager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{test.target}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, Status: TaskStatusActive, StartTime: start, EndTime: start.Add(time.Hour), ImplicitDeactivationAllowed: true}
			server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, taskManager)
			id := schema.UUID(xid.String())
			client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
			request := client.buildRequestMessage()
			response := server.handleGetTaskDetails(&schema.GetTaskDetailsRequest{XId: &id, X1RequestMessage: request})
			document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
			require.NoError(t, err)
			require.Contains(t, string(document), test.xml)
			validateX1DocumentWithSchema(t, document)
		})
	}
}

func TestE164ActivationSyntaxErrorBundledSchema(t *testing.T) {
	taskManager := newMockTaskManager()
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, taskManager)
	xid := schema.UUID(uuid.NewString())
	number := schema.InternationalE164("+15551234567")
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	request := client.buildRequestMessage()
	response := server.handleActivateTask(&schema.ActivateTaskRequest{X1RequestMessage: request, TaskDetails: &schema.TaskDetails{XId: &xid, TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{E164Number: &number}}}}})
	document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
	require.NoError(t, err)
	require.Contains(t, string(document), "<errorCode>101</errorCode>")
	require.Empty(t, taskManager.tasks)
	validateX1DocumentWithSchema(t, document)
}

func TestE164ReadbackRefusesInvalidStoredNumber(t *testing.T) {
	taskManager := newMockTaskManager()
	xid := uuid.New()
	taskManager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeE164, Value: "+15551234567"}}}
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, taskManager)
	id := schema.UUID(xid.String())
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	response := server.handleGetTaskDetails(&schema.GetTaskDetailsRequest{XId: &id, X1RequestMessage: client.buildRequestMessage()})
	document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
	require.NoError(t, err)
	require.NotContains(t, string(document), "<e164Number>")
	require.Contains(t, string(document), `xsi:type="ErrorResponse"`)
	validateX1DocumentWithSchema(t, document)
}
