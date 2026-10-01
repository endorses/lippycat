//go:build li

package x1

import (
	"encoding/xml"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRawActivationPreservesDefinitionPresenceAndReadback(t *testing.T) {
	mediation := func(window string) string {
		return "<listOfMediationDetails><mediationDetails><LIID>synthetic-window</LIID><deliveryType>HI2andHI3</deliveryType>" + window + "</mediationDetails></listOfMediationDetails>"
	}
	start := "<StartTime>2020-01-01T00:00:00.000000Z</StartTime>"
	for _, test := range []struct {
		name     string
		fields   string
		presence TaskDefinitionPresence
	}{
		{"omitted", "", TaskDefinitionPresence{}},
		{"implicit only", "<implicitDeactivationAllowed>false</implicitDeactivationAllowed>", TaskDefinitionPresence{Implicit: true}},
		{"unknown mediation window", mediation(""), TaskDefinitionPresence{Mediation: true}},
		{"explicit open end", mediation(start) + "<implicitDeactivationAllowed>false</implicitDeactivationAllowed>", TaskDefinitionPresence{Mediation: true, Start: true, End: true, Implicit: true}},
		{"explicit end", mediation(start+"<EndTime>2099-01-01T00:00:00.000000Z</EndTime>") + "<implicitDeactivationAllowed>true</implicitDeactivationAllowed>", TaskDefinitionPresence{Mediation: true, Start: true, End: true, EndProvided: true, Implicit: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			raw := fmt.Sprintf("<ActivateTaskRequest><taskDetails><xId>%s</xId><targetIdentifiers><targetIdentifier><e164Number>15551234567</e164Number></targetIdentifier></targetIdentifiers><deliveryType>X2andX3</deliveryType><listOfDIDs><dId>%s</dId></listOfDIDs>%s</taskDetails></ActivateTaskRequest>", xid, did, test.fields)
			var req schema.ActivateTaskRequest
			require.NoError(t, xml.Unmarshal([]byte(raw), &req))
			client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
			req.X1RequestMessage = client.buildRequestMessage()
			manager := newMockTaskManager()
			server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, manager)
			activation := server.handleActivateTask(&req)
			activationXML, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{activation}})
			require.NoError(t, err)
			require.NotContains(t, string(activationXML), `xsi:type="ErrorResponse"`)
			validateX1DocumentWithSchema(t, activationXML)
			task := manager.tasks[xid]
			require.NotNil(t, task)
			require.Equal(t, &test.presence, task.DefinitionPresence)
			id := schema.UUID(xid.String())
			response := server.handleGetTaskDetails(&schema.GetTaskDetailsRequest{XId: &id, X1RequestMessage: client.buildRequestMessage()})
			document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
			require.NoError(t, err)
			validateX1DocumentWithSchema(t, document)
			readback := response.(*schema.GetTaskDetailsResponse).TaskResponseDetails.TaskDetails
			presence, err := extractTaskDefinitionPresence(readback)
			require.NoError(t, err)
			require.Equal(t, task.DefinitionPresence, presence, "readback must not invent complete authorization fields")
		})
	}
}

func TestRawActivationRejectsInconsistentWindowPresence(t *testing.T) {
	start := schema.QualifiedMicrosecondDateTime("2020-01-01T00:00:00.000000Z")
	for _, list := range []*schema.ListOfMediationDetails{
		{},
		{MediationDetails: []*schema.MediationDetails{nil}},
		{MediationDetails: []*schema.MediationDetails{{StartTime: &start}, {}}},
	} {
		_, err := extractTaskDefinitionPresence(&schema.TaskDetails{ListOfMediationDetails: list})
		require.Error(t, err)
	}
}

func TestUnknownStartReadbackRetainsExplicitEnd(t *testing.T) {
	manager := newMockTaskManager()
	xid := uuid.New()
	end := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	manager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeE164, Value: "15551234567"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, Status: TaskStatusActive, EndTime: end, DefinitionPresence: &TaskDefinitionPresence{End: true, EndProvided: true}}
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, manager)
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	id := schema.UUID(xid.String())
	response := server.handleGetTaskDetails(&schema.GetTaskDetailsRequest{XId: &id, X1RequestMessage: client.buildRequestMessage()})
	document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
	require.NoError(t, err)
	validateX1DocumentWithSchema(t, document)
	require.Contains(t, string(document), "<EndTime>")
	require.NotContains(t, string(document), "<StartTime>")
	require.NotContains(t, string(document), "<implicitDeactivationAllowed>")
	p, err := extractTaskDefinitionPresence(response.(*schema.GetTaskDetailsResponse).TaskResponseDetails.TaskDetails)
	require.NoError(t, err)
	require.True(t, p.EndProvided)
	require.False(t, p.Start)
	require.False(t, p.Implicit)
}

func TestKnownStartUnknownEndReadbackCannotClaimOpenWindow(t *testing.T) {
	manager := newMockTaskManager()
	xid := uuid.New()
	manager.tasks[xid] = &Task{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeE164, Value: "15551234567"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, Status: TaskStatusActive, StartTime: time.Now().UTC().Add(-time.Hour), ImplicitDeactivationAllowed: true, DefinitionPresence: &TaskDefinitionPresence{Mediation: true, Start: true, Implicit: true}}
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, manager)
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	id := schema.UUID(xid.String())
	response := server.handleGetTaskDetails(&schema.GetTaskDetailsRequest{XId: &id, X1RequestMessage: client.buildRequestMessage()})
	document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
	require.NoError(t, err)
	validateX1DocumentWithSchema(t, document)
	require.NotContains(t, string(document), "<listOfMediationDetails>")
	p, err := extractTaskDefinitionPresence(response.(*schema.GetTaskDetailsResponse).TaskResponseDetails.TaskDetails)
	require.NoError(t, err)
	require.False(t, p.Mediation)
	require.False(t, p.End)
	require.True(t, p.Implicit)
}
