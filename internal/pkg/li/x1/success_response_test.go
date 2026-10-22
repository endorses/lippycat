//go:build li

package x1

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestServerCompletedResponsesConformToBundledXSD(t *testing.T) {
	destinations := newMockDestinationManager()
	tasks := newMockTaskManager()
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, destinations, tasks)
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	did := schema.UUID("12345678-1234-1234-1234-123456789abc")
	xid := schema.UUID("abcdefab-1234-1234-1234-abcdefabcdef")
	destinationID := uuid.MustParse(string(did))
	taskID := uuid.MustParse(string(xid))
	address, port := "192.0.2.10", 5443
	name := "synthetic destination"
	sipURI := schema.SIPURI("sip:alice@example.com")
	destinationDetails := &schema.DestinationDetails{
		DId: &did, DeliveryType: "X2andX3",
		DeliveryAddress: &schema.DeliveryAddress{IpAddressAndPort: &schema.IPAddressPort{
			Address: &schema.IPAddress{IPv4Address: &address}, Port: &schema.Port{TCPPort: &port},
		}},
	}

	// Run the real request dispatch and HTTP response container through a
	// complete synchronous lifecycle, with managers recording each operation.
	tests := []struct {
		requestType string
		request     any
		completed   func()
	}{
		{
			requestType: MessageTypePing,
			request:     &schema.PingRequest{X1RequestMessage: client.buildRequestMessage()},
		},
		{
			requestType: MessageTypeCreateDestination,
			request:     &schema.CreateDestinationRequest{DestinationDetails: destinationDetails, X1RequestMessage: client.buildRequestMessage()},
			completed: func() {
				require.Contains(t, destinations.destinations, destinationID)
			},
		},
		{
			requestType: MessageTypeModifyDestination,
			request: &schema.ModifyDestinationRequest{
				DestinationDetails: &schema.DestinationDetails{DId: &did, FriendlyName: &name}, X1RequestMessage: client.buildRequestMessage(),
			},
			completed: func() {
				require.Equal(t, name, destinations.destinations[destinationID].Description)
			},
		},
		{
			requestType: MessageTypeActivateTask,
			request: &schema.ActivateTaskRequest{
				TaskDetails: &schema.TaskDetails{
					XId: &xid, DeliveryType: "X2andX3",
					TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{SipUri: &sipURI}}},
					ListOfDIDs:        &schema.ListOfDids{DId: []*schema.UUID{&did}},
				},
				X1RequestMessage: client.buildRequestMessage(),
			},
			completed: func() {
				require.Equal(t, TaskStatusActive, tasks.tasks[taskID].Status)
			},
		},
		{
			requestType: MessageTypeModifyTask,
			request: &schema.ModifyTaskRequest{
				TaskDetails: &schema.TaskDetails{XId: &xid, DeliveryType: "X2Only"}, X1RequestMessage: client.buildRequestMessage(),
			},
			completed: func() {
				require.Equal(t, DeliveryX2Only, tasks.tasks[taskID].DeliveryType)
			},
		},
		{
			requestType: MessageTypeDeactivateTask,
			request:     &schema.DeactivateTaskRequest{XId: &xid, X1RequestMessage: client.buildRequestMessage()},
			completed: func() {
				require.Equal(t, TaskStatusDeactivated, tasks.tasks[taskID].Status)
			},
		},
		{
			requestType: MessageTypeRemoveDestination,
			request:     &schema.RemoveDestinationRequest{DId: &did, X1RequestMessage: client.buildRequestMessage()},
			completed: func() {
				require.NotContains(t, destinations.destinations, destinationID)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.requestType, func(t *testing.T) {
			request, err := marshalWrappedRequest(test.requestType, test.request)
			require.NoError(t, err)
			recorder := httptest.NewRecorder()
			server.handleX1Request(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(request)))
			require.Equal(t, http.StatusOK, recorder.Code)
			require.Contains(t, recorder.Header().Get("Content-Type"), "application/xml")
			response := recorder.Body.Bytes()
			requireCompletedResponse(t, response, strings.TrimSuffix(test.requestType, "Request")+"Response")
			validateX1DocumentWithSchema(t, response)
			require.NoError(t, validateReportAcknowledgment(request, response, test.requestType))
			if test.completed != nil {
				test.completed()
			}

			// A base response may pass schema validation but cannot establish
			// success; neither absent type nor absent/duplicate oK is accepted.
			responseType := strings.TrimSuffix(test.requestType, "Request") + "Response"
			for _, malformed := range []struct {
				name string
				from string
				to   string
			}{
				{"missing type", ` xsi:type="` + responseType + `"`, ""},
				{"missing OK", "<oK>AcknowledgedAndCompleted</oK>", ""},
				{"duplicate OK", "<oK>AcknowledgedAndCompleted</oK>", "<oK>AcknowledgedAndCompleted</oK><oK>AcknowledgedAndCompleted</oK>"},
			} {
				t.Run(malformed.name, func(t *testing.T) {
					require.Contains(t, string(response), malformed.from)
					document := bytes.Replace(response, []byte(malformed.from), []byte(malformed.to), 1)
					require.Error(t, validateReportAcknowledgment(request, document, test.requestType))
				})
			}
		})
	}
}

func requireCompletedResponse(t *testing.T, document []byte, responseType string) {
	t.Helper()
	var envelope struct {
		XMLName  xml.Name
		Attrs    []xml.Attr `xml:",any,attr"`
		Messages []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
			Type    string     `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			OK      []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:"oK"`
		} `xml:"x1ResponseMessage"`
	}
	require.NoError(t, xml.Unmarshal(document, &envelope))
	require.Equal(t, xml.Name{Space: etsiX1Namespace, Local: "X1Response"}, envelope.XMLName)
	require.Len(t, envelope.Messages, 1)
	message := envelope.Messages[0]
	require.Equal(t, xml.Name{Space: etsiX1Namespace, Local: "x1ResponseMessage"}, message.XMLName)
	prefix, local := "", message.Type
	if parts := strings.SplitN(message.Type, ":", 2); len(parts) == 2 {
		prefix, local = parts[0], parts[1]
	}
	require.Equal(t, responseType, local)
	namespace := ""
	for _, attrs := range [][]xml.Attr{envelope.Attrs, message.Attrs} {
		for _, attr := range attrs {
			if (prefix == "" && attr.Name == (xml.Name{Local: "xmlns"})) ||
				(prefix != "" && attr.Name == (xml.Name{Space: "xmlns", Local: prefix})) {
				namespace = attr.Value
			}
		}
	}
	require.Equal(t, etsiX1Namespace, namespace, "xsi:type must resolve in the X1 namespace")
	require.Len(t, message.OK, 1)
	require.Equal(t, xml.Name{Space: etsiX1Namespace, Local: "oK"}, message.OK[0].XMLName)
	require.Equal(t, "AcknowledgedAndCompleted", message.OK[0].Value)
}

func TestBuildOKResponseRejectsUnmappedOperation(t *testing.T) {
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, nil)
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	for _, requestType := range []string{MessageTypeGetTaskDetails, "UnknownOperationRequest"} {
		t.Run(requestType, func(t *testing.T) {
			base := client.buildRequestMessage()
			response, ok := server.buildOKResponse(base, requestType).(*schema.ErrorResponse)
			require.True(t, ok, "unmapped success must return a concrete protocol error")
			require.Equal(t, ErrorCodeGenericError, response.ErrorInformation.ErrorCode)
			require.Equal(t, base.X1TransactionId, response.X1TransactionId)
			document, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{response}})
			require.NoError(t, err)
			require.Contains(t, string(document), `xsi:type="ErrorResponse"`)
			require.NotContains(t, string(document), "<oK>")
			validateX1DocumentWithSchema(t, document)
		})
	}
}

func TestCompletedResponseFixPreservesProtocolErrors(t *testing.T) {
	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, newMockDestinationManager(), nil)
	client := &Client{config: ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, admfIdentifier: "test-admf"}
	did := schema.UUID("12345678-1234-1234-1234-123456789abc")
	request, err := marshalWrappedRequest(MessageTypeRemoveDestination, &schema.RemoveDestinationRequest{DId: &did, X1RequestMessage: client.buildRequestMessage()})
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	server.handleX1Request(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(request)))
	require.Equal(t, http.StatusOK, recorder.Code)
	response := recorder.Body.Bytes()
	validateX1DocumentWithSchema(t, response)
	require.Contains(t, string(response), `xsi:type="ErrorResponse"`)
	require.NotContains(t, string(response), "<oK>")
	var protocolError *ADMFError
	require.ErrorAs(t, validateReportAcknowledgment(request, response, MessageTypeRemoveDestination), &protocolError)
	require.Equal(t, ErrorCodeDIDNotFound, protocolError.ErrorCode)
}
