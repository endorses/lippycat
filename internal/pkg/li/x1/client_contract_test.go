//go:build li

package x1

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Realistic ADMF response fixture: every response echoes the transaction and
// addressing metadata from the actual request and uses a typed X1 envelope.
func reportAcknowledgment(t *testing.T, body []byte, payload string) []byte {
	t.Helper()
	var request struct {
		Message struct {
			Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			schema.X1RequestMessage
		} `xml:"x1RequestMessage"`
	}
	require.NoError(t, xml.Unmarshal(body, &request))
	base, err := xml.Marshal(request.Message.X1RequestMessage)
	require.NoError(t, err)
	fields := string(base)
	fields = fields[strings.IndexByte(fields, '>')+1 : strings.LastIndex(fields, "</")]
	responseType := strings.TrimSuffix(request.Message.Type, "Request") + "Response"
	if payload == "" {
		payload = "<oK>AcknowledgedAndCompleted</oK>"
	}
	if strings.Contains(payload, "<errorInformation>") {
		responseType = "ErrorResponse"
	}
	return []byte(fmt.Sprintf(`<X1Response xmlns="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><x1ResponseMessage xsi:type="%s">%s%s</x1ResponseMessage></X1Response>`, etsiX1Namespace, responseType, fields, payload))
}

// Existing behavior tests specify HTTP outcomes; successful report fixtures now
// return actual acknowledgments instead of treating an empty HTTP 200 as one.
func newReportingTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		for name, values := range recorder.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(recorder.Code)
		response := recorder.Body.Bytes()
		if recorder.Code == http.StatusOK && len(response) == 0 {
			response = reportAcknowledgment(t, body, "")
		}
		_, err = w.Write(response)
		require.NoError(t, err)
	}))
}

func TestOutboundHelpersConformToBundledXSD(t *testing.T) {
	id := uuid.New()
	code := 1
	tests := []struct {
		name, reportType string
		call             func(*Client) error
	}{
		{"keepalive", "", func(c *Client) error { return c.SendKeepalive(context.Background()) }},
		{"task-warning", "Warning", func(c *Client) error { return c.ReportTaskWarning(context.Background(), id, "Definition conflict") }},
		{"task-error", "NonTerminatingFault", func(c *Client) error { return c.ReportTaskError(context.Background(), id, code, "Delivery fault") }},
		{"task-terminating-fault", "TerminatingFault", func(c *Client) error {
			return c.ReportTaskTerminatingFault(context.Background(), id, code, "Task terminated")
		}},
		{"task-completed-success", "FullyActionedAndSuccessful", func(c *Client) error { return c.ReportTaskCompletion(context.Background(), id, true, "Completed") }},
		{"task-completed-failure", "FullyActionedAndUnsuccessful", func(c *Client) error { return c.ReportTaskCompletion(context.Background(), id, false, "Failed") }},
		{"task-progress", "AllClear", func(c *Client) error { return c.ReportTaskProgress(context.Background(), id, "Progress") }},
		{"task-expiry", "ImplicitDeactivation", func(c *Client) error { return c.ReportTaskImplicitDeactivation(context.Background(), id, "Expired") }},
		{"destination-generic", "Warning", func(c *Client) error {
			return c.ReportDestinationIssue(context.Background(), id, "Warning", &code, "Warning")
		}},
		{"delivery-error", "NonTerminatingFault", func(c *Client) error { return c.ReportDeliveryError(context.Background(), id, code, "Delivery fault") }},
		{"delivery-recovered", "AllClear", func(c *Client) error { return c.ReportDeliveryRecovered(context.Background(), id) }},
		{"connection-lost", "NonTerminatingFault", func(c *Client) error { return c.ReportConnectionLost(context.Background(), id, "Connection lost") }},
		{"connection-established", "AllClear", func(c *Client) error { return c.ReportConnectionEstablished(context.Background(), id) }},
		{"ne-generic", "Alert", func(c *Client) error { return c.ReportNEIssue(context.Background(), "Alert", "Alert", &code) }},
		{"ne-startup", "Alert", func(c *Client) error { return c.ReportStartup(context.Background()) }},
		{"ne-shutdown", "Alert", func(c *Client) error { return c.ReportShutdown(context.Background()) }},
		{"ne-warning", "Warning", func(c *Client) error { return c.ReportWarning(context.Background(), code, "Warning") }},
		{"ne-error", "FaultReport", func(c *Client) error { return c.ReportError(context.Background(), code, "Fault") }},
		{"ne-recovered", "FaultCleared", func(c *Client) error { return c.ReportFaultCleared(context.Background(), "Recovered") }},
		{"all-details", "", func(c *Client) error { _, err := c.GetAllDetails(context.Background()); return err }},
		{"all-task-details", "", func(c *Client) error { _, err := c.GetAllTaskDetails(context.Background()); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{ADMFEndpoint: "https://admf.example.test", ADMFIdentifier: "admf", NEIdentifier: "ne", InitialBackoff: time.Millisecond, MaxRetries: 1})
			require.NoError(t, err)
			var attempts [][]byte
			client.httpClient.Transport = startupTransportFunc(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				validateX1DocumentWithSchema(t, body)
				if tt.reportType != "" {
					require.Contains(t, string(body), ">"+tt.reportType+"<")
				}
				attempts = append(attempts, body)
				if len(attempts) == 1 {
					return startupResponse(http.StatusServiceUnavailable), nil
				}
				payload := ""
				if tt.name == "all-details" {
					payload = `<neStatusDetails><neStatus>OK</neStatus><listOfFaults/></neStatusDetails><listOfTaskResponseDetails/><listOfDestinationResponseDetails/>`
				}
				if tt.name == "all-task-details" {
					payload = `<listOfTaskResponseDetails/>`
				}
				response := reportAcknowledgment(t, body, payload)
				validateX1DocumentWithSchema(t, response)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: make(http.Header)}, nil
			})
			require.NoError(t, tt.call(client))
			require.Len(t, attempts, 2)
			var first, second struct {
				Message schema.X1RequestMessage `xml:"x1RequestMessage"`
			}
			require.NoError(t, xml.Unmarshal(attempts[0], &first))
			require.NoError(t, xml.Unmarshal(attempts[1], &second))
			require.NotEqual(t, *first.Message.X1TransactionId, *second.Message.X1TransactionId)
			require.NotEqual(t, *first.Message.MessageTimestamp, *second.Message.MessageTimestamp)
		})
	}
}

func TestReportAcknowledgmentRequired(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"empty", func([]byte) []byte { return nil }},
		{"malformed", func([]byte) []byte { return []byte("<broken>") }},
		{"untyped", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(`xsi:type="ReportTaskIssueResponse"`), nil) }},
		{"wrong-type", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte(`ReportTaskIssueResponse`), []byte(`KeepaliveResponse`))
		}},
		{"wrong-namespace", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(etsiX1Namespace), []byte("urn:wrong")) }},
		{"wrong-type-namespace", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte(`xsi:type="ReportTaskIssueResponse"`), []byte(`xmlns:other="urn:wrong" xsi:type="other:ReportTaskIssueResponse"`))
		}},
		{"wrong-id", func(b []byte) []byte {
			start := bytes.Index(b, []byte("<x1TransactionId>")) + len("<x1TransactionId>")
			end := bytes.Index(b, []byte("</x1TransactionId>"))
			return append(append(append([]byte{}, b[:start]...), []byte(uuid.NewString())...), b[end:]...)
		}},
		{"wrong-ne", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("<neIdentifier>ne</neIdentifier>"), []byte("<neIdentifier>wrong</neIdentifier>"))
		}},
		{"missing-timestamp", func(b []byte) []byte {
			start := bytes.Index(b, []byte("<messageTimestamp>"))
			end := bytes.Index(b, []byte("</messageTimestamp>")) + len("</messageTimestamp>")
			return append(append([]byte{}, b[:start]...), b[end:]...)
		}},
		{"duplicate-metadata", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("<neIdentifier>ne</neIdentifier>"), []byte("<neIdentifier>wrong</neIdentifier><neIdentifier>ne</neIdentifier>"))
		}},
		{"wrong-field-namespace", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("<oK>"), []byte(`<oK xmlns="urn:wrong">`)) }},
		{"trailing-root", func(b []byte) []byte { return append(b, []byte("<another/>")...) }},
		{"wrong-admf", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("<admfIdentifier>admf</admfIdentifier>"), []byte("<admfIdentifier>wrong</admfIdentifier>"))
		}},
		{"wrong-version", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte(DefaultProtocolVersion), []byte("v1.0.0")) }},
		{"invalid-ok", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("AcknowledgedAndCompleted"), []byte("OK")) }},
		{"missing-ok", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("<oK>AcknowledgedAndCompleted</oK>"), nil) }},
		{"multiple-messages", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("</X1Response>"), []byte("<x1ResponseMessage/></X1Response>"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{ADMFEndpoint: "https://admf.example.test", ADMFIdentifier: "admf", NEIdentifier: "ne", MaxRetries: 3})
			require.NoError(t, err)
			attempts := 0
			client.httpClient.Transport = startupTransportFunc(func(r *http.Request) (*http.Response, error) {
				attempts++
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(tt.mutate(reportAcknowledgment(t, body, "")))), Header: make(http.Header)}, nil
			})
			require.ErrorIs(t, client.ReportTaskWarning(context.Background(), uuid.New(), "Conflict"), ErrInvalidAcknowledgment)
			require.Equal(t, 1, attempts)
			require.Zero(t, client.Stats().TaskReportsSent)
			require.Equal(t, uint64(1), client.Stats().TaskReportsFailed)
		})
	}
	t.Run("schema-valid-rejection", func(t *testing.T) {
		client, err := NewClient(ClientConfig{ADMFEndpoint: "https://admf.example.test", MaxRetries: 3})
		require.NoError(t, err)
		attempts := 0
		client.httpClient.Transport = startupTransportFunc(func(r *http.Request) (*http.Response, error) {
			attempts++
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			response := reportAcknowledgment(t, body, `<requestMessageType>ReportTaskIssue</requestMessageType><errorInformation><errorCode>1000</errorCode><errorDescription>Rejected</errorDescription></errorInformation>`)
			validateX1DocumentWithSchema(t, response)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: make(http.Header)}, nil
		})
		require.ErrorIs(t, client.ReportTaskWarning(context.Background(), uuid.New(), "Conflict"), ErrADMFError)
		require.Equal(t, 1, attempts)
		require.Zero(t, client.Stats().TaskReportsSent)
	})
}
