//go:build li

package x1

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func TestFormatQualifiedMicrosecondDateTime(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{
			name: "UTC with nanoseconds",
			in:   time.Date(2026, time.August, 26, 12, 34, 56, 123456789, time.UTC),
			want: "2026-08-26T12:34:56.123456Z",
		},
		{
			name: "whole second UTC",
			in:   time.Date(2026, time.August, 26, 12, 34, 56, 0, time.UTC),
			want: "2026-08-26T12:34:56.000000Z",
		},
		{
			name: "trailing zeroes retained",
			in:   time.Date(2026, time.August, 26, 12, 34, 56, 123000000, time.UTC),
			want: "2026-08-26T12:34:56.123000Z",
		},
		{
			name: "positive offset",
			in:   time.Date(2026, time.August, 26, 12, 34, 56, 1000, time.FixedZone("east", 5*60*60+30*60)),
			want: "2026-08-26T12:34:56.000001+05:30",
		},
		{
			name: "negative offset",
			in:   time.Date(2026, time.August, 26, 12, 34, 56, 999999999, time.FixedZone("west", -(7*60*60+45*60))),
			want: "2026-08-26T12:34:56.999999-07:45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(formatQualifiedMicrosecondDateTime(tt.in))
			assert.Equal(t, tt.want, got)
			validateQualifiedTimestampWithSchema(t, got)

			parsed, err := time.Parse(qualifiedMicrosecondLayout, got)
			require.NoError(t, err)
			assert.True(t, parsed.Equal(tt.in.Truncate(time.Microsecond)))
		})
	}
}

func TestQualifiedMicrosecondWireMessagesValidate(t *testing.T) {
	client := &Client{
		config:         ClientConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion},
		admfIdentifier: "test-admf",
	}
	id := schema.UUID("12345678-1234-1234-1234-123456789abc")
	details := "test details"
	requests := []struct {
		name        string
		messageType string
		message     any
	}{
		{"keepalive", "KeepaliveRequest", &schema.KeepaliveRequest{X1RequestMessage: client.buildRequestMessage()}},
		{"task report", "ReportTaskIssueRequest", &schema.ReportTaskIssueRequest{XId: &id, TaskReportType: "Warning", TaskIssueDetails: &details, X1RequestMessage: client.buildRequestMessage()}},
		{"destination report", "ReportDestinationIssueRequest", &schema.ReportDestinationIssueRequest{DId: &id, DestinationReportType: "Warning", DestinationIssueDetails: &details, X1RequestMessage: client.buildRequestMessage()}},
		{"NE report", "ReportNEIssueRequest", &schema.ReportNEIssueRequest{TypeOfNeIssueMessage: "Warning", Description: details, X1RequestMessage: client.buildRequestMessage()}},
		{"all details query", "GetAllDetailsRequest", &schema.GetAllDetailsRequest{X1RequestMessage: client.buildRequestMessage()}},
		{"all task details query", "GetAllTaskDetailsRequest", &schema.GetAllTaskDetailsRequest{X1RequestMessage: client.buildRequestMessage()}},
	}
	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := marshalWrappedRequest(tt.messageType, tt.message)
			require.NoError(t, err)
			validateX1DocumentWithSchema(t, request)
		})
	}

	server := NewServer(ServerConfig{NEIdentifier: "test-ne", Version: DefaultProtocolVersion}, nil, nil)
	response, err := xml.Marshal(&flexibleResponseContainer{Responses: []any{server.responseMessage(client.buildRequestMessage())}})
	require.NoError(t, err)
	validateX1DocumentWithSchema(t, response)

	for _, timestamp := range []schema.QualifiedMicrosecondDateTime{
		*client.buildRequestMessage().MessageTimestamp,
		*server.responseMessage(nil).MessageTimestamp,
		*server.buildErrorResponse(nil, "Ping", ErrorCodeGenericError, "test").MessageTimestamp,
	} {
		validateQualifiedTimestampWithSchema(t, string(timestamp))
	}
}

func TestTaskDetailsResponseMediationTimes(t *testing.T) {
	tests := []struct {
		name      string
		start     time.Time
		end       time.Time
		wantStart string
		wantEnd   string
	}{
		{name: "absent"},
		{
			name:      "whole second",
			start:     time.Date(2026, 8, 26, 1, 2, 3, 0, time.UTC),
			end:       time.Date(2026, 8, 26, 2, 2, 3, 0, time.UTC),
			wantStart: "2026-08-26T01:02:03.000000Z",
			wantEnd:   "2026-08-26T02:02:03.000000Z",
		},
		{
			name:      "sub-microsecond truncated",
			start:     time.Date(2026, 8, 26, 1, 2, 3, 123456999, time.FixedZone("east", 2*60*60)),
			end:       time.Date(2026, 8, 26, 2, 2, 3, 987654999, time.FixedZone("east", 2*60*60)),
			wantStart: "2026-08-26T01:02:03.123456+02:00",
			wantEnd:   "2026-08-26T02:02:03.987654+02:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			details := taskDetailsResponse(&Task{StartTime: tt.start, EndTime: tt.end})
			require.Len(t, details.ListOfMediationDetails.MediationDetails, 1)
			mediation := details.ListOfMediationDetails.MediationDetails[0]
			if tt.wantStart == "" {
				assert.Nil(t, mediation.StartTime)
				assert.Nil(t, mediation.EndTime)
				return
			}
			require.NotNil(t, mediation.StartTime)
			require.NotNil(t, mediation.EndTime)
			assert.Equal(t, tt.wantStart, string(*mediation.StartTime))
			assert.Equal(t, tt.wantEnd, string(*mediation.EndTime))
			validateQualifiedTimestampWithSchema(t, string(*mediation.StartTime))
			validateQualifiedTimestampWithSchema(t, string(*mediation.EndTime))
		})
	}
}

func TestOutboundX1TimestampSitesDoNotUseRFC3339Nano(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(filename)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(contents), ".Format(time.RFC3339Nano)", entry.Name())
	}
}

func validateX1DocumentWithSchema(t *testing.T, document []byte) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	schemaPath := filepath.Join(filepath.Dir(filename), "xsd", "TS_103_221_01.xsd")
	validateXMLWithSchema(t, schemaPath, document)
}

func validateQualifiedTimestampWithSchema(t *testing.T, timestamp string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	commonSchema := filepath.Join(filepath.Dir(filename), "xsd", "TS_103_280.xsd")
	harness := fmt.Sprintf(`<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
 xmlns:common="http://uri.etsi.org/03280/common/2017/07">
 <xs:import namespace="http://uri.etsi.org/03280/common/2017/07" schemaLocation="%s"/>
 <xs:element name="timestamp" type="common:QualifiedMicrosecondDateTime"/>
</xs:schema>`, commonSchema)
	harnessPath := filepath.Join(t.TempDir(), "timestamp.xsd")
	require.NoError(t, os.WriteFile(harnessPath, []byte(harness), 0o600))
	validateXMLWithSchema(t, harnessPath, []byte("<timestamp>"+timestamp+"</timestamp>"))
}

func validateXMLWithSchema(t *testing.T, schemaPath string, document []byte) {
	t.Helper()
	xmllint, err := exec.LookPath("xmllint")
	require.NoError(t, err, "xmllint is required for authoritative X1 schema tests")
	documentPath := filepath.Join(t.TempDir(), "message.xml")
	require.NoError(t, os.WriteFile(documentPath, document, 0o600))
	command := exec.Command(xmllint, "--noout", "--schema", schemaPath, documentPath)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
}
