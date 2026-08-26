//go:build li

package x1

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

func TestClassifyProtocolVersion_AcceptedWindow(t *testing.T) {
	for minor := 13; minor <= 22; minor++ {
		for _, prefix := range []string{"", "v"} {
			version := fmt.Sprintf("%s1.%d.1", prefix, minor)
			expected := revisionAcceptedCompatible
			if minor == 22 {
				expected = revisionAcceptedExact
			}
			t.Run(version, func(t *testing.T) { assert.Equal(t, expected, classifyProtocolVersion(version)) })
		}
	}
}

func TestClassifyProtocolVersion_Rejections(t *testing.T) {
	tests := map[string]revisionDisposition{
		"1.13.0": revisionUnsupported, "v1.12.9": revisionUnsupported,
		"1.22.2": revisionUnsupported, "v1.23.1": revisionUnsupported,
		"1.13": revisionMalformed, "1.13.1.0": revisionMalformed,
		"-1.13.1": revisionMalformed, "v1.-13.1": revisionMalformed,
		"V1.13.1": revisionMalformed, " 1.13.1": revisionMalformed,
		"1.13.1 ": revisionMalformed, "1.13.1extra": revisionMalformed,
		"v": revisionMalformed, "1..1": revisionMalformed,
	}
	for version, expected := range tests {
		t.Run(version, func(t *testing.T) { assert.Equal(t, expected, classifyProtocolVersion(version)) })
	}
	assert.Equal(t, revisionAbsent, classifyProtocolVersion(""))
}

func TestServer_ProtocolRevisionErrorAndMetrics(t *testing.T) {
	s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, newMockDestinationManager(), newMockTaskManager())
	versions := []string{"v1.22.1", "1.13.1", "", "broken", "v1.23.1"}
	for _, version := range versions {
		body := `<pingRequest><version>` + version + `</version></pingRequest>`
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.handleX1Request(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		if version == "broken" || version == "v1.23.1" {
			var container struct {
				Errors []*schema.ErrorResponse `xml:"errorResponse"`
			}
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &container))
			require.Len(t, container.Errors, 1)
			assert.Equal(t, ErrorCodeRequestSyntaxError, container.Errors[0].ErrorInformation.ErrorCode)
			assert.Contains(t, container.Errors[0].ErrorInformation.ErrorDescription, fmt.Sprintf("%q", version))
			assert.Contains(t, container.Errors[0].ErrorInformation.ErrorDescription, minimumProtocolVersion)
			assert.Contains(t, container.Errors[0].ErrorInformation.ErrorDescription, DefaultProtocolVersion)
		}
	}
	assert.Equal(t, RevisionStats{AcceptedExact: 1, AcceptedCompatible: 1, Absent: 1, Malformed: 1, Unsupported: 1}, s.RevisionStats())

	// Repeated observations for one peer/revision retain one bounded log key.
	s.logRevisionOnce("192.0.2.1", "v1.13.1")
	s.logRevisionOnce("192.0.2.1", "v1.13.1")
	assert.Len(t, s.revisionLogs, 2) // compatible v1.13.1 plus unspecified
}

func TestServer_AllInboundOperationsAcceptWindowBoundaries(t *testing.T) {
	operations := []string{
		"createDestinationRequest", "modifyDestinationRequest", "removeDestinationRequest", "pingRequest",
		"activateTaskRequest", "deactivateTaskRequest", "modifyTaskRequest", "getTaskDetailsRequest",
	}
	for _, operation := range operations {
		for _, version := range []string{minimumProtocolVersion, DefaultProtocolVersion} {
			t.Run(operation+"_"+version, func(t *testing.T) {
				s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, newMockDestinationManager(), newMockTaskManager())
				body := fmt.Sprintf("<%s><version>%s</version></%s>", operation, version, operation)
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
				w := httptest.NewRecorder()
				s.handleX1Request(w, req)
				assert.NotContains(t, w.Body.String(), "unsupported X1 protocol version")
			})
		}
	}
}
