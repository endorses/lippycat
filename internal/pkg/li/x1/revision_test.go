//go:build li

package x1

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
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
	did, xid := uuid.New(), uuid.New()
	operations := map[string]func(string) string{
		"pingRequest": func(version string) string { return requestXML("pingRequest", version, "") },
		"createDestinationRequest": func(version string) string {
			return requestXML("createDestinationRequest", version, destinationXML(did))
		},
		"modifyDestinationRequest": func(version string) string {
			return requestXML("modifyDestinationRequest", version, destinationXML(did))
		},
		"removeDestinationRequest": func(version string) string {
			return requestXML("removeDestinationRequest", version, "<dId>"+did.String()+"</dId>")
		},
		"activateTaskRequest": func(version string) string {
			return requestXML("activateTaskRequest", version, taskXML(xid, did, true))
		},
		"modifyTaskRequest": func(version string) string { return requestXML("modifyTaskRequest", version, taskXML(xid, did, false)) },
		"deactivateTaskRequest": func(version string) string {
			return requestXML("deactivateTaskRequest", version, "<xId>"+xid.String()+"</xId>")
		},
		"getTaskDetailsRequest": func(version string) string {
			return requestXML("getTaskDetailsRequest", version, "<xId>"+xid.String()+"</xId>")
		},
	}
	for operation, fixture := range operations {
		for _, version := range []string{minimumProtocolVersion, DefaultProtocolVersion} {
			t.Run(operation+"_"+version, func(t *testing.T) {
				destinations, tasks := newMockDestinationManager(), newMockTaskManager()
				destinations.destinations[did] = &Destination{DID: did, X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3"}
				tasks.tasks[xid] = &Task{XID: xid, DeliveryType: DeliveryX2andX3, Status: TaskStatusActive}
				if operation == "createDestinationRequest" {
					delete(destinations.destinations, did)
				}
				if operation == "activateTaskRequest" {
					delete(tasks.tasks, xid)
				}
				s := NewServer(ServerConfig{NEIdentifier: "test-ne"}, destinations, tasks)
				body := fixture(version)
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
				w := httptest.NewRecorder()
				s.handleX1Request(w, req)
				assert.NotContains(t, w.Body.String(), "errorResponse", w.Body.String())
			})
		}
	}
}

func requestXML(operation, version, payload string) string {
	return fmt.Sprintf("<%s><admfIdentifier>test-admf</admfIdentifier><neIdentifier>test-ne</neIdentifier><version>%s</version>%s</%s>", operation, version, payload, operation)
}

func destinationXML(did uuid.UUID) string {
	return "<destinationDetails><dId>" + did.String() + "</dId><deliveryType>X2andX3</deliveryType><deliveryAddress><ipAddressAndPort><address><IPv4Address>192.0.2.10</IPv4Address></address><port><TCPPort>9443</TCPPort></port></ipAddressAndPort></deliveryAddress></destinationDetails>"
}

func taskXML(xid, did uuid.UUID, full bool) string {
	if !full {
		return "<taskDetails><xId>" + xid.String() + "</xId><implicitDeactivationAllowed>true</implicitDeactivationAllowed></taskDetails>"
	}
	return "<taskDetails><xId>" + xid.String() + "</xId><targetIdentifiers><targetIdentifier><sipUri>sip:alice@example.net</sipUri></targetIdentifier></targetIdentifiers><deliveryType>X2andX3</deliveryType><listOfDIDs><dId>" + did.String() + "</dId></listOfDIDs></taskDetails>"
}
