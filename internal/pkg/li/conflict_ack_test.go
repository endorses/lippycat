//go:build li

package li

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/stretchr/testify/require"
)

// Mirror request correlation in a real typed acknowledgment. Schema validation
// of actual client emissions and responses belongs to x1's wire test matrix.
func conflictTestAcknowledgment(t *testing.T, body []byte) []byte {
	t.Helper()
	var request struct {
		Message struct {
			Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			schema.X1RequestMessage
		} `xml:"x1RequestMessage"`
	}
	require.NoError(t, xml.Unmarshal(body, &request))
	response := struct {
		XMLName xml.Name `xml:"http://uri.etsi.org/03221/X1/2017/10 X1Response"`
		XSI     string   `xml:"xmlns:xsi,attr"`
		Message struct {
			Type string `xml:"xsi:type,attr"`
			schema.X1RequestMessage
			OK string `xml:"oK"`
		} `xml:"x1ResponseMessage"`
	}{XSI: "http://www.w3.org/2001/XMLSchema-instance"}
	response.Message.Type = strings.TrimSuffix(request.Message.Type, "Request") + "Response"
	response.Message.X1RequestMessage = request.Message.X1RequestMessage
	response.Message.OK = "AcknowledgedAndCompleted"
	encoded, err := xml.Marshal(response)
	require.NoError(t, err)
	return encoded
}
