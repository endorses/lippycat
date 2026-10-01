//go:build li

package x1

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClient_GetAllDetailsRequiresCompleteSnapshot(t *testing.T) {
	sections := `<neStatusDetails><neStatus>operational</neStatus></neStatusDetails><listOfTaskResponseDetails/><listOfDestinationResponseDetails/>`
	cases := []struct {
		name string
		xml  string
		ok   bool
	}{
		{"empty envelope", `<X1Response/>`, false},
		{"empty message", `<X1Response><x1ResponseMessage/></X1Response>`, false},
		{"missing NE status", `<GetAllDetailsResponse><listOfTaskResponseDetails/><listOfDestinationResponseDetails/></GetAllDetailsResponse>`, false},
		{"empty NE status", `<GetAllDetailsResponse><neStatusDetails/><listOfTaskResponseDetails/><listOfDestinationResponseDetails/></GetAllDetailsResponse>`, false},
		{"missing task list", `<GetAllDetailsResponse><neStatusDetails><neStatus>operational</neStatus></neStatusDetails><listOfDestinationResponseDetails/></GetAllDetailsResponse>`, false},
		{"missing destination list", `<GetAllDetailsResponse><neStatusDetails><neStatus>operational</neStatus></neStatusDetails><listOfTaskResponseDetails/></GetAllDetailsResponse>`, false},
		{"wrong direct type", `<GetNEStatusResponse>` + sections + `</GetNEStatusResponse>`, false},
		{"wrong wrapped type", `<X1Response xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><x1ResponseMessage xsi:type="GetNEStatusResponse">` + sections + `</x1ResponseMessage></X1Response>`, false},
		{"multiple messages", `<X1Response><x1ResponseMessage>` + sections + `</x1ResponseMessage><x1ResponseMessage>` + sections + `</x1ResponseMessage></X1Response>`, false},
		{"valid direct empty lists", `<GetAllDetailsResponse>` + sections + `</GetAllDetailsResponse>`, true},
		{"valid wrapped empty lists", `<X1Response xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:x1="http://uri.etsi.org/03221/X1/2017/10"><x1ResponseMessage xsi:type="x1:GetAllDetailsResponse">` + sections + `</x1ResponseMessage></X1Response>`, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(ClientConfig{
				ADMFEndpoint:   "http://admf.example.test",
				InitialBackoff: time.Millisecond,
				MaxBackoff:     time.Millisecond,
				MaxRetries:     1,
			})
			require.NoError(t, err)
			defer client.Stop()
			client.httpClient.Transport = startupTransportFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(test.xml)), Header: make(http.Header)}, nil
			})
			response, err := client.GetAllDetails(context.Background())
			if test.ok {
				require.NoError(t, err)
				require.NotNil(t, response.NeStatusDetails)
				require.NotNil(t, response.ListOfTaskResponseDetails)
				require.NotNil(t, response.ListOfDestinationResponseDetails)
				require.Empty(t, response.ListOfTaskResponseDetails.TaskResponseDetails)
				require.Empty(t, response.ListOfDestinationResponseDetails.DestinationResponseDetails)
			} else {
				require.Error(t, err)
				require.Nil(t, response)
			}
		})
	}
}
