package failover

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeEndpoints(t *testing.T) {
	got, err := NormalizeEndpoints(" RELAY-A.EXAMPLE.:05555 ", nil)
	require.NoError(t, err)
	require.Equal(t, []Endpoint{{Address: "relay-a.example:5555"}}, got)
	input := []Endpoint{{Address: "[2001:db8:0:0::1]:55555", TLSServerName: "station.example"}, {Address: "127.0.0.1:4444"}}
	got, err = NormalizeEndpoints("", input)
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::1]:55555", got[0].Address)
	require.Equal(t, "station.example", got[0].TLSServerName)
	got[0].Address = "changed:1"
	require.Equal(t, "[2001:db8:0:0::1]:55555", input[0].Address)
}

func TestNormalizeEndpointsRejectsInvalidAndAmbiguousInput(t *testing.T) {
	for _, address := range []string{"", "station", "station:", ":55555", "https://station:55555", "bad host:55555", "station:0", "station:65536", "station:-1", "station:http", "2001:db8::1:55555", "station..example:55555"} {
		t.Run(address, func(t *testing.T) {
			_, err := NormalizeEndpoints("", []Endpoint{{Address: address}})
			require.Error(t, err)
		})
	}
	_, err := NormalizeEndpoints("a:1", []Endpoint{{Address: "b:2"}})
	require.ErrorContains(t, err, "both")
	_, err = NormalizeEndpoints("", []Endpoint{{Address: "A:0001"}, {Address: "a:1"}})
	require.ErrorContains(t, err, "duplicate")
	_, err = NormalizeEndpoints("", []Endpoint{{Address: "a:1", TLSServerName: "a.example"}, {Address: "a:1", TLSServerName: "b.example"}})
	require.ErrorContains(t, err, "conflicting")
	_, err = NormalizeEndpoints("", []Endpoint{{Address: "a:1", TLSServerName: "https://a.example"}})
	require.ErrorContains(t, err, "TLS server name")
}
