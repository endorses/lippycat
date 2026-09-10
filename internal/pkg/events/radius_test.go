package events

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/stretchr/testify/require"
)

func TestRADIUSEventAttributePolicyAndOwnership(t *testing.T) {
	o := &radius.Observation{Message: &radius.Message{Code: 1, Identifier: 255, Length: 80, Attributes: []radius.Attribute{
		{Type: 1, Value: []byte{'a', 0xff, '\n'}}, {Type: 2, Value: []byte("password")},
		{Type: 3, Value: []byte("chap")}, {Type: 79, Value: []byte("eap")}, {Type: 200, Value: []byte("unknown")},
		{Type: 1, Value: []byte("second")}, {Type: 26, VendorID: 3561, VendorAttributes: []radius.VendorAttribute{{Type: 1, Value: []byte("line")}, {Type: 2, Value: []byte("vendor-secret")}}},
	}}, Association: radius.Association{Status: radius.AssociationUnique, RequestInstanceID: radius.Identity{Epoch: [16]byte{1}, Sequence: 42}}}
	ev, ok := RADIUSFromObservation(Envelope{}, o)
	require.True(t, ok)
	require.Equal(t, []string{"1:hex:61ff0a", "1:hex:7365636f6e64", "26/3561/1:hex:6c696e65"}, ev.Attributes)
	require.Equal(t, "01000000000000000000000000000000:42", ev.RequestInstanceID)
	o.Message.Attributes[0].Value[0] = 'z'
	require.Equal(t, "1:hex:61ff0a", ev.Attributes[0])
	serialized, err := json.Marshal(ev)
	require.NoError(t, err)
	for _, secret := range []string{"password", "chap", "eap", "unknown", "vendor-secret", "Authenticator"} {
		require.NotContains(t, string(serialized), secret)
	}
	_, ok = RADIUSFromObservation(Envelope{}, nil)
	require.False(t, ok)
}
