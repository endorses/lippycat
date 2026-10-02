package sip

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSDPEndpointNormalization(t *testing.T) {
	tests := []struct {
		name, body string
		want       []string
	}{
		{"media overrides do not leak", "c=IN IP4 10.0.0.1\nm=audio 9000 RTP/AVP 0\nc=IN IP4 10.0.0.2\nm=video 10000 RTP/AVP 96", []string{"10.0.0.2:9000", "10.0.0.2:9001", "10.0.0.1:10000", "10.0.0.1:10001"}},
		{"IPv6 separate RTCP", "c=IN IP6 2001:db8::1\nm=audio 9000 RTP/AVP 0\na=rtcp:9007 IN IP6 2001:db8::2", []string{"[2001:db8::1]:9000", "[2001:db8::2]:9007"}},
		{"mux", "c=IN IP4 10.0.0.1\nm=audio 9000 UDP/TLS/RTP/SAVPF 0\na=rtcp-mux", []string{"10.0.0.1:9000"}},
		{"disabled and inactive", "c=IN IP4 10.0.0.1\nm=audio 0 RTP/AVP 0\nm=audio 9000 RTP/AVP 0\na=inactive", nil},
		{"media connection not session", "m=audio 9000 RTP/AVP 0\nc=IN IP4 10.0.0.2\nm=audio 10000 RTP/AVP 0", []string{"10.0.0.2:9000", "10.0.0.2:9001"}},
		{"multiple port pairs", "c=IN IP4 10.0.0.1\nm=video 9000/2 RTP/AVP 96", []string{"10.0.0.1:9000", "10.0.0.1:9001", "10.0.0.1:9002", "10.0.0.1:9003"}},
		{"hold zero address", "c=IN IP4 0.0.0.0\nm=audio 9000 RTP/AVP 0", nil},
		{"multicast TTL", "c=IN IP4 239.1.2.3/64\nm=audio 9000 RTP/AVP 0", []string{"239.1.2.3:9000", "239.1.2.3:9001"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoints, err := ParseSDPEndpoints(tt.body, 32)
			require.NoError(t, err)
			var got []string
			for _, e := range endpoints {
				got = append(got, e.Address.String())
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSDPLimitsNeverPublishPartialResult(t *testing.T) {
	for _, body := range []string{
		"c=IN IP4 10.0.0.1\nm=audio 9000/65535 RTP/AVP 0",
		"c=IN IP4 10.0.0.1\nm=audio 65535 RTP/AVP 0",
		"c=IN IP4 10.0.0.1\nm=audio invalid RTP/AVP 0",
		"c=IN IP4 239.1.2.3/64/5\nm=audio 9000 RTP/AVP 0",
	} {
		endpoints, err := ParseSDPEndpoints(body, 2)
		require.Error(t, err)
		require.Nil(t, endpoints)
	}
	endpoints, err := ParseSDPEndpoints("c=IN IP4 10.0.0.1\nm=audio 9000 RTP/AVP 0", 1)
	require.ErrorIs(t, err, ErrSDPEndpointLimit)
	require.Nil(t, endpoints)
}
