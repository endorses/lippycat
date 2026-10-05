package sip

import (
	"github.com/stretchr/testify/require"
	"strings"
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
			parsed := ParseSDPResult(tt.body, 32)
			if tt.name == "media connection not session" {
				require.False(t, parsed.Complete)
			} else {
				require.True(t, parsed.Complete)
			}
			endpoints := parsed.Endpoints
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

func TestPartialSDPRecoversIndependentSections(t *testing.T) {
	for _, broken := range []string{
		"m=audio invalid RTP/AVP 0\nc=IN IP4 192.0.2.99",
		"m=\nc=IN IP4 192.0.2.99\na=inactive",
		"m=audio 11000 RTP/AVP 0\nc=IN IP4 unresolved.example",
		"m=audio 11000 RTP/AVP 0\nc=IN IP6 192.0.2.99",
		"m=audio 11000 RTP/AVP 0\na=rtcp:bad",
		"m=audio 11000 RTP/AVP 0\na=rtcp:11001 IN IP4 unresolved.example",
		"m=audio 11000/2 RTP/AVP 0\na=rtcp:11009",
		"m=audio 65535 RTP/AVP 0",
	} {
		t.Run(broken, func(t *testing.T) {
			body := "c=IN IP6 2001:db8::1\nm=audio 9000 RTP/AVP 0\n" + broken + "\nm=video 12000 RTP/AVP 96"
			result := ParseSDPResult(body, 32)
			require.False(t, result.Complete)
			require.False(t, result.ResourceLimited)
			require.False(t, result.IntentionalEmpty)
			var got []string
			for _, endpoint := range result.Endpoints {
				got = append(got, endpoint.Address.String())
			}
			require.Equal(t, []string{"[2001:db8::1]:9000", "[2001:db8::1]:9001", "[2001:db8::1]:12000", "[2001:db8::1]:12001"}, got)
			require.NotEmpty(t, result.Diagnostics)
			require.Error(t, result.Err())
		})
	}
}

func TestPartialSDPInvalidConnectionScope(t *testing.T) {
	result := ParseSDPResult("c=IN IP4 invalid.example\nm=audio 9000 RTP/AVP 0\nm=video 12000 RTP/AVP 96\nc=IN IP4 192.0.2.2", 32)
	require.False(t, result.Complete)
	require.Len(t, result.Endpoints, 2)
	require.Equal(t, "192.0.2.2:12000", result.Endpoints[0].Address.String())
	result = ParseSDPResult("c=IN IP4 192.0.2.1\nm=audio 9000 RTP/AVP 0\nc=IN IP4 192.0.2.2\nc=IN IP4 invalid.example\nm=video 12000 RTP/AVP 96", 32)
	require.Len(t, result.Endpoints, 2)
	require.Equal(t, "192.0.2.1:12000", result.Endpoints[0].Address.String())
}

func TestPartialSDPBoundsAndIntentionalEmpty(t *testing.T) {
	body := "c=IN IP4 192.0.2.1\nm=audio 9000 RTP/AVP 0\nm=video 12000 RTP/AVP 96"
	result := ParseSDPResult(body, 3)
	require.Len(t, result.Endpoints, 3)
	require.True(t, result.ResourceLimited)
	require.ErrorIs(t, result.Err(), ErrSDPEndpointLimit)
	require.Equal(t, "192.0.2.1:12000", result.Endpoints[2].Address.String())
	result = ParseSDPResult(strings.Repeat("x", MaxMessageSize+1), 32)
	require.Empty(t, result.Endpoints)
	require.True(t, result.ResourceLimited)
	require.Equal(t, SDPBodyLimit, result.Diagnostics[0].Reason)
	result = ParseSDPResult(strings.Repeat("m=invalid\n", MaxSDPDiagnostics+10), 32)
	require.Len(t, result.Diagnostics, MaxSDPDiagnostics)
	require.Equal(t, uint64(10), result.DiagnosticsDropped)
	var counters SDPParseCounters
	counters.Observe(result)
	require.Equal(t, uint64(MaxSDPDiagnostics+10), counters.Snapshot().Reasons[SDPMediaInvalid])
	for _, body := range []string{
		"c=IN IP4 192.0.2.1\nm=audio 0 RTP/AVP 0",
		"c=IN IP4 192.0.2.1\nm=audio 9000 RTP/AVP 0\na=inactive",
		"c=IN IP4 0.0.0.0\nm=audio 9000 RTP/AVP 0",
		"m=application 9000 TCP/MSRP *",
	} {
		result := ParseSDPResult(body, 32)
		require.True(t, result.Complete)
		require.True(t, result.IntentionalEmpty)
		require.Empty(t, result.Endpoints)
	}
	result = ParseSDPResult("m=audio 9000 RTP/AVP 0", 32)
	require.False(t, result.Complete)
	require.False(t, result.IntentionalEmpty)
	require.Equal(t, SDPConnectionMissing, result.Diagnostics[0].Reason)
}
