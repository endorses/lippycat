//go:build li

package li

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func ep(t *testing.T, addr string, port uint16) mediaEndpoint {
	t.Helper()
	a, err := netip.ParseAddr(addr)
	require.NoError(t, err)
	return mediaEndpoint{addr: a.Unmap(), port: port}
}

func TestParseSDPMediaEndpoints(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []mediaEndpoint
	}{
		{
			name: "IPv4 session level connection",
			body: "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 10000)},
		},
		{
			name: "IPv6 session level connection",
			body: "v=0\r\nc=IN IP6 2001:db8:b::2\r\nm=audio 40696 RTP/AVP 104\r\n",
			want: []mediaEndpoint{ep(t, "2001:db8:b::2", 40696)},
		},
		{
			// A media-level c= follows the m= line of the section it applies to.
			name: "media level connection applies to its own section",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nc=IN IP4 192.0.2.9\r\nm=video 10002 RTP/AVP 96\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.9", 10000), ep(t, "192.0.2.1", 10002)},
		},
		{
			name: "media level connection does not leak into next stream",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nc=IN IP4 192.0.2.9\r\nm=audio 10004 RTP/AVP 0\r\nm=audio 10006 RTP/AVP 0\r\n",
			want: []mediaEndpoint{
				ep(t, "192.0.2.9", 10000),
				ep(t, "192.0.2.1", 10004),
				ep(t, "192.0.2.1", 10006),
			},
		},
		{
			name: "declined stream (port 0) is ignored",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n",
			want: nil,
		},
		{
			name: "on-hold unspecified address is ignored",
			body: "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: nil,
		},
		{
			name: "port count suffix is stripped",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 49170/2 RTP/AVP 0\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 49170)},
		},
		{
			name: "multicast TTL suffix is stripped",
			body: "v=0\r\nc=IN IP4 224.2.1.1/127/3\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: []mediaEndpoint{ep(t, "224.2.1.1", 10000)},
		},
		{
			name: "non-media m= lines are skipped",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 10000)},
		},
		{
			name: "duplicate endpoints are collapsed",
			body: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=audio 10000 RTP/AVP 8\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 10000)},
		},
		{
			name: "LF-only line endings",
			body: "v=0\nc=IN IP4 192.0.2.1\nm=audio 10000 RTP/AVP 0\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 10000)},
		},
		{
			name: "media without any connection address",
			body: "v=0\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: nil,
		},
		{
			name: "malformed lines are tolerated",
			body: "c=IN IP4 192.0.2.1\r\nc=IN IP4\r\nc=IN IP4 not-an-address\r\nm=audio\r\nm=audio notaport RTP/AVP 0\r\nm=audio 10000 RTP/AVP 0\r\n",
			want: []mediaEndpoint{ep(t, "192.0.2.1", 10000)},
		},
		{
			name: "empty body",
			body: "",
			want: nil,
		},
		{
			name: "non-SDP body",
			body: "Hello, this is a text message body\r\n",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSDPMediaEndpoints(tt.body)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSIPMessageBody(t *testing.T) {
	const sdp = "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"
	msg := "INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc\r\nContent-Type: application/sdp\r\n\r\n" + sdp

	t.Run("from RawSIP", func(t *testing.T) {
		pkt := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{RawSIP: []byte(msg)}}
		assert.Equal(t, sdp, sipMessageBody(pkt))
	})

	t.Run("from RawData with headers before the SIP message", func(t *testing.T) {
		raw := append([]byte{0x45, 0x00, 0x01, 0x02, 0x11, 0x94}, []byte(msg)...)
		pkt := &types.PacketDisplay{RawData: raw, VoIPData: &types.VoIPMetadata{}}
		assert.Equal(t, sdp, sipMessageBody(pkt))
	})

	t.Run("LF-only separator", func(t *testing.T) {
		lf := "SIP/2.0 200 OK\nCall-ID: abc\n\n" + sdp
		pkt := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{RawSIP: []byte(lf)}}
		assert.Equal(t, sdp, sipMessageBody(pkt))
	})

	t.Run("no body", func(t *testing.T) {
		pkt := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
			RawSIP: []byte("BYE sip:bob@example.com SIP/2.0\r\nCall-ID: abc\r\n\r\n"),
		}}
		assert.Equal(t, "", sipMessageBody(pkt))
	})

	t.Run("no SIP message in raw data", func(t *testing.T) {
		pkt := &types.PacketDisplay{RawData: []byte{0x00, 0x01, 0x02}}
		assert.Equal(t, "", sipMessageBody(pkt))
	})

	t.Run("nil packet", func(t *testing.T) {
		assert.Equal(t, "", sipMessageBody(nil))
	})
}

func TestPacketEndpoints(t *testing.T) {
	t.Run("IPv6 with ports", func(t *testing.T) {
		pkt := &types.PacketDisplay{
			SrcIP: "2001:db8:a::1", SrcPort: "49120",
			DstIP: "2001:db8:b::2", DstPort: "40696",
		}
		src, dst, ok := packetEndpoints(pkt)
		require.True(t, ok)
		assert.Equal(t, ep(t, "2001:db8:a::1", 49120), src)
		assert.Equal(t, ep(t, "2001:db8:b::2", 40696), dst)
	})

	t.Run("missing port", func(t *testing.T) {
		pkt := &types.PacketDisplay{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: "10000"}
		_, _, ok := packetEndpoints(pkt)
		assert.False(t, ok)
	})

	t.Run("unparsable address", func(t *testing.T) {
		pkt := &types.PacketDisplay{SrcIP: "nope", SrcPort: "1", DstIP: "192.0.2.2", DstPort: "2"}
		_, _, ok := packetEndpoints(pkt)
		assert.False(t, ok)
	})
}
