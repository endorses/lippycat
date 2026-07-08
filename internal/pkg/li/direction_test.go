//go:build li

package li

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestPayloadDirectionForTarget(t *testing.T) {
	tests := []struct {
		name   string
		target TargetIdentity
		pkt    *types.PacketDisplay
		want   x2x3.PayloadDirection
	}{
		{
			name:   "IPv4 address source is target -> from target",
			target: TargetIdentity{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			pkt:    &types.PacketDisplay{SrcIP: "192.168.1.100", DstIP: "10.0.0.5"},
			want:   x2x3.PayloadDirectionFromTarget,
		},
		{
			name:   "IPv4 address dest is target -> to target",
			target: TargetIdentity{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			pkt:    &types.PacketDisplay{SrcIP: "10.0.0.5", DstIP: "192.168.1.100"},
			want:   x2x3.PayloadDirectionToTarget,
		},
		{
			name:   "IPv4 CIDR contains source -> from target",
			target: TargetIdentity{Type: TargetTypeIPv4CIDR, Value: "10.0.0.0/8"},
			pkt:    &types.PacketDisplay{SrcIP: "10.1.2.3", DstIP: "8.8.8.8"},
			want:   x2x3.PayloadDirectionFromTarget,
		},
		{
			name:   "IPv4 target on neither side -> unknown",
			target: TargetIdentity{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			pkt:    &types.PacketDisplay{SrcIP: "10.0.0.5", DstIP: "10.0.0.6"},
			want:   x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "IPv4 target on both sides -> unknown",
			target: TargetIdentity{Type: TargetTypeIPv4CIDR, Value: "10.0.0.0/8"},
			pkt:    &types.PacketDisplay{SrcIP: "10.0.0.5", DstIP: "10.0.0.6"},
			want:   x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "IPv6 address source is target -> from target",
			target: TargetIdentity{Type: TargetTypeIPv6Address, Value: "2001:db8::1"},
			pkt:    &types.PacketDisplay{SrcIP: "2001:db8::1", DstIP: "2001:db8::2"},
			want:   x2x3.PayloadDirectionFromTarget,
		},
		{
			name:   "SIP URI matches From -> from target",
			target: TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "\"Alice\" <sip:alice@example.com>;tag=abc",
				To:   "<sip:bob@example.com>",
			}},
			want: x2x3.PayloadDirectionFromTarget,
		},
		{
			name:   "SIP URI matches To -> to target",
			target: TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "<sip:alice@example.com>;tag=abc",
				To:   "<sip:bob@example.com:5060;transport=tcp>",
			}},
			want: x2x3.PayloadDirectionToTarget,
		},
		{
			name:   "TEL URI matches From by digits -> from target",
			target: TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "<sip:+15551234567@ims.example.com;user=phone>;tag=x",
				To:   "<sip:+15559999999@ims.example.com;user=phone>",
			}},
			want: x2x3.PayloadDirectionFromTarget,
		},
		{
			name:   "username matches To -> to target",
			target: TargetIdentity{Type: TargetTypeUsername, Value: "bob"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "<sip:alice@example.com>",
				To:   "<sip:bob@other.example.net>",
			}},
			want: x2x3.PayloadDirectionToTarget,
		},
		{
			name:   "SIP URI on neither side -> unknown",
			target: TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:carol@example.com"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "<sip:alice@example.com>",
				To:   "<sip:bob@example.com>",
			}},
			want: x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "SIP URI target on RTP packet (no SIP identity) -> unknown",
			target: TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			pkt:    &types.PacketDisplay{VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 0x1234}},
			want:   x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "TEL target must not substring-match a longer number -> unknown",
			target: TargetIdentity{Type: TargetTypeTELURI, Value: "tel:555"},
			pkt: &types.PacketDisplay{VoIPData: &types.VoIPMetadata{
				From: "<sip:5551234@ims.example.com;user=phone>",
				To:   "<sip:5559999@ims.example.com;user=phone>",
			}},
			want: x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "IMSI target -> unknown (no per-packet direction)",
			target: TargetIdentity{Type: TargetTypeIMSI, Value: "001010123456789"},
			pkt:    &types.PacketDisplay{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
			want:   x2x3.PayloadDirectionUnknown,
		},
		{
			name:   "nil packet -> unknown",
			target: TargetIdentity{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
			pkt:    nil,
			want:   x2x3.PayloadDirectionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PayloadDirectionForTarget(tt.target, tt.pkt)
			if got != tt.want {
				t.Errorf("PayloadDirectionForTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}
