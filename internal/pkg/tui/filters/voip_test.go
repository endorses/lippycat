//go:build tui || all

package filters

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/assert"
)

func TestVoIPFilter_FromTag(t *testing.T) {
	filter := NewVoIPFilter("fromtag", "abc123")

	// Should match packet with matching FromTag in VoIPData
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "abc123",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match FromTag in VoIPData")

	// Should NOT match packet with different FromTag
	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "xyz789",
		},
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different FromTag")

	// Should NOT match packet without VoIPData
	packet3 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet3), "Should NOT match packet without VoIPData")
}

func TestVoIPFilter_ToTag(t *testing.T) {
	filter := NewVoIPFilter("totag", "def456")

	// Should match packet with matching ToTag
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			ToTag: "def456",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match ToTag in VoIPData")

	// Should NOT match packet with different ToTag
	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			ToTag: "ghi789",
		},
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different ToTag")
}

func TestVoIPFilter_FromTag_Wildcard(t *testing.T) {
	filter := NewVoIPFilter("fromtag", "abc*")

	// Should match tags starting with "abc"
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "abc123",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match prefix wildcard")

	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "abcxyz",
		},
	}
	assert.True(t, filter.Match(packet2), "Should match prefix wildcard")

	// Should NOT match tags with different prefix
	packet3 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "xyz123",
		},
	}
	assert.False(t, filter.Match(packet3), "Should NOT match different prefix")
}

func TestVoIPFilter_ToTag_Wildcard(t *testing.T) {
	filter := NewVoIPFilter("totag", "*456")

	// Should match tags ending with "456"
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			ToTag: "def456",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match suffix wildcard")

	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			ToTag: "xyz456",
		},
	}
	assert.True(t, filter.Match(packet2), "Should match suffix wildcard")

	// Should NOT match tags with different suffix
	packet3 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			ToTag: "def789",
		},
	}
	assert.False(t, filter.Match(packet3), "Should NOT match different suffix")
}

func TestVoIPFilter_Method(t *testing.T) {
	filter := NewVoIPFilter("method", "INVITE")

	// Should match packet with INVITE method
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			Method: "INVITE",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match INVITE method")

	// Should NOT match packet with different method
	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			Method: "BYE",
		},
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different method")
}

func TestVoIPFilter_User(t *testing.T) {
	filter := NewVoIPFilter("user", "alicent")

	// Should match packet with matching user
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			User: "alicent",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match user")

	// Should NOT match packet with different user
	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			User: "robb",
		},
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different user")
}

func TestVoIPFilter_CallID(t *testing.T) {
	filter := NewVoIPFilter("callid", "test-call-123")

	// Should match packet with matching CallID
	packet1 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			CallID: "test-call-123",
		},
	}
	assert.True(t, filter.Match(packet1), "Should match CallID")

	// Should NOT match packet with different CallID
	packet2 := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
		VoIPData: &components.VoIPMetadata{
			CallID: "test-call-456",
		},
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different CallID")
}

func TestVoIPFilter_NonSIPProtocol(t *testing.T) {
	filter := NewVoIPFilter("fromtag", "abc123")

	// Should NOT match non-SIP packets
	packet := components.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "RTP",
		VoIPData: &components.VoIPMetadata{
			FromTag: "abc123",
		},
	}
	assert.False(t, filter.Match(packet), "Should NOT match non-SIP protocol")
}

func TestVoIPFilter_String(t *testing.T) {
	filter1 := NewVoIPFilter("fromtag", "abc123")
	assert.Equal(t, "sip.fromtag:abc123", filter1.String())

	filter2 := NewVoIPFilter("totag", "def*")
	assert.Equal(t, "sip.totag:def*", filter2.String())

	filter3 := NewVoIPFilter("user", "alicent")
	assert.Equal(t, "sip.user:alicent", filter3.String())
}
