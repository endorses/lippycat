//go:build tui || all
// +build tui all

package filters

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/stretchr/testify/assert"
)

func TestNodeFilter_ExactMatch(t *testing.T) {
	filter := NewNodeFilter("hunter-kamailio")

	// Should match exact NodeID
	packet1 := components.PacketDisplay{
		NodeID:    "hunter-kamailio",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet1), "Should match exact NodeID")

	// Should NOT match different NodeID
	packet2 := components.PacketDisplay{
		NodeID:    "hunter-fusionpbx",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet2), "Should NOT match different NodeID")

	// Should NOT match Local
	packet3 := components.PacketDisplay{
		NodeID:    "Local",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet3), "Should NOT match Local")
}

func TestNodeFilter_WildcardAll(t *testing.T) {
	filter := NewNodeFilter("*")

	// Should match any hunter
	packet1 := components.PacketDisplay{
		NodeID:    "hunter-kamailio",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet1), "Should match any hunter")

	// Should NOT match Local
	packet2 := components.PacketDisplay{
		NodeID:    "Local",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet2), "Should NOT match Local with wildcard")

	// Should NOT match empty
	packet3 := components.PacketDisplay{
		NodeID:    "",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet3), "Should NOT match empty NodeID")
}

func TestNodeFilter_PrefixWildcard(t *testing.T) {
	filter := NewNodeFilter("hunter-*")

	// Should match prefix
	packet1 := components.PacketDisplay{
		NodeID:    "hunter-kamailio",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet1), "Should match hunter- prefix")

	packet2 := components.PacketDisplay{
		NodeID:    "hunter-fusionpbx",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet2), "Should match hunter- prefix")

	// Should NOT match different prefix
	packet3 := components.PacketDisplay{
		NodeID:    "edge-01",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet3), "Should NOT match different prefix")
}

func TestNodeFilter_SuffixWildcard(t *testing.T) {
	filter := NewNodeFilter("*-kamailio")

	// Should match suffix
	packet1 := components.PacketDisplay{
		NodeID:    "hunter-kamailio",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet1), "Should match -kamailio suffix")

	packet2 := components.PacketDisplay{
		NodeID:    "edge-kamailio",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.True(t, filter.Match(packet2), "Should match -kamailio suffix")

	// Should NOT match different suffix
	packet3 := components.PacketDisplay{
		NodeID:    "hunter-fusionpbx",
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		Protocol:  "SIP",
	}
	assert.False(t, filter.Match(packet3), "Should NOT match different suffix")
}

func TestNodeFilter_String(t *testing.T) {
	filter1 := NewNodeFilter("hunter-kamailio")
	assert.Equal(t, "node:hunter-kamailio", filter1.String())

	filter2 := NewNodeFilter("*")
	assert.Equal(t, "node:*", filter2.String())

	filter3 := NewNodeFilter("hunter-*")
	assert.Equal(t, "node:hunter-*", filter3.String())
}

func TestNodeFilter_Selectivity(t *testing.T) {
	// Wildcard all should have low selectivity
	filter1 := NewNodeFilter("*")
	assert.Equal(t, 0.1, filter1.Selectivity())

	// Specific node should have high selectivity
	filter2 := NewNodeFilter("hunter-kamailio")
	assert.Equal(t, 0.9, filter2.Selectivity())
}
