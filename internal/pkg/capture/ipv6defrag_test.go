package capture

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mkV6 builds a minimal IPv6 layer with the given endpoints.
func mkV6(src, dst string) *layers.IPv6 {
	return &layers.IPv6{
		Version:  6,
		SrcIP:    net.ParseIP(src),
		DstIP:    net.ParseIP(dst),
		HopLimit: 64,
	}
}

// mkV6Frag builds an IPv6 fragment layer carrying payload. offset is in
// 8-byte units (the on-wire fragment-offset encoding).
func mkV6Frag(nextHdr layers.IPProtocol, offset uint16, more bool, id uint32, payload []byte) *layers.IPv6Fragment {
	f := &layers.IPv6Fragment{
		NextHeader:     nextHdr,
		FragmentOffset: offset,
		MoreFragments:  more,
		Identification: id,
	}
	f.BaseLayer = layers.BaseLayer{Payload: payload}
	return f
}

// A 2-fragment IPv6 datagram — the on-wire pattern of a large SIP INVITE
// fragmented on an IMS/VXLAN tunnel — reassembles in order.
func TestIPv6Defragmenter_TwoFragments(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03:9ec0:fc81::1b", "2a03:9ec0::8c")

	first := bytes.Repeat([]byte{0xAA}, 1448) // multiple of 8 (non-final)
	second := bytes.Repeat([]byte{0xBB}, 1146)

	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 0xdeadbeef, first))
	require.NoError(t, err)
	require.Nil(t, out, "datagram should not be complete after the first fragment")

	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 181, false, 0xdeadbeef, second))
	require.NoError(t, err)
	require.NotNil(t, out, "datagram should be complete after the final fragment")

	assert.Equal(t, layers.IPProtocolUDP, out.NextHeader)
	require.Len(t, out.Payload, len(first)+len(second))
	assert.True(t, bytes.Equal(out.Payload[:len(first)], first), "first fragment misplaced")
	assert.True(t, bytes.Equal(out.Payload[len(first):], second), "second fragment misplaced")
	assert.Equal(t, 0, d.inFlight(), "completed datagram should be evicted")
}

// Fragments arriving out of order (final fragment before the first) must
// still reassemble correctly — multi-path forwarding can reorder them.
func TestIPv6Defragmenter_OutOfOrder(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03:9ec0:fc81::1b", "2a03:9ec0::8c")

	first := bytes.Repeat([]byte{0xAA}, 800) // multiple of 8 (non-final)
	second := bytes.Repeat([]byte{0xBB}, 400)

	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 100, false, 1, second))
	require.NoError(t, err)
	require.Nil(t, out, "datagram should not be complete with only the final fragment")

	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 1, first))
	require.NoError(t, err)
	require.NotNil(t, out, "datagram should be complete once both fragments arrive")

	require.Len(t, out.Payload, 1200)
	assert.True(t, bytes.Equal(out.Payload[:800], first))
	assert.True(t, bytes.Equal(out.Payload[800:], second))
}

// Fragments with distinct identification values belong to distinct
// datagrams and must not be mixed.
func TestIPv6Defragmenter_DistinctIDs(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03::1", "2a03::2")

	// ID 1: only the first fragment — must stay incomplete.
	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 1, bytes.Repeat([]byte{1}, 64)))
	require.NoError(t, err)
	require.Nil(t, out)

	// ID 2: a complete pair — must complete independently.
	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 2, bytes.Repeat([]byte{0x10}, 64)))
	require.NoError(t, err)
	require.Nil(t, out)
	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 8, false, 2, bytes.Repeat([]byte{0x20}, 32)))
	require.NoError(t, err)
	require.NotNil(t, out, "ID 2 should complete independently of ID 1")

	assert.Equal(t, 1, d.inFlight(), "ID 1 should still be pending")
}

// Stale, incomplete datagrams are evicted by DiscardOlderThan.
func TestIPv6Defragmenter_DiscardOlderThan(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03::1", "2a03::2")
	now := time.Now()

	out, err := d.DefragIPv6WithTimestamp(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 99, bytes.Repeat([]byte{1}, 16)), now)
	require.NoError(t, err)
	require.Nil(t, out)
	require.Equal(t, 1, d.inFlight())

	discarded := d.DiscardOlderThan(now.Add(time.Minute))
	assert.Equal(t, 1, discarded)
	assert.Equal(t, 0, d.inFlight(), "stale datagram should be evicted")
}

// A datagram whose fragments do not cover a contiguous byte range is
// rejected rather than yielding a corrupt payload.
func TestIPv6Defragmenter_NonContiguousRejected(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03::1", "2a03::2")

	// offset 0 (8 bytes, more) + offset 16 (8 bytes, final) leaves an
	// 8-byte hole at offset 8: totalLen 24, but only 16 bytes present.
	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 7, bytes.Repeat([]byte{1}, 8)))
	require.NoError(t, err)
	require.Nil(t, out)
	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 2, false, 7, bytes.Repeat([]byte{2}, 8)))
	require.NoError(t, err)
	require.Nil(t, out, "datagram with a hole must not complete")

	// A duplicate of the first fragment makes the byte count reach
	// totalLen while leaving the hole — build() must reject it.
	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 7, bytes.Repeat([]byte{1}, 8)))
	require.Error(t, err, "non-contiguous fragments must be rejected")
	assert.Nil(t, out)
}

// Malformed fragments are rejected: a non-final fragment must be a
// multiple of 8 bytes, and the offset must be within range.
func TestIPv6Defragmenter_MalformedRejected(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03::1", "2a03::2")

	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 1, bytes.Repeat([]byte{1}, 7)))
	require.Error(t, err, "non-final fragment not a multiple of 8 bytes must be rejected")
	assert.Nil(t, out)

	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, IPv6MaximumFragmentOffset+1, false, 2, []byte{1, 2, 3}))
	require.Error(t, err, "out-of-range fragment offset must be rejected")
	assert.Nil(t, out)

	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolUDP, 0, true, 3, nil))
	require.Error(t, err, "empty fragment payload must be rejected")
	assert.Nil(t, out)
}

// ESP-encapsulated fragments are routed to decapsulateIPv6FragmentESP by
// the capture loop, not here — but the defragmenter itself still accepts
// any next-header value, so a caller that does pass one through works.
func TestIPv6Defragmenter_NextHeaderPreserved(t *testing.T) {
	d := NewIPv6Defragmenter()
	ip6 := mkV6("2a03::1", "2a03::2")

	out, err := d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolTCP, 0, true, 1, bytes.Repeat([]byte{1}, 16)))
	require.NoError(t, err)
	require.Nil(t, out)
	out, err = d.DefragIPv6(ip6, mkV6Frag(layers.IPProtocolTCP, 2, false, 1, bytes.Repeat([]byte{2}, 8)))
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, layers.IPProtocolTCP, out.NextHeader, "inner protocol must be preserved")
}
