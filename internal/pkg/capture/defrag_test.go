package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createIPv4Fragment creates a mock IPv4 fragment for testing
func createIPv4Fragment(srcIP, dstIP string, id uint16, offset uint16, moreFragments bool, payload []byte) *layers.IPv4 {
	var flags layers.IPv4Flag
	if moreFragments {
		flags = layers.IPv4MoreFragments
	}

	// Calculate total length: IP header (20 bytes, IHL=5) + payload
	totalLen := uint16(20 + len(payload))

	ip := &layers.IPv4{
		Version:    4,
		IHL:        5, // 20 bytes
		TOS:        0,
		Length:     totalLen,
		Id:         id,
		Flags:      flags,
		FragOffset: offset / 8, // Convert bytes to 8-byte units
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	// Set payload via the embedded BaseLayer
	ip.BaseLayer.Payload = payload
	return ip
}

func TestIPv4Defragmenter_NonFragmentedPacket(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Non-fragmented packet (MF=0, offset=0)
	pkt := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, false, []byte("hello world"))

	result, err := d.DefragIPv4(pkt)

	require.NoError(t, err)
	assert.Same(t, pkt, result, "non-fragmented packet should be returned unchanged")
}

func TestIPv4Defragmenter_DontFragmentFlag(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Packet with DF flag set
	pkt := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, false, []byte("hello world"))
	pkt.Flags = layers.IPv4DontFragment

	result, err := d.DefragIPv4(pkt)

	require.NoError(t, err)
	assert.Same(t, pkt, result, "DF-flagged packet should be returned unchanged")
}

func TestIPv4Defragmenter_TwoFragments(t *testing.T) {
	d := NewIPv4Defragmenter()

	// First fragment: offset=0, MF=1, 16 bytes payload
	frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, true, []byte("Hello, World!!! ")) // 16 bytes

	// Second fragment: offset=16 (in bytes), MF=0, 8 bytes payload
	frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 16, false, []byte("Testing!"))

	// Process first fragment - should return nil (waiting for more)
	result1, err := d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result1, "first fragment should return nil")

	// Process second fragment - should return reassembled packet
	result2, err := d.DefragIPv4(frag2)
	require.NoError(t, err)
	require.NotNil(t, result2, "second fragment should trigger reassembly")

	assert.Equal(t, []byte("Hello, World!!! Testing!"), result2.Payload)
	assert.Equal(t, uint16(0), result2.FragOffset)
	assert.Equal(t, layers.IPv4Flag(0), result2.Flags)
}

// TestIPv4Defragmenter_SmallFinalFragment tests the RFC 791 compliance fix.
// Final fragments (MF=0, offset > 0) can be any size, including < 8 bytes.
// This is the critical test for the gopacket bug fix.
func TestIPv4Defragmenter_SmallFinalFragment(t *testing.T) {
	d := NewIPv4Defragmenter()

	// First fragment: offset=0, MF=1, 1480 bytes payload (typical MTU fragment)
	// Simulating a large SIP INVITE
	payload1 := make([]byte, 1480)
	for i := range payload1 {
		payload1[i] = 'A'
	}
	frag1 := createIPv4Fragment("192.0.2.1", "198.51.100.1", 52914, 0, true, payload1)

	// Second fragment: offset=1480, MF=0, only 7 bytes payload
	// This is the RFC 791 compliance test - gopacket would reject this as "too small"
	// The 7 bytes represent the tail of a SIP message: "13\r\n\r\n" or similar
	payload2 := []byte("13\r\n\r\n") // 7 bytes - less than IPv4MinimumFragmentSize (8)
	frag2 := createIPv4Fragment("192.0.2.1", "198.51.100.1", 52914, 1480, false, payload2)

	// Process first fragment
	result1, err := d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result1)

	// Process second (small final) fragment - should NOT error
	result2, err := d.DefragIPv4(frag2)
	require.NoError(t, err, "small final fragment should be accepted per RFC 791")
	require.NotNil(t, result2, "should return reassembled packet")

	// Verify payload was reassembled correctly
	expectedLen := len(payload1) + len(payload2)
	assert.Len(t, result2.Payload, expectedLen)
	assert.Equal(t, payload2, result2.Payload[len(payload1):])
}

// TestIPv4Defragmenter_SmallNonFinalFragment tests that non-final fragments
// smaller than 8 bytes are correctly rejected (they violate RFC 791).
func TestIPv4Defragmenter_SmallNonFinalFragment(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Non-final fragment (MF=1) with only 4 bytes - should be rejected
	smallFrag := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, true, []byte("tiny"))

	_, err := d.DefragIPv4(smallFrag)
	assert.Error(t, err, "non-final fragment < 8 bytes should be rejected")
	assert.Contains(t, err.Error(), "non-final fragment too small")
}

func TestIPv4Defragmenter_OutOfOrder(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Create fragments that arrive out of order
	frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 5678, 0, true, []byte("AAAAAAAA")) // offset 0, 8 bytes
	frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 5678, 8, true, []byte("BBBBBBBB")) // offset 8, 8 bytes
	frag3 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 5678, 16, false, []byte("CCCC"))   // offset 16, 4 bytes (final)

	// Send in reverse order: 3, 1, 2
	result, err := d.DefragIPv4(frag3)
	require.NoError(t, err)
	assert.Nil(t, result)

	result, err = d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result)

	result, err = d.DefragIPv4(frag2)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, []byte("AAAAAAAABBBBBBBBCCCC"), result.Payload)
}

func TestIPv4Defragmenter_DuplicateFragment(t *testing.T) {
	d := NewIPv4Defragmenter()

	frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, true, []byte("AAAAAAAA"))
	frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 8, false, []byte("BBBB"))

	// Process first fragment
	result, err := d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Send duplicate of first fragment - should be ignored
	result, err = d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Complete with second fragment
	result, err = d.DefragIPv4(frag2)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, []byte("AAAAAAAABBBB"), result.Payload)
}

func TestIPv4Defragmenter_MultipleFlows(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Flow 1: ID 1000
	flow1_frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1000, 0, true, []byte("FLOW1_AA"))
	flow1_frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1000, 8, false, []byte("_END"))

	// Flow 2: ID 2000
	flow2_frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 2000, 0, true, []byte("FLOW2_BB"))
	flow2_frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", 2000, 8, false, []byte("_FIN"))

	// Interleave fragments from both flows
	d.DefragIPv4(flow1_frag1)
	d.DefragIPv4(flow2_frag1)

	result2, _ := d.DefragIPv4(flow2_frag2)
	result1, _ := d.DefragIPv4(flow1_frag2)

	require.NotNil(t, result1)
	require.NotNil(t, result2)

	assert.Equal(t, []byte("FLOW1_AA_END"), result1.Payload)
	assert.Equal(t, []byte("FLOW2_BB_FIN"), result2.Payload)
}

func TestIPv4Defragmenter_DiscardOlderThan(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Create a fragment but don't complete it
	frag := createIPv4Fragment("10.0.0.1", "10.0.0.2", 9999, 0, true, []byte("AAAAAAAA"))

	baseTime := time.Now()
	_, err := d.DefragIPv4WithTimestamp(frag, baseTime)
	require.NoError(t, err)

	// Flow should exist
	d.mu.Lock()
	assert.Len(t, d.ipFlows, 1)
	d.mu.Unlock()

	// Discard flows older than baseTime + 1 second
	count := d.DiscardOlderThan(baseTime.Add(time.Second))
	assert.Equal(t, 1, count)

	// Flow should be removed
	d.mu.Lock()
	assert.Len(t, d.ipFlows, 0)
	d.mu.Unlock()
}

func TestIPv4Defragmenter_FragmentOffsetTooLarge(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Create fragment with offset > maximum
	frag := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 0, true, []byte("AAAAAAAA"))
	frag.FragOffset = IPv4MaximumFragmentOffset + 1

	_, err := d.DefragIPv4(frag)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fragment offset too large")
}

func TestIPv4Defragmenter_ReassembledPacketWouldExceedMaxSize(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Create fragment where offset + length > IPv4MaximumSize
	frag := createIPv4Fragment("10.0.0.1", "10.0.0.2", 1234, 65000, true, []byte("AAAAAAAA"))
	// Manually set a large length that would overflow when combined with offset
	frag.Length = 1000

	_, err := d.DefragIPv4(frag)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "would exceed maximum IP size")
}

// TestIPv4Defragmenter_RealWorldSIPFragment simulates the actual case from
// the research document where a SIP INVITE fragments with a 7-byte final fragment.
func TestIPv4Defragmenter_RealWorldSIPFragment(t *testing.T) {
	d := NewIPv4Defragmenter()

	// Simulate actual packet from research document:
	// Frame 8032 (First fragment):
	//   IP ID: 0xceb2 (52914)
	//   Flags: 0x01 (MF=1)
	//   Frag Offset: 0
	//   IP Length: 1500

	// Frame 8033 (Final fragment):
	//   IP ID: 0xceb2 (52914)
	//   Flags: 0x00 (MF=0)
	//   Frag Offset: 185 (185 × 8 = 1480 bytes)
	//   IP Length: 27 (20 header + 7 payload)

	// Build SIP-like content
	sipHeaders := "INVITE sip:user@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: <sip:caller@example.com>;tag=1234\r\n" +
		"To: <sip:user@example.com>\r\n" +
		"Call-ID: test-call-id@example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 200\r\n\r\n" +
		"v=0\r\n" +
		"o=- 12345 12345 IN IP4 10.0.0.1\r\n" +
		"s=Test Session\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 28642 RTP/AVP 0 8 9 101 13"
	// Pad to exactly 1480 bytes for first fragment
	padding := make([]byte, 1480-len(sipHeaders))
	for i := range padding {
		padding[i] = ' '
	}
	payload1 := append([]byte(sipHeaders), padding...)

	// Final 7 bytes: end of SDP (simulates the tail of an SDP body)
	payload2 := []byte("101 13\n") // 7 bytes - represents remaining codec IDs

	frag1 := createIPv4Fragment("192.0.2.10", "198.51.100.10", 52914, 0, true, payload1)
	frag2 := createIPv4Fragment("192.0.2.10", "198.51.100.10", 52914, 1480, false, payload2)

	// Process fragments
	result1, err := d.DefragIPv4(frag1)
	require.NoError(t, err)
	assert.Nil(t, result1)

	result2, err := d.DefragIPv4(frag2)
	require.NoError(t, err, "7-byte final fragment must be accepted per RFC 791")
	require.NotNil(t, result2, "packet should be reassembled")

	// Verify the SDP content is intact
	assert.Contains(t, string(result2.Payload), "m=audio 28642")
	assert.Equal(t, 1487, len(result2.Payload), "expected 1480 + 7 = 1487 bytes")
}

// Benchmark for defragmentation performance
func BenchmarkIPv4Defragmenter_TwoFragments(b *testing.B) {
	d := NewIPv4Defragmenter()

	payload1 := make([]byte, 1480)
	payload2 := make([]byte, 520)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uint16(i % 65536)
		frag1 := createIPv4Fragment("10.0.0.1", "10.0.0.2", id, 0, true, payload1)
		frag2 := createIPv4Fragment("10.0.0.1", "10.0.0.2", id, 1480, false, payload2)

		d.DefragIPv4(frag1)
		d.DefragIPv4(frag2)
	}
}
