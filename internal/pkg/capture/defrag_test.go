package capture

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPv4DefragmenterConcurrentFragmentsAndCleanup(t *testing.T) {
	d := NewIPv4Defragmenter()
	base := time.Unix(100, 0)
	for run := 0; run < 50; run++ {
		id := uint16(run)
		first := createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 0, true, []byte("AAAAAAAA"))
		middle := createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 8, true, []byte("BBBBBBBB"))
		final := createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 16, false, []byte("CCCC"))
		_, err := d.DefragIPv4WithTimestamp(first, base)
		require.NoError(t, err)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := d.DefragIPv4WithTimestamp(middle, base.Add(2*time.Second)); err != nil {
				t.Errorf("insert middle: %v", err)
			}
		}()
		wg.Add(1)
		go func() { defer wg.Done(); <-start; d.DiscardOlderThan(base.Add(time.Second)) }()
		close(start)
		wg.Wait()
		// A stale sweep may win and remove the first fragment, or insertion may
		// refresh it first. In either order, the fresh middle must remain live.
		_, err = d.DefragIPv4WithTimestamp(first, base.Add(2*time.Second))
		require.NoError(t, err)
		out, err := d.DefragIPv4WithTimestamp(final, base.Add(2*time.Second))
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, []byte("AAAAAAAABBBBBBBBCCCC"), out.Payload)
	}
	require.Equal(t, 0, d.Snapshot().InFlightDatagrams)
	// Force the removal-first order too, independent of scheduler luck.
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 99, 0, true, []byte("AAAAAAAA"))
	_, err := d.DefragIPv4WithTimestamp(first, base)
	require.NoError(t, err)
	require.Equal(t, 1, d.DiscardOlderThan(base.Add(time.Second)))
	_, err = d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 99, 8, false, []byte("DONE")), base.Add(2*time.Second))
	require.NoError(t, err)
	result, err := d.DefragIPv4WithTimestamp(first, base.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, []byte("AAAAAAAADONE"), result.Payload)
}

func TestIPv4DefragmenterBoundsAndRecovery(t *testing.T) {
	d, err := NewIPv4DefragmenterWithConfig(IPv4DefragConfig{MaxDatagrams: 2, MaxFragments: 3, MaxPayloadBytes: 24, MaxFragmentsPerDatagram: 2})
	require.NoError(t, err)
	base := time.Unix(100, 0)
	for id := uint16(1); id <= 3; id++ {
		_, err := d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 0, true, []byte("AAAAAAAA")), base.Add(time.Duration(id)*time.Second))
		require.NoError(t, err)
		s := d.Snapshot()
		require.LessOrEqual(t, s.InFlightDatagrams, 2)
		require.LessOrEqual(t, s.InFlightFragments, 3)
		require.LessOrEqual(t, s.InFlightPayloadBytes, 24)
	}
	require.Equal(t, uint64(1), d.Snapshot().CapacityEvictions)
	_, err = d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 3, 8, true, []byte("BBBBBBBB")), base.Add(4*time.Second))
	require.NoError(t, err)
	_, err = d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 3, 16, false, []byte("CCCC")), base.Add(5*time.Second))
	require.ErrorContains(t, err, "fragment list exceeded maximum")
	_, err = d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 4, 0, true, []byte("AAAAAAAA")), base.Add(6*time.Second))
	require.NoError(t, err)
	result, err := d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 4, 8, false, []byte("CCCC")), base.Add(7*time.Second))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, []byte("AAAAAAAACCCC"), result.Payload)
}

func TestIPv4DefragmenterCapacityProtectsIncomingExistingFlow(t *testing.T) {
	d, err := NewIPv4DefragmenterWithConfig(IPv4DefragConfig{MaxDatagrams: 2, MaxFragments: 2, MaxPayloadBytes: 16, MaxFragmentsPerDatagram: 2})
	require.NoError(t, err)
	base := time.Unix(100, 0)
	for _, id := range []uint16{1, 2} {
		_, err := d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 0, true, []byte("AAAAAAAA")), base.Add(time.Duration(id)*time.Second))
		require.NoError(t, err)
	}
	result, err := d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 1, 8, false, []byte("DONE")), base.Add(3*time.Second))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, []byte("AAAAAAAADONE"), result.Payload)
	snapshot := d.Snapshot()
	require.Equal(t, uint64(1), snapshot.CompletedDatagrams)
	require.Equal(t, uint64(1), snapshot.CapacityEvictions)
	require.Zero(t, snapshot.InFlightDatagrams)
}

func TestIPv4DefragmenterRejectsWhenOnlyProtectedFlowRemains(t *testing.T) {
	d, err := NewIPv4DefragmenterWithConfig(IPv4DefragConfig{MaxDatagrams: 1, MaxFragments: 2, MaxPayloadBytes: 8, MaxFragmentsPerDatagram: 2})
	require.NoError(t, err)
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 1, 0, true, []byte("AAAAAAAA"))
	_, err = d.DefragIPv4(first)
	require.NoError(t, err)
	_, err = d.DefragIPv4(createIPv4Fragment("192.0.2.1", "198.51.100.1", 1, 8, false, []byte("DONE")))
	require.ErrorContains(t, err, "protected datagram exceeds capacity")
	snapshot := d.Snapshot()
	require.Equal(t, 1, snapshot.InFlightDatagrams)
	require.Equal(t, 1, snapshot.InFlightFragments)
	require.Equal(t, 8, snapshot.InFlightPayloadBytes)
	require.Zero(t, snapshot.CapacityEvictions)
	require.Equal(t, uint64(1), snapshot.RejectedFragments)
}

func TestIPv4DefragmenterImpossibleProtectedGrowthDoesNotEvictOtherFlows(t *testing.T) {
	for _, tc := range []struct {
		name              string
		config            IPv4DefragConfig
		first             []byte
		second            []byte
		shrinkFragmentCap bool
	}{
		{"payload bytes", IPv4DefragConfig{MaxDatagrams: 2, MaxFragments: 3, MaxPayloadBytes: 24, MaxFragmentsPerDatagram: 2}, []byte("AAAAAAAAAAAAAAAA"), []byte("BBBBBBBBBBBBBBBB"), false},
		{"fragment count", IPv4DefragConfig{MaxDatagrams: 2, MaxFragments: 2, MaxPayloadBytes: 24, MaxFragmentsPerDatagram: 2}, []byte("AAAAAAAA"), []byte("BBBBBBBB"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewIPv4DefragmenterWithConfig(tc.config)
			require.NoError(t, err)
			a := createIPv4Fragment("192.0.2.1", "198.51.100.1", 1, 0, true, tc.first)
			b := createIPv4Fragment("192.0.2.1", "198.51.100.1", 2, 0, true, []byte("BBBBBBBB"))
			_, err = d.DefragIPv4(a)
			require.NoError(t, err)
			_, err = d.DefragIPv4(b)
			require.NoError(t, err)
			if tc.shrinkFragmentCap {
				// With a fixed cap, A alone cannot already consume every fragment
				// slot while B exists. Simulate a lowered cap to exercise the guard.
				d.mu.Lock()
				d.config.MaxFragments = 1
				d.mu.Unlock()
			}
			_, err = d.DefragIPv4(createIPv4Fragment("192.0.2.1", "198.51.100.1", 1, uint16(len(tc.first)), false, tc.second))
			require.ErrorContains(t, err, "protected datagram exceeds capacity")
			snapshot := d.Snapshot()
			require.Equal(t, 2, snapshot.InFlightDatagrams)
			require.Zero(t, snapshot.CapacityEvictions)
			require.Equal(t, uint64(1), snapshot.RejectedFragments)
			d.mu.Lock()
			require.NotNil(t, d.ipFlows[ipv4FlowKey{flow: b.NetworkFlow(), id: b.Id, protocol: b.Protocol}])
			d.mu.Unlock()
		})
	}
}

func TestIPv4DefragmenterExpiryUsesLatestTimestamp(t *testing.T) {
	d := NewIPv4Defragmenter()
	base := time.Unix(100, 0)
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 42, 0, true, []byte("AAAAAAAA"))
	_, err := d.DefragIPv4WithTimestamp(first, base.Add(10*time.Second))
	require.NoError(t, err)
	_, err = d.DefragIPv4WithTimestamp(createIPv4Fragment("192.0.2.1", "198.51.100.1", 42, 8, true, []byte("BBBBBBBB")), base)
	require.NoError(t, err)
	require.Zero(t, d.DiscardOlderThan(base.Add(5*time.Second)))
	require.Equal(t, 1, d.Snapshot().InFlightDatagrams)
	require.Equal(t, 1, d.DiscardOlderThan(base.Add(11*time.Second)))
	require.Equal(t, uint64(1), d.Snapshot().ExpiredDatagrams)
}

func TestIPv4DefragmenterStaleRemovalCannotDeleteReplacement(t *testing.T) {
	d := NewIPv4Defragmenter()
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 42, 0, true, []byte("AAAAAAAA"))
	_, err := d.DefragIPv4(first)
	require.NoError(t, err)
	key := ipv4FlowKey{flow: first.NetworkFlow(), id: first.Id, protocol: first.Protocol}
	d.mu.Lock()
	stale := d.ipFlows[key]
	require.True(t, d.removeLocked(stale))
	d.mu.Unlock()
	_, err = d.DefragIPv4(first)
	require.NoError(t, err)
	d.mu.Lock()
	require.False(t, d.removeLocked(stale))
	require.NotNil(t, d.ipFlows[key])
	d.mu.Unlock()
	require.Equal(t, 1, d.Snapshot().InFlightDatagrams)
}

func TestIPv4DefragmenterOverlapDoesNotOvercountRetention(t *testing.T) {
	d := NewIPv4Defragmenter()
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 73, 0, true, []byte("ABCDEFGHIJKLMNOP"))
	overlap := createIPv4Fragment("192.0.2.1", "198.51.100.1", 73, 8, false, []byte("xxxxxxxxYYYY"))
	_, err := d.DefragIPv4(first)
	require.NoError(t, err)
	result, err := d.DefragIPv4(overlap)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, []byte("ABCDEFGHIJKLMNOPYYYY"), result.Payload)
	snapshot := d.Snapshot()
	require.Zero(t, snapshot.InFlightFragments)
	require.Zero(t, snapshot.InFlightPayloadBytes)
	require.Equal(t, uint64(1), snapshot.CompletedDatagrams)
}

func BenchmarkIPv4DefragmenterNonFragmented(b *testing.B) {
	d := NewIPv4Defragmenter()
	packet := createIPv4Fragment("192.0.2.1", "198.51.100.1", 7, 0, false, []byte("AAAAAAAA"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.DefragIPv4(packet)
	}
}

func BenchmarkIPv4DefragmenterFirstFragmentFlood(b *testing.B) {
	d := NewIPv4Defragmenter()
	payload := make([]byte, 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packet := createIPv4Fragment("192.0.2.1", "198.51.100.1", uint16(i), 0, true, payload)
		_, _ = d.DefragIPv4(packet)
	}
}

func BenchmarkIPv4DefragmenterParallelFragments(b *testing.B) {
	d := NewIPv4Defragmenter()
	var next atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := uint16(next.Add(1))
			first := createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 0, true, []byte("AAAAAAAA"))
			last := createIPv4Fragment("192.0.2.1", "198.51.100.1", id, 8, false, []byte("BBBB"))
			_, _ = d.DefragIPv4(first)
			_, _ = d.DefragIPv4(last)
		}
	})
}

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
