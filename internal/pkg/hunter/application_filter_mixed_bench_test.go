//go:build hunter || tap || all

package hunter

import (
	"fmt"
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BenchmarkApplicationFilterMixedVoIP is the regression baseline for a
// media-heavy VoIP workload. Packets and filters are entirely synthetic, and
// packet serialization happens before the timer so the benchmark measures the
// application-filter hot path rather than fixture construction.
func BenchmarkApplicationFilterMixedVoIP(b *testing.B) {
	filter := newMixedVoIPBenchmarkFilter(b)
	packets := mixedVoIPBenchmarkPackets(b)
	assertMixedVoIPBenchmarkClassification(b, filter, packets)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.MatchPacketWithIDs(packets[i%len(packets)])
	}
}

func assertMixedVoIPBenchmarkClassification(b *testing.B, filter *ApplicationFilter, packets []gopacket.Packet) {
	b.Helper()

	for i, packet := range packets {
		expected := "SIP"
		switch {
		case i < 80:
			expected = "RTP"
		case i < 90:
			// The centralized detector currently represents RTCP through its RTP classification path.
			expected = "RTP"
		}
		result := filter.detector.Detect(packet)
		if result == nil || result.Protocol != expected {
			b.Fatalf("packet %d: got classification %v, want %s", i, result, expected)
		}
	}
}

func newMixedVoIPBenchmarkFilter(tb testing.TB) *ApplicationFilter {
	tb.Helper()

	filter, err := NewApplicationFilter(nil)
	if err != nil {
		tb.Fatal(err)
	}

	// A few hundred identity filters are representative of a busy local tap and
	// make accidental identity parsing of binary media visible in B/op.
	filters := make([]*management.Filter, 0, 500)
	for i := 0; i < 125; i++ {
		filters = append(filters,
			&management.Filter{Id: fmt.Sprintf("sip-%03d", i), Type: management.FilterType_FILTER_SIP_USER, Pattern: fmt.Sprintf("synthetic-user-%03d", i)},
			&management.Filter{Id: fmt.Sprintf("phone-%03d", i), Type: management.FilterType_FILTER_PHONE_NUMBER, Pattern: fmt.Sprintf("1555000%04d", i)},
			&management.Filter{Id: fmt.Sprintf("imsi-%03d", i), Type: management.FilterType_FILTER_IMSI, Pattern: fmt.Sprintf("00101000000%04d", i)},
			&management.Filter{Id: fmt.Sprintf("imei-%03d", i), Type: management.FilterType_FILTER_IMEI, Pattern: fmt.Sprintf("99000000000%04d", i)},
		)
	}
	filter.UpdateFilters(filters)
	return filter
}

func TestApplicationFilterClassifiedRTPPacketLevelAllocationCeiling(t *testing.T) {
	filter := newMixedVoIPBenchmarkFilter(t)
	packet := mixedVoIPBenchmarkPackets(t)[0]

	allocs := testing.AllocsPerRun(1000, func() {
		matched, ids := filter.MatchPacketLevelWithIDs(packet)
		if matched || len(ids) != 0 {
			t.Fatalf("classified RTP unexpectedly matched: matched=%t ids=%v", matched, ids)
		}
	})
	if allocs > 0 {
		t.Fatalf("classified RTP packet-level filtering allocations/run = %.1f, want 0", allocs)
	}
}

func mixedVoIPBenchmarkPackets(tb testing.TB) []gopacket.Packet {
	tb.Helper()

	packets := make([]gopacket.Packet, 0, 100)
	for i := 0; i < 80; i++ {
		payload := make([]byte, 172)
		payload[0] = 0x80 // RTP version 2
		payload[1] = 0x00 // PCMU payload type
		sequence := i + 1
		payload[2] = byte(sequence >> 8)
		payload[3] = byte(sequence)
		payload[4], payload[5], payload[6], payload[7] = 0, 0, byte(sequence), 0x40
		payload[8], payload[9], payload[10], payload[11] = 0x12, 0x34, 0x56, 0x78
		packets = append(packets, serializeMixedVoIPBenchmarkPacket(tb, 10000, 20000, payload))
	}
	for i := 0; i < 10; i++ {
		// Minimal synthetic RTCP sender report: version 2, PT 200, six words.
		payload := []byte{0x80, 200, 0x00, 0x06, 0, 0, 0, byte(i + 1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		packets = append(packets, serializeMixedVoIPBenchmarkPacket(tb, 10001, 20001, payload))
	}
	for i := 0; i < 10; i++ {
		payload := []byte(fmt.Sprintf("INVITE sip:peer-%02d@synthetic.invalid SIP/2.0\r\nFrom: <sip:caller-%02d@synthetic.invalid>\r\nTo: <sip:peer-%02d@synthetic.invalid>\r\nCall-ID: synthetic-call-%02d\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", i, i, i, i))
		packets = append(packets, serializeMixedVoIPBenchmarkPacket(tb, 5060, 5060, payload))
	}
	return packets
}

func serializeMixedVoIPBenchmarkPacket(tb testing.TB, srcPort, dstPort layers.UDPPort, payload []byte) gopacket.Packet {
	tb.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		tb.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		tb.Fatal(err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
