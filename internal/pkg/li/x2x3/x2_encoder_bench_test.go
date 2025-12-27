package x2x3

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// BenchmarkX2Encoder_EncodeIRI benchmarks X2 IRI encoding for different SIP message types.
func BenchmarkX2Encoder_EncodeIRI(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	testCases := []struct {
		name string
		pkt  *types.PacketDisplay
	}{
		{
			name: "SessionBegin_INVITE",
			pkt: &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.200",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID:  "abc123@192.168.1.100",
					Method:  "INVITE",
					From:    "alice@example.com",
					To:      "bob@example.com",
					FromTag: "tag-from-123",
				},
			},
		},
		{
			name: "SessionAnswer_200OK",
			pkt: &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.200",
				DstIP:     "192.168.1.100",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID:  "abc123@192.168.1.100",
					Status:  200,
					From:    "alice@example.com",
					To:      "bob@example.com",
					FromTag: "tag-from-123",
					ToTag:   "tag-to-456",
				},
			},
		},
		{
			name: "SessionEnd_BYE",
			pkt: &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.200",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID:  "abc123@192.168.1.100",
					Method:  "BYE",
					From:    "alice@example.com",
					To:      "bob@example.com",
					FromTag: "tag-from-123",
					ToTag:   "tag-to-456",
				},
			},
		},
		{
			name: "Registration_REGISTER",
			pkt: &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "192.168.1.100",
				DstIP:     "192.168.1.1",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID: "reg123@192.168.1.100",
					Method: "REGISTER",
					From:   "alice@example.com",
					To:     "alice@example.com",
				},
			},
		},
		{
			name: "IPv6_INVITE",
			pkt: &types.PacketDisplay{
				Timestamp: time.Now(),
				SrcIP:     "2001:db8::1",
				DstIP:     "2001:db8::2",
				SrcPort:   "5060",
				DstPort:   "5060",
				Protocol:  "SIP",
				VoIPData: &types.VoIPMetadata{
					CallID:  "ipv6-call@example.com",
					Method:  "INVITE",
					From:    "alice@example.com",
					To:      "bob@example.com",
					FromTag: "tag-ipv6",
				},
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := encoder.EncodeIRI(tc.pkt, xid)
				if err != nil {
					b.Fatalf("EncodeIRI failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkX2Encoder_EncodeIRI_Parallel benchmarks X2 IRI encoding under concurrent load.
func BenchmarkX2Encoder_EncodeIRI_Parallel(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "INVITE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encoder.EncodeIRI(pkt, xid)
			if err != nil {
				b.Fatalf("EncodeIRI failed: %v", err)
			}
		}
	})
}

// BenchmarkX2Encoder_EncodeAndSerialize benchmarks the full encode + serialize path.
func BenchmarkX2Encoder_EncodeAndSerialize(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "INVITE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	var totalBytes int64
	for i := 0; i < b.N; i++ {
		pdu, err := encoder.EncodeIRI(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeIRI failed: %v", err)
		}

		data, err := pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
		totalBytes += int64(len(data))
	}

	b.ReportMetric(float64(totalBytes)/float64(b.N), "bytes/op")
}

// BenchmarkX2Encoder_EncodeAndSerialize_Parallel benchmarks concurrent encode + serialize.
func BenchmarkX2Encoder_EncodeAndSerialize_Parallel(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "INVITE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pdu, err := encoder.EncodeIRI(pkt, xid)
			if err != nil {
				b.Fatalf("EncodeIRI failed: %v", err)
			}

			_, err = pdu.MarshalBinary()
			if err != nil {
				b.Fatalf("MarshalBinary failed: %v", err)
			}
		}
	})
}

// BenchmarkX2Encoder_Throughput measures throughput in IRI events per second.
func BenchmarkX2Encoder_Throughput(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	// Create a mix of SIP message types to simulate realistic traffic.
	packets := []*types.PacketDisplay{
		// INVITE
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			SrcPort:   "5060",
			DstPort:   "5060",
			VoIPData: &types.VoIPMetadata{
				CallID:  "call1@192.168.1.100",
				Method:  "INVITE",
				From:    "alice@example.com",
				To:      "bob@example.com",
				FromTag: "tag-from-1",
			},
		},
		// 200 OK
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.200",
			DstIP:     "192.168.1.100",
			SrcPort:   "5060",
			DstPort:   "5060",
			VoIPData: &types.VoIPMetadata{
				CallID:  "call1@192.168.1.100",
				Status:  200,
				From:    "alice@example.com",
				To:      "bob@example.com",
				FromTag: "tag-from-1",
				ToTag:   "tag-to-1",
			},
		},
		// BYE
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			SrcPort:   "5060",
			DstPort:   "5060",
			VoIPData: &types.VoIPMetadata{
				CallID:  "call1@192.168.1.100",
				Method:  "BYE",
				From:    "alice@example.com",
				To:      "bob@example.com",
				FromTag: "tag-from-1",
				ToTag:   "tag-to-1",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		pkt := packets[i%len(packets)]
		pdu, err := encoder.EncodeIRI(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeIRI failed: %v", err)
		}
		_, err = pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
	}
	elapsed := time.Since(start)

	iriPerSecond := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(iriPerSecond, "IRI/s")
}

// BenchmarkX2Encoder_VaryingCallIDs benchmarks encoding with many different Call-IDs.
// This tests the FNV hash performance for correlation ID generation.
func BenchmarkX2Encoder_VaryingCallIDs(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	// Pre-generate packets with different Call-IDs.
	numCallIDs := 1000
	packets := make([]*types.PacketDisplay, numCallIDs)
	for i := 0; i < numCallIDs; i++ {
		packets[i] = &types.PacketDisplay{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			SrcPort:   "5060",
			DstPort:   "5060",
			VoIPData: &types.VoIPMetadata{
				CallID:  fmt.Sprintf("call-%d@192.168.1.100", i),
				Method:  "INVITE",
				From:    "alice@example.com",
				To:      "bob@example.com",
				FromTag: fmt.Sprintf("tag-from-%d", i),
			},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pkt := packets[i%numCallIDs]
		_, err := encoder.EncodeIRI(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeIRI failed: %v", err)
		}
	}
}

// BenchmarkX2Encoder_LongSIPHeaders benchmarks encoding with long SIP headers.
// This tests TLV encoding performance with larger attribute values.
func BenchmarkX2Encoder_LongSIPHeaders(b *testing.B) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	// Create packet with long SIP header values.
	longCallID := "very-long-call-id-with-many-characters-to-simulate-real-world-sip-traffic-" +
		"that-includes-domain-names-and-additional-parameters@sip.very-long-domain-name.example.com"
	longFrom := "\"Alice Wonderland with a very long display name\" <sip:alice.wonderland.user@very-long-domain-name.example.com;transport=tls>"
	longTo := "\"Bob Builder with equally long display name\" <sip:bob.builder.recipient@another-long-domain-name.example.org;transport=tls>"

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		VoIPData: &types.VoIPMetadata{
			CallID:  longCallID,
			Method:  "INVITE",
			From:    longFrom,
			To:      longTo,
			FromTag: "very-long-from-tag-with-additional-characters-12345678901234567890",
			ToTag:   "very-long-to-tag-with-additional-characters-09876543210987654321",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pdu, err := encoder.EncodeIRI(pkt, xid)
		if err != nil {
			b.Fatalf("EncodeIRI failed: %v", err)
		}
		_, err = pdu.MarshalBinary()
		if err != nil {
			b.Fatalf("MarshalBinary failed: %v", err)
		}
	}
}
