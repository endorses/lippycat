package offline

import (
	"testing"
	"time"
)

func BenchmarkCompactValueCodec(b *testing.B) {
	row := compactRow{Argument: 3, Sequence: 10000, Locator: Locator{BackingID: 1, Offset: 4096, Length: 128}, Timestamp: time.Unix(1700000000, 1234).UTC(), SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "5060", DstPort: "5060", Protocol: "SIP", Info: "INVITE sip:bob@example.com", Projection: compactProjection{Presence: 1, User: "alice", From: "alice@example.com", To: "bob@example.com", CallID: "test-call", Method: "INVITE"}}
	wire, err := encodeCompactValue(row, 1<<20)
	if err != nil {
		b.Fatal(err)
	}
	columns, err := encodeCompactFields(row, 1<<20)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := encodeCompactValue(row, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("EncodeStoredRow", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := encodeCompactRow(&row, 1<<20, 16); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var result compactRow
			if err := decodeCompactValue(wire, &result, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("EncodeColumns", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := encodeCompactFields(row, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("DecodeColumns", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var result compactRow
			if err := decodeCompactFields(columns, &result, 1<<20); err != nil {
				b.Fatal(err)
			}
		}
	})
}
