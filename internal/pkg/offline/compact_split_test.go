package offline

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompactSplitRowMatchesCodec(t *testing.T) {
	const max = 1 << 20
	for presence := uint8(0); presence < 32; presence++ {
		row := compactRow{
			Sequence: 1 << 40, Locator: Locator{BackingID: 2, Offset: 1234, Digest: [32]byte{1, 2}},
			Timestamp: time.Unix(-12, 999999999).UTC(), SrcIP: "::ffff:192.0.2.1", DstPort: "0",
			Info: "INVITE sip:bob@example.com", Derived: true,
			Projection: compactProjection{Presence: presence, User: "alice", IsRTP: true, QueryName: "example.com", AnswerPresent: true, SNI: "tls.example.com", Path: "/test", ContentLength: -1},
		}
		encoded, err := encodeCompactValue(row, max)
		require.NoError(t, err)
		data := append(make([]byte, 16), encoded...)
		parts, err := compactSplitRow(1, data, max)
		require.NoError(t, err)
		want, err := encodeCompactFields(row, max)
		require.NoError(t, err)
		require.Equal(t, want, parts[2:])
		require.Equal(t, data, bytes.Join(parts, nil))
		// All fields alias the original admitted row; no field bytes are copied.
		offset := 0
		for _, part := range parts {
			if len(part) > 0 {
				require.Same(t, &data[offset], &part[0])
			}
			offset += len(part)
		}
		for end := 0; end < len(data); end++ {
			_, err := compactSplitRow(1, data[:end], max)
			require.Error(t, err, "presence=%d end=%d", presence, end)
		}
		_, err = compactSplitRow(1, append(data, 0), max)
		require.Error(t, err)
	}
}

func TestCompactSplitRowRejectsMalformedValues(t *testing.T) {
	const max = 1 << 20
	row := compactRow{Timestamp: time.Unix(0, 0).UTC(), Info: strings.Repeat("x", 1024)}
	encoded, err := encodeCompactValue(row, max)
	require.NoError(t, err)
	data := append(make([]byte, 16), encoded...)
	parts, err := compactSplitRow(1, data, max)
	require.NoError(t, err)
	for _, name := range []string{"Timestamp", "Derived", "Projection", "Info"} {
		t.Run(name, func(t *testing.T) {
			copyParts := make([][]byte, len(parts))
			for i, p := range parts {
				copyParts[i] = bytes.Clone(p)
			}
			for i, field := range compactFieldNames[reflect.TypeOf(compactRow{})] {
				if field != name {
					continue
				}
				p := copyParts[i+2]
				if name == "Timestamp" {
					for j := 8; j < 12; j++ {
						p[j] = 255
					}
				} else {
					p[0] = 255
				}
			}
			bad := bytes.Join(copyParts, nil)
			var decoded compactRow
			require.Error(t, decodeCompactValue(bad[16:], &decoded, max))
			_, err := compactSplitRow(1, bad, max)
			require.Error(t, err)
		})
	}
	// Encoded size alone fits; the decoded row's strings and fixed graph do not.
	var decoded compactRow
	budget := uint64(len(encoded))
	require.Error(t, decodeCompactValue(encoded, &decoded, budget))
	_, err = compactSplitRow(1, data, budget)
	require.Error(t, err)
}

func BenchmarkCompactSplitRow(b *testing.B) {
	const max = 1 << 20
	row := compactRow{Timestamp: time.Unix(1700000000, 1234).UTC(), SrcIP: "192.0.2.1", DstIP: "198.51.100.2", Protocol: "RTP", Info: "RTP audio", Projection: compactProjection{Presence: 1, IsRTP: true, CallID: "call", Codec: "PCMU"}}
	encoded, err := encodeCompactValue(row, max)
	require.NoError(b, err)
	data := append(make([]byte, 16), encoded...)
	b.Run("zero-copy", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := compactSplitRow(1, data, max)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("decode-encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var decoded compactRow
			if err := decodeCompactValue(data[16:], &decoded, max); err != nil {
				b.Fatal(err)
			}
			if _, err := encodeCompactFields(decoded, max); err != nil {
				b.Fatal(err)
			}
		}
	})
}
