package ntp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func packet(mode byte) []byte {
	p := make([]byte, 48)
	p[0] = 4<<3 | mode
	return p
}

func TestDecodeExactFields(t *testing.T) {
	p := packet(4)
	p[0] |= 3 << 6
	p[1], p[2], p[3] = 255, 255, 127
	binary.BigEndian.PutUint32(p[4:8], 0xffff8000)
	binary.BigEndian.PutUint32(p[8:12], 0xffffffff)
	copy(p[12:16], []byte{0, 255, 10, 128})
	for i := 16; i < 48; i += 8 {
		binary.BigEndian.PutUint64(p[i:i+8], 0xe123456780000001+uint64(i))
	}
	o, err := Decode(p, time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Equal(t, uint8(4), o.Version)
	require.Equal(t, uint8(3), o.LeapIndicator)
	require.Equal(t, int8(-1), o.Poll)
	require.Equal(t, int8(127), o.Precision)
	require.Equal(t, int32(-32768), o.RootDelay)
	require.Equal(t, uint32(0xffffffff), o.RootDispersion)
	require.Equal(t, [4]byte{0, 255, 10, 128}, o.ReferenceID)
	for i, ts := range []Timestamp{o.Reference, o.Origin, o.Receive, o.Transmit} {
		require.Equal(t, uint64(0xe123456780000001)+uint64(16+i*8), ts.Raw)
	}
	require.False(t, o.Partial)
}

func TestTimestampEraAndZero(t *testing.T) {
	boundary := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	require.True(t, ResolveTimestamp(0, boundary).Time.IsZero())
	require.True(t, ResolveTimestamp(1, time.Time{}).Time.IsZero())
	require.Equal(t, boundary.Add(500*time.Millisecond), ResolveTimestamp(1<<31, boundary).Time)
	require.Equal(t, boundary.Add(-time.Second), ResolveTimestamp(uint64(0xffffffff)<<32, boundary).Time)
	require.Equal(t, boundary.Add(time.Second), ResolveTimestamp(uint64(1)<<32, boundary.Add(-time.Second)).Time)
	require.Equal(t, time.Date(1900, 1, 1, 0, 0, 1, 0, time.UTC), ResolveTimestamp(uint64(1)<<32, time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)).Time)
}

func TestDecodeRolesReferenceAndUnsupported(t *testing.T) {
	for mode := byte(0); mode < 8; mode++ {
		o, err := Decode(packet(mode), time.Time{})
		if mode < 1 || mode > 5 {
			require.ErrorIs(t, err, ErrUnsupported)
		} else {
			require.NoError(t, err)
			require.NotEqual(t, "unknown", o.Role())
		}
	}
	for size := 0; size < 48; size++ {
		_, err := Decode(make([]byte, size), time.Time{})
		require.ErrorIs(t, err, ErrShortHeader)
	}
	for _, version := range []byte{0, 5, 6, 7} {
		p := packet(3)
		p[0] = version<<3 | 3
		_, err := Decode(p, time.Time{})
		require.ErrorIs(t, err, ErrUnsupported)
	}
	for _, tc := range []struct {
		stratum, version byte
		kind             string
	}{{0, 4, "kiss_code"}, {1, 4, "clock_id"}, {2, 4, "ipv4_or_hash"}, {2, 3, "ipv4"}, {16, 4, "opaque"}} {
		require.Equal(t, tc.kind, (Observation{Stratum: tc.stratum, Version: tc.version}).ReferenceIDKind())
	}
}

func TestDecodeBoundedTails(t *testing.T) {
	for _, size := range []int{4, 20, 24} {
		o, err := Decode(append(packet(3), make([]byte, size)...), time.Time{})
		require.NoError(t, err)
		require.False(t, o.Partial)
	}
	ext := make([]byte, 16)
	binary.BigEndian.PutUint16(ext[2:4], 16)
	o, err := Decode(append(packet(3), ext...), time.Time{})
	require.NoError(t, err)
	require.Equal(t, uint16(1), o.ExtensionCount)
	require.False(t, o.Partial)
	for _, tc := range []struct {
		tail      []byte
		truncated bool
	}{{[]byte{1}, true}, {make([]byte, 8), false}, {append([]byte{0, 0, 0, 32}, make([]byte, 12)...), true}, {make([]byte, MaxPacketSize), true}} {
		o, err := Decode(append(packet(3), tc.tail...), time.Time{})
		require.NoError(t, err)
		require.True(t, o.Partial)
		require.Equal(t, tc.truncated, o.Truncated)
	}
	p := packet(3)
	for i := 0; i < MaxExtensions+1; i++ {
		p = append(p, ext...)
	}
	o, err = Decode(p, time.Time{})
	require.NoError(t, err)
	require.True(t, o.Truncated)
	require.Equal(t, uint16(MaxExtensions), o.ExtensionCount)
}

func FuzzDecode(f *testing.F) {
	f.Add(packet(3))
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, p []byte) { _, _ = Decode(p, time.Unix(1790985600, 0)) })
}
