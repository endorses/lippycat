package radius

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestIPOptionBoundaries(t *testing.T) {
	for _, options := range [][]byte{nil, {1}, {0, 255}, {1, 2, 2}, {99, 4, 0xff, 0xff, 1}} {
		require.NoError(t, validateIPv4Options(options))
	}
	for _, options := range [][]byte{{2}, {2, 0}, {2, 1}, {2, 255, 0, 0}, {1, 2}} {
		require.ErrorIs(t, validateIPv4Options(options), ErrMalformed)
	}
	for _, options := range [][]byte{nil, {0}, {1, 0}, {99, 2, 0xff, 0xff, 0}} {
		require.NoError(t, validateIPv6Options(options))
	}
	for _, options := range [][]byte{{2}, {2, 255, 0, 0}, {1, 1}, {0, 2}} {
		require.ErrorIs(t, validateIPv6Options(options), ErrMalformed)
	}
}

func TestMalformedIPOptionsCannotExposeRadiusIdentity(t *testing.T) {
	for _, version := range []byte{4, 6} {
		for _, extension := range []byte{0, 60} {
			b := testIPPacket(version == 6, 1812)
			if version == 4 {
				b = append(b[:20], append([]byte{2, 255, 0, 0}, b[20:]...)...)
				b[0] = 0x46
				binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
			} else {
				b = append(b[:40], append([]byte{17, 0, 2, 255, 0, 0, 0, 0}, b[40:]...)...)
				b[6] = extension
				binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
			}
			ci := gopacket.CaptureInfo{CaptureLength: len(b), Length: len(b)}
			o, outcome, err := DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
			require.ErrorIs(t, err, ErrMalformed)
			require.Equal(t, OutcomeMalformed, outcome)
			require.Nil(t, o.Message)
			require.Empty(t, o.NAS)
			require.Empty(t, o.Direct)
			require.Empty(t, o.Inherited)
			// Visible fragments retain priority even when option TLVs are bad.
			if version == 4 {
				binary.BigEndian.PutUint16(b[6:8], 0x2000)
			} else {
				b[40] = 44
			}
			_, outcome, err = DecodePacket(b, layers.LinkTypeRaw, ci, CaptureScope{}, Identity{})
			require.ErrorIs(t, err, ErrFragmented)
			require.Equal(t, OutcomeFragmented, outcome)
		}
	}
}
