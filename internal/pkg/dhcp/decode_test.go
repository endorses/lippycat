package dhcp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func packet(kind byte, options ...byte) []byte {
	b := make([]byte, 240)
	b[0] = 1
	if kind == 2 || kind == 5 || kind == 6 {
		b[0] = 2
	}
	b[1] = 1
	b[2] = 6
	binary.BigEndian.PutUint32(b[4:8], 1234)
	copy(b[28:34], []byte{1, 2, 3, 4, 5, 6})
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	b = append(b, 53, 1, kind)
	return append(b, options...)
}

func TestDecodeSemanticFieldsAndOwnership(t *testing.T) {
	b := packet(3, 61, 4, 0, 0xff, 0, 1, 12, 4, 'h', 'o', 's', 't', 15, 3, 'l', 'a', 'n', 50, 4, 192, 0, 2, 5, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0, 60, 3, 4, 192, 0, 2, 2, 6, 8, 192, 0, 2, 3, 192, 0, 2, 4, 55, 3, 1, 3, 6, 255)
	copy(b[20:24], []byte{192, 0, 2, 99})
	m, err := Decode(b)
	require.NoError(t, err)
	require.Equal(t, uint32(1234), m.TransactionID)
	require.Equal(t, RoleRequest, m.Role())
	require.Equal(t, []byte{0, 255, 0, 1}, m.ClientIdentifier)
	require.Equal(t, "host", m.Hostname)
	require.Equal(t, "lan", m.Domain)
	require.Equal(t, netip.MustParseAddr("192.0.2.99"), m.NextServerAddress)
	require.Equal(t, netip.MustParseAddr("192.0.2.1"), m.ServerIdentifier)
	require.Equal(t, netip.MustParseAddr("192.0.2.5"), m.RequestedAddress)
	require.Equal(t, uint32(60), *m.LeaseSeconds)
	require.Len(t, m.Routers, 1)
	require.Len(t, m.DNSServers, 2)
	require.Equal(t, []byte{1, 3, 6}, m.ParameterRequestList)
	clear(b)
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6}, m.HardwareAddress)
	require.Equal(t, []byte{0, 255, 0, 1}, m.ClientIdentifier)
}

func TestDecodePartialOptions(t *testing.T) {
	cases := []struct {
		name      string
		opts      []byte
		truncated bool
	}{
		{"missing end", nil, true}, {"missing length", []byte{12}, true}, {"missing bytes", []byte{12, 3, 'a'}, true},
		{"bad scalar", []byte{51, 1, 1, 255}, false}, {"repeated scalar", []byte{51, 4, 0, 0, 0, 1, 51, 4, 0, 0, 0, 2, 255}, false},
		{"bad list", []byte{3, 3, 1, 2, 3, 255}, false}, {"empty name", []byte{12, 0, 255}, false}, {"control name", []byte{12, 2, 27, 91, 255}, false}, {"binary name", []byte{12, 1, 255, 255}, false},
		{"empty identifier", []byte{61, 1, 0, 255}, false}, {"bad overload", []byte{52, 1, 4, 255}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Decode(packet(1, tc.opts...))
			require.ErrorIs(t, err, ErrOptions)
			require.True(t, m.Partial)
			require.Equal(t, tc.truncated, m.Truncated)
		})
	}
}

func TestDecodeOverloadRepeatedAndUnknown(t *testing.T) {
	b := packet(2, 52, 1, 3, 12, 2, 'a', 'b', 222, 3, 1, 2, 3, 0, 255, 12, 1, 'z')
	copy(b[108:236], []byte{12, 2, 'c', 'd', 255})
	copy(b[44:108], []byte{12, 2, 'e', 'f', 255})
	m, err := Decode(b)
	require.NoError(t, err)
	require.Equal(t, "abcdef", m.Hostname)
	b[108] = 52
	b[109] = 1
	b[110] = 1
	b[111] = 255
	m, err = Decode(b)
	require.ErrorIs(t, err, ErrOptions)
	require.True(t, m.Partial)
}

func TestDecodeBoundsAndHeaders(t *testing.T) {
	b := packet(1, 255)
	for n := 0; n < 240; n++ {
		m, err := Decode(b[:n])
		require.Error(t, err)
		require.Nil(t, m)
	}
	for _, offset := range []int{0, 1, 236} {
		bad := append([]byte(nil), b...)
		bad[offset] = 0
		m, err := Decode(bad)
		require.Error(t, err)
		require.Nil(t, m)
	}
	bad := append([]byte(nil), b...)
	bad[2] = 17
	_, err := Decode(bad)
	require.ErrorIs(t, err, ErrHeader)
	bad = append([]byte(nil), b...)
	bad[1] = 255
	bad[3] = 255
	_, err = Decode(bad)
	require.NoError(t, err)
	options := []byte{}
	for i := 0; i < 5; i++ {
		options = append(options, 61, 255)
		options = append(options, make([]byte, 255)...)
	}
	options = append(options, 255)
	m, err := Decode(packet(1, options...))
	require.ErrorIs(t, err, ErrOptions)
	require.Nil(t, m.ClientIdentifier)
	m, err = Decode(packet(1, 53, 1, 1, 255))
	require.ErrorIs(t, err, ErrMessageType)
	require.Nil(t, m)
	m, err = Decode(append(b[:240], 255))
	require.ErrorIs(t, err, ErrBOOTP)
	require.Nil(t, m)
	m, err = Decode(packet(9, 255))
	require.ErrorIs(t, err, ErrMessageType)
	require.Nil(t, m)
}

func FuzzDecode(f *testing.F) {
	f.Add(packet(1, 255))
	f.Add(packet(2, 52, 1, 3, 255))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if m != nil {
			if err != nil && !errors.Is(err, ErrOptions) {
				t.Fatal(err)
			}
			if len(m.ClientIdentifier) > MaxIdentifierBytes || len(m.HardwareAddress) > 16 || len(m.Routers) > MaxAddresses || len(m.DNSServers) > MaxAddresses {
				t.Fatal("unbounded field")
			}
			if err != nil && !m.Partial {
				t.Fatal("silent partial")
			}
		}
	})
}
