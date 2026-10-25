//go:build cli || hunter || tap || tui || all

package tls

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECHAvailabilityRequiresCompleteClientHello(t *testing.T) {
	plain := clientHelloFixture(t)
	withECH := append([]byte(nil), plain...)
	// Fixture: fixed hello vectors end at byte 56; extend its extension vector.
	extensionLengthOffset := 5 + 4 + 2 + 32 + 1 + 2 + 6 + 2
	extensionsLength := binary.BigEndian.Uint16(withECH[extensionLengthOffset:])
	withECH = appendExtension(withECH, ExtensionEncryptedClientHello, []byte{0, 1, 2})
	binary.BigEndian.PutUint16(withECH[extensionLengthOffset:], extensionsLength+7)
	updateHelloLengths(withECH)

	malformed := append([]byte(nil), withECH...)
	binary.BigEndian.PutUint16(malformed[len(malformed)-5:], 4) // Body only has three bytes.
	trailingHeader := append(append([]byte(nil), plain...), 0xfe)
	binary.BigEndian.PutUint16(trailingHeader[extensionLengthOffset:], extensionsLength+1)
	updateHelloLengths(trailingHeader)
	server := append([]byte(nil), withECH...)
	server[5] = HandshakeTypeServerHello
	for _, tc := range []struct {
		name              string
		payload           []byte
		observed, offered bool
	}{
		{"without extension", plain, true, false},
		{"opaque ECH offer", withECH, true, true},
		{"malformed extension length", malformed, false, false},
		{"truncated extension header", trailingHeader, false, false},
		{"server hello", server, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewParser().ParsePayload(tc.payload)
			require.NotNil(t, m)
			require.Equal(t, tc.observed, m.ClientHelloObserved)
			require.Equal(t, tc.offered, m.ECHOffered)
		})
	}
	for length := 0; length < len(withECH); length++ {
		require.Nil(t, NewParser().ParsePayload(withECH[:length]), "incomplete TLS record length=%d", length)
	}
}

func TestClientHelloWithoutOptionalExtensionsIsObserved(t *testing.T) {
	body := binary.BigEndian.AppendUint16(nil, VersionTLS12)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0)
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	m := NewParser().ParseHandshake(VersionTLS12, message)
	require.NotNil(t, m)
	require.True(t, m.ClientHelloObserved)
	require.False(t, m.ECHOffered)
}

func updateHelloLengths(record []byte) {
	binary.BigEndian.PutUint16(record[3:5], uint16(len(record)-5))
	size := len(record) - 9
	record[6], record[7], record[8] = byte(size>>16), byte(size>>8), byte(size)
}
