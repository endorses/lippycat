//go:build cli || hunter || tap || tui || all

package tls

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientHelloPopulatesJA3AndJA4(t *testing.T) {
	payload := clientHelloFixture(t)

	metadata := NewParser().ParsePayload(payload)

	require.NotNil(t, metadata)
	assert.Equal(t, VersionTLS12, int(metadata.VersionRaw), "JA3 must use ClientHello legacy_version")
	assert.Equal(t, []uint16{0x0a0a, VersionTLS13, VersionTLS12}, metadata.SupportedVersions)
	assert.Equal(t, "771,4865-4866,0-10-11-13-16-43,29-23,0", metadata.JA3String)
	assert.Equal(t, "8b85ec5fe3da506907f3cac65cd06803", metadata.JA3Fingerprint)
	assert.Equal(t, "t13d0206h1_62ed6f6ca7ad_fb71836bce29", metadata.JA4Fingerprint)
	assert.Equal(t, metadata.JA4Fingerprint, metadata.JA4String)

	filter := NewContentFilter(ContentFilterConfig{JA4Fingerprints: []string{metadata.JA4Fingerprint}})
	assert.True(t, filter.Match(metadata), "the sniff TLS filter must match a parser-produced JA4")
}

func clientHelloFixture(t *testing.T) []byte {
	t.Helper()

	extensions := []byte{}
	extensions = appendExtension(extensions, ExtensionSNI, []byte{0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})
	extensions = appendExtension(extensions, ExtensionSupportedGroups, []byte{0, 6, 0x0a, 0x0a, 0, 29, 0, 23})
	extensions = appendExtension(extensions, ExtensionECPointFormats, []byte{1, 0})
	extensions = appendExtension(extensions, ExtensionSignatureAlgos, []byte{0, 4, 4, 3, 8, 4})
	extensions = appendExtension(extensions, ExtensionALPN, []byte{0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	extensions = appendExtension(extensions, ExtensionSupportedVer, []byte{6, 0x0a, 0x0a, 3, 4, 3, 3})

	body := make([]byte, 0, 128)
	body = binary.BigEndian.AppendUint16(body, VersionTLS12)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session ID length
	body = binary.BigEndian.AppendUint16(body, 6)
	body = binary.BigEndian.AppendUint16(body, 0x0a0a)
	body = binary.BigEndian.AppendUint16(body, 0x1301)
	body = binary.BigEndian.AppendUint16(body, 0x1302)
	body = append(body, 1, 0) // compression methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{HandshakeTypeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{RecordTypeHandshake, 3, 1}
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...)
}

func appendExtension(dst []byte, extensionType uint16, data []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, extensionType)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(data)))
	return append(dst, data...)
}
