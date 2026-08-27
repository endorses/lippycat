//go:build cli || hunter || tap || tui || all

package tls

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateJA4ReferenceVector(t *testing.T) {
	// Independently generated from the canonical JA4 Python implementation
	// (FoxIO-LLC/ja4, python/ja4.py) using the ClientHello fields below. Keeping
	// the unhashed inputs in this fixture makes the expected value reproducible
	// without sharing CalculateJA4's helpers.
	metadata := &types.TLSMetadata{
		VersionRaw: VersionTLS13,
		SNI:        "example.com",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
			0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x001b, ExtensionSNI, 0x0033, ExtensionALPN, 0x4469, 0x0017,
			0x002d, ExtensionSignatureAlgos, 0x0005, 0x0023, 0x0012,
			ExtensionSupportedVer, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		SignatureAlgos: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		ALPNProtocols:  []string{"h2", "http/1.1"},
	}

	raw, fingerprint := CalculateJA4(metadata)
	require.Equal(t, "t13d1516h2_8daaf6152771_e5627efa2ab1", fingerprint)
	assert.Equal(t, fingerprint, raw)
}

func TestCalculateJA4ALPNTransformation(t *testing.T) {
	tests := []struct {
		name string
		alpn []string
		want string
	}{
		{name: "h2", alpn: []string{"h2"}, want: "h2"},
		{name: "http 1.1", alpn: []string{"http/1.1"}, want: "h1"},
		{name: "one character", alpn: []string{"x"}, want: "xx"},
		{name: "no ALPN", want: "00"},
		{name: "empty ALPN", alpn: []string{""}, want: "00"},
		{name: "non-alphanumeric boundary", alpn: []string{string([]byte{0x20, 0x61})}, want: "21"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &types.TLSMetadata{VersionRaw: VersionTLS13, ALPNProtocols: tt.alpn}
			_, fingerprint := CalculateJA4(metadata)
			assert.Equal(t, tt.want, fingerprint[8:10])
		})
	}
}

func TestCalculateJA4GREASEExclusionsAndEmptyHashes(t *testing.T) {
	metadata := &types.TLSMetadata{
		VersionRaw:     VersionTLS12,
		CipherSuites:   []uint16{0x0a0a},
		Extensions:     []uint16{0x1a1a, ExtensionSNI, ExtensionALPN},
		SignatureAlgos: []uint16{0x2a2a},
	}

	_, fingerprint := CalculateJA4(metadata)
	assert.Equal(t, "t12d000200_000000000000_000000000000", fingerprint)
}

func TestCalculateJA4SelectsHighestNonGREASESupportedVersion(t *testing.T) {
	metadata := &types.TLSMetadata{
		VersionRaw:        VersionTLS12,
		SupportedVersions: []uint16{0x2a2a, VersionTLS12, VersionTLS13, VersionTLS11},
	}

	_, fingerprint := CalculateJA4(metadata)
	assert.Equal(t, "t13i000000_000000000000_000000000000", fingerprint)
}

func TestParseSupportedVersionsPreservesWireList(t *testing.T) {
	p := NewParser()
	versions := p.parseSupportedVersions([]byte{8, 0x2a, 0x2a, 0x03, 0x03, 0x03, 0x04, 0x03, 0x02})
	assert.Equal(t, []uint16{0x2a2a, VersionTLS12, VersionTLS13, VersionTLS11}, versions)
	assert.Equal(t, uint16(VersionTLS13), highestSupportedVersion(versions))
}

func TestCalculateJA3AndJA3SRegression(t *testing.T) {
	client := &types.TLSMetadata{
		VersionRaw:      VersionTLS12,
		CipherSuites:    []uint16{0x1301, 0x1302, 0x0a0a, 0x002f},
		Extensions:      []uint16{0, 10, 11, 13, 16, 0x1a1a},
		SupportedGroups: []uint16{29, 23},
		ECPointFormats:  []uint8{0},
	}
	ja3String, ja3Hash := CalculateJA3(client)
	assert.Equal(t, "771,4865-4866-47,0-10-11-13-16,29-23,0", ja3String)
	assert.Equal(t, "2415fb670b19672c72ed68a8977464ea", ja3Hash)

	server := &types.TLSMetadata{
		VersionRaw:     VersionTLS12,
		IsServer:       true,
		SelectedCipher: 0x1301,
		Extensions:     []uint16{43, 51, 0x2a2a},
	}
	ja3sString, ja3sHash := CalculateJA3S(server)
	assert.Equal(t, "771,4865,43-51", ja3sString)
	assert.Equal(t, "f4febc55ea12b31ae17cfb7e614afda8", ja3sHash)
}
