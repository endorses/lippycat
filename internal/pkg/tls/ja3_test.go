//go:build cli || hunter || tap || tui || all

package tls

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCalculateJA3KnownVector(t *testing.T) {
	metadata := &types.TLSMetadata{
		VersionRaw:      VersionTLS12,
		CipherSuites:    []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:      []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		SupportedGroups: []uint16{0x001d, 0x0017, 0x0018},
		ECPointFormats:  []uint8{0},
	}

	ja3String, fingerprint := CalculateJA3(metadata)

	assert.Equal(t, "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0", ja3String)
	assert.Equal(t, "c000e2caf3a25423f9de6c8a4b12a975", fingerprint)
}

func TestCalculateJA3SKnownVector(t *testing.T) {
	metadata := &types.TLSMetadata{
		IsServer:       true,
		VersionRaw:     VersionTLS12,
		SelectedCipher: 0x1301,
		Extensions:     []uint16{0x002b, 0x0033},
	}

	ja3sString, fingerprint := CalculateJA3S(metadata)

	assert.Equal(t, "771,4865,43-51", ja3sString)
	assert.Equal(t, "f4febc55ea12b31ae17cfb7e614afda8", fingerprint)
}

func TestCalculateJA4OfficialVector(t *testing.T) {
	metadata := &types.TLSMetadata{
		VersionRaw:        VersionTLS12,
		SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		SNI:               "example.com",
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:        []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		SignatureAlgos:    []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		ALPNProtocols:     []string{"h2"},
	}

	ja4String, fingerprint := CalculateJA4(metadata)

	assert.Equal(t, "t13d1516h2_8daaf6152771_e5627efa2ab1", ja4String)
	assert.Equal(t, ja4String, fingerprint)
}

func TestCalculateJA4ALPNUsesFirstAndLastCharacters(t *testing.T) {
	metadata := &types.TLSMetadata{VersionRaw: VersionTLS12, ALPNProtocols: []string{"http/1.1"}}

	_, fingerprint := CalculateJA4(metadata)

	assert.Equal(t, "t12i0000h1_000000000000_000000000000", fingerprint)
}
