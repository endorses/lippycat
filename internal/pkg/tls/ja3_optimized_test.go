//go:build cli || hunter || processor || tap || tui || all

package tls

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOptimizedFingerprintsMatchFrozenImplementation(t *testing.T) {
	rng := rand.New(rand.NewSource(20260906))
	values := func(count int) []uint16 {
		var result []uint16
		for range count {
			value := uint16(rng.Intn(65536))
			if rng.Intn(4) == 0 {
				grease := uint16(rng.Intn(16))*16 + 10
				value = grease<<8 | grease
			}
			result = append(result, value)
		}
		return result
	}
	check := func(m *types.TLSMetadata) {
		t.Helper()
		for _, pair := range [][2]func(*types.TLSMetadata) (string, string){
			{frozenCalculateJA3, CalculateJA3},
			{frozenCalculateJA3S, CalculateJA3S},
			{frozenCalculateJA4, CalculateJA4},
		} {
			wantRaw, wantFingerprint := pair[0](m)
			gotRaw, gotFingerprint := pair[1](m)
			require.Equal(t, wantRaw, gotRaw)
			require.Equal(t, wantFingerprint, gotFingerprint)
		}
	}
	check(nil)
	check(&types.TLSMetadata{})
	check(&types.TLSMetadata{IsServer: true})
	for sample := range 512 {
		count := rng.Intn(320)
		if sample == 0 {
			count = 4096
		} // Exercise stack-buffer growth without truncation.
		m := &types.TLSMetadata{
			VersionRaw: uint16(rng.Intn(65536)), SelectedCipher: uint16(rng.Intn(65536)),
			CipherSuites: values(count), Extensions: values(rng.Intn(320)),
			SupportedGroups: values(rng.Intn(100)), SupportedVersions: values(rng.Intn(8)),
			SignatureAlgos: values(rng.Intn(320)),
		}
		if sample%3 == 0 {
			m.VersionRaw = []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13, VersionTLS13D}[sample%6]
		}
		if sample%5 == 0 {
			m.Extensions = append(m.Extensions, ExtensionSNI, ExtensionALPN)
		}
		for range rng.Intn(10) {
			m.ECPointFormats = append(m.ECPointFormats, uint8(rng.Intn(256)))
		}
		if sample%4 != 0 {
			alpn := make([]byte, rng.Intn(100))
			for i := range alpn {
				alpn[i] = byte(rng.Intn(256))
			}
			m.ALPNProtocols = []string{string(alpn), "ignored"}
		}
		before := *m
		before.CipherSuites = slices.Clone(m.CipherSuites)
		before.Extensions = slices.Clone(m.Extensions)
		before.SignatureAlgos = slices.Clone(m.SignatureAlgos)
		before.SupportedGroups = slices.Clone(m.SupportedGroups)
		before.SupportedVersions = slices.Clone(m.SupportedVersions)
		before.ECPointFormats = slices.Clone(m.ECPointFormats)
		before.ALPNProtocols = slices.Clone(m.ALPNProtocols)
		check(m)
		require.Equal(t, before, *m, "fingerprinting must preserve wire ordering")
		m.IsServer = true
		check(m)
	}
	for value := 0; value < 65536; value++ {
		require.Equal(t, frozenIsGREASE(uint16(value)), isGREASE(uint16(value)))
	}
}

var fingerprintBenchmarkRaw, fingerprintBenchmarkHash string

func BenchmarkFingerprintAssembly(b *testing.B) {
	metadata := &types.TLSMetadata{
		VersionRaw: VersionTLS12, SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		CipherSuites:    []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:      []uint16{0x001b, 0, 0x33, 16, 0x4469, 0x17, 0x2d, 13, 5, 0x23, 0x12, 43, 0xff01, 11, 10, 21},
		SignatureAlgos:  []uint16{0x403, 0x804, 0x401, 0x503, 0x805, 0x501, 0x806, 0x601},
		SupportedGroups: []uint16{29, 23, 24}, ECPointFormats: []uint8{0}, ALPNProtocols: []string{"h2", "http/1.1"},
	}
	for _, tc := range []struct {
		name      string
		calculate func(*types.TLSMetadata) (string, string)
	}{
		{"JA3/frozen", frozenCalculateJA3}, {"JA3/optimized", CalculateJA3},
		{"JA4/frozen", frozenCalculateJA4}, {"JA4/optimized", CalculateJA4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				fingerprintBenchmarkRaw, fingerprintBenchmarkHash = tc.calculate(metadata)
			}
		})
	}
}
