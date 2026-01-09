//go:build cli || hunter || tap || tui || all

package tls

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// JA3 GREASE values that should be excluded from fingerprint calculation.
// GREASE (Generate Random Extensions And Sustain Extensibility) values are
// used to prevent implementation bugs from being baked into the TLS ecosystem.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// CalculateJA3 calculates the JA3 fingerprint for a ClientHello.
// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
//
// Reference: https://github.com/salesforce/ja3
func CalculateJA3(metadata *types.TLSMetadata) (ja3String string, ja3Hash string) {
	if metadata == nil || metadata.IsServer {
		return "", ""
	}

	// Version
	version := fmt.Sprintf("%d", metadata.VersionRaw)

	// Ciphers (filter out GREASE)
	var ciphers []string
	for _, c := range metadata.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}
	ciphersStr := strings.Join(ciphers, "-")

	// Extensions (filter out GREASE)
	var extensions []string
	for _, e := range metadata.Extensions {
		if !isGREASE(e) {
			extensions = append(extensions, strconv.Itoa(int(e)))
		}
	}
	extensionsStr := strings.Join(extensions, "-")

	// Elliptic Curves / Supported Groups (filter out GREASE)
	var curves []string
	for _, c := range metadata.SupportedGroups {
		if !isGREASE(c) {
			curves = append(curves, strconv.Itoa(int(c)))
		}
	}
	curvesStr := strings.Join(curves, "-")

	// EC Point Formats
	var formats []string
	for _, f := range metadata.ECPointFormats {
		formats = append(formats, strconv.Itoa(int(f)))
	}
	formatsStr := strings.Join(formats, "-")

	// Build JA3 string
	ja3String = fmt.Sprintf("%s,%s,%s,%s,%s", version, ciphersStr, extensionsStr, curvesStr, formatsStr)

	// Calculate MD5 hash
	hash := md5.Sum([]byte(ja3String))
	ja3Hash = hex.EncodeToString(hash[:])

	return ja3String, ja3Hash
}

// CalculateJA3S calculates the JA3S fingerprint for a ServerHello.
// JA3S = MD5(SSLVersion,Cipher,Extensions)
//
// Reference: https://github.com/salesforce/ja3
func CalculateJA3S(metadata *types.TLSMetadata) (ja3sString string, ja3sHash string) {
	if metadata == nil || !metadata.IsServer {
		return "", ""
	}

	// Version
	version := fmt.Sprintf("%d", metadata.VersionRaw)

	// Selected cipher
	cipherStr := strconv.Itoa(int(metadata.SelectedCipher))

	// Extensions (filter out GREASE)
	var extensions []string
	for _, e := range metadata.Extensions {
		if !isGREASE(e) {
			extensions = append(extensions, strconv.Itoa(int(e)))
		}
	}
	extensionsStr := strings.Join(extensions, "-")

	// Build JA3S string
	ja3sString = fmt.Sprintf("%s,%s,%s", version, cipherStr, extensionsStr)

	// Calculate MD5 hash
	hash := md5.Sum([]byte(ja3sString))
	ja3sHash = hex.EncodeToString(hash[:])

	return ja3sString, ja3sHash
}

// CalculateJA4 calculates the JA4 fingerprint for a ClientHello.
// JA4 is a more modern fingerprint format that improves on JA3.
//
// Format: t{version}{sni}{ciphers}_{extensions}_{alpn}
// Example: t13d1516h2_8daaf6152771_b186095e22bb
//
// Reference: https://github.com/FoxIO-LLC/ja4
func CalculateJA4(metadata *types.TLSMetadata) (ja4String string, ja4Fingerprint string) {
	if metadata == nil || metadata.IsServer {
		return "", ""
	}

	var parts []string

	// Part 1: Protocol type (t=TLS, q=QUIC)
	proto := "t"

	// Part 2: TLS version (2 chars)
	var versionCode string
	switch metadata.VersionRaw {
	case VersionSSL30:
		versionCode = "s3"
	case VersionTLS10:
		versionCode = "10"
	case VersionTLS11:
		versionCode = "11"
	case VersionTLS12:
		versionCode = "12"
	case VersionTLS13:
		versionCode = "13"
	default:
		if metadata.VersionRaw >= VersionTLS13D && metadata.VersionRaw < 0x7F20 {
			versionCode = "13"
		} else {
			versionCode = "00"
		}
	}

	// Part 3: SNI indicator (d=has domain, i=IP only)
	sniIndicator := "i"
	if metadata.SNI != "" {
		sniIndicator = "d"
	}

	// Part 4: Number of cipher suites (2 digits, capped at 99)
	cipherCount := len(metadata.CipherSuites)
	for _, c := range metadata.CipherSuites {
		if isGREASE(c) {
			cipherCount--
		}
	}
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Part 5: Number of extensions (2 digits, capped at 99)
	extCount := len(metadata.Extensions)
	for _, e := range metadata.Extensions {
		if isGREASE(e) {
			extCount--
		}
	}
	if extCount > 99 {
		extCount = 99
	}

	// Part 6: First ALPN protocol (h2, h1, etc.)
	alpn := "00"
	if len(metadata.ALPNProtocols) > 0 {
		first := metadata.ALPNProtocols[0]
		if len(first) >= 2 {
			alpn = first[:2]
		} else if len(first) == 1 {
			alpn = first + "0"
		}
	}

	// Build JA4_a (first part)
	ja4a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, versionCode, sniIndicator, cipherCount, extCount, alpn)
	parts = append(parts, ja4a)

	// Part 7: Sorted cipher suites hash (JA4_b)
	var sortedCiphers []int
	for _, c := range metadata.CipherSuites {
		if !isGREASE(c) {
			sortedCiphers = append(sortedCiphers, int(c))
		}
	}
	sort.Ints(sortedCiphers)
	var cipherStrs []string
	for _, c := range sortedCiphers {
		cipherStrs = append(cipherStrs, fmt.Sprintf("%04x", c))
	}
	cipherHash := truncatedHash(strings.Join(cipherStrs, ","))
	parts = append(parts, cipherHash)

	// Part 8: Sorted extensions hash (JA4_c), excluding SNI and ALPN
	var sortedExts []int
	for _, e := range metadata.Extensions {
		if !isGREASE(e) && e != ExtensionSNI && e != ExtensionALPN {
			sortedExts = append(sortedExts, int(e))
		}
	}
	sort.Ints(sortedExts)
	var extStrs []string
	for _, e := range sortedExts {
		extStrs = append(extStrs, fmt.Sprintf("%04x", e))
	}

	// Add signature algorithms to extension hash
	var sigAlgStrs []string
	for _, s := range metadata.SignatureAlgos {
		sigAlgStrs = append(sigAlgStrs, fmt.Sprintf("%04x", s))
	}
	extInput := strings.Join(extStrs, ",")
	if len(sigAlgStrs) > 0 {
		extInput += "_" + strings.Join(sigAlgStrs, ",")
	}
	extHash := truncatedHash(extInput)
	parts = append(parts, extHash)

	// Build final JA4 fingerprint
	ja4Fingerprint = strings.Join(parts, "_")
	ja4String = ja4Fingerprint // JA4 string and fingerprint are the same

	return ja4String, ja4Fingerprint
}

// isGREASE checks if a value is a GREASE value.
func isGREASE(value uint16) bool {
	return greaseValues[value]
}

// truncatedHash computes a truncated SHA256 hash for JA4.
func truncatedHash(input string) string {
	if input == "" {
		return "000000000000"
	}
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:6]) // First 12 hex chars (6 bytes)
}

// IsValidJA3Hash checks if a string is a valid JA3/JA3S hash (32-char hex).
func IsValidJA3Hash(hash string) bool {
	if len(hash) != 32 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsValidJA4Fingerprint checks if a string looks like a JA4 fingerprint.
func IsValidJA4Fingerprint(fp string) bool {
	// JA4 format: <ja4_a>_<ja4_b>_<ja4_c>
	// Example: t13d1516h2_8daaf6152771_b186095e22bb
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		return false
	}

	// ja4_a should start with 't' or 'q' and be ~10 chars
	if len(parts[0]) < 8 || (parts[0][0] != 't' && parts[0][0] != 'q') {
		return false
	}

	// ja4_b and ja4_c should be 12-char hex strings
	for i := 1; i < 3; i++ {
		if len(parts[i]) != 12 {
			return false
		}
		for _, c := range parts[i] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}

	return true
}
