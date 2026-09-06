//go:build cli || hunter || processor || tap || tui || all

package tls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// CalculateJA3 calculates the JA3 fingerprint for a ClientHello.
// JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
//
// Reference: https://github.com/salesforce/ja3
func CalculateJA3(metadata *types.TLSMetadata) (ja3String string, ja3Hash string) {
	if metadata == nil || metadata.IsServer {
		return "", ""
	}

	var storage [1024]byte
	input := strconv.AppendUint(storage[:0], uint64(metadata.VersionRaw), 10)
	input = append(input, ',')
	input = appendJA3Values(input, metadata.CipherSuites)
	input = append(input, ',')
	input = appendJA3Values(input, metadata.Extensions)
	input = append(input, ',')
	input = appendJA3Values(input, metadata.SupportedGroups)
	input = append(input, ',')
	for i, format := range metadata.ECPointFormats {
		if i != 0 {
			input = append(input, '-')
		}
		input = strconv.AppendUint(input, uint64(format), 10)
	}
	return ja3Digest(input)
}

// CalculateJA3S calculates the JA3S fingerprint for a ServerHello.
// JA3S = MD5(SSLVersion,Cipher,Extensions)
//
// Reference: https://github.com/salesforce/ja3
func CalculateJA3S(metadata *types.TLSMetadata) (ja3sString string, ja3sHash string) {
	if metadata == nil || !metadata.IsServer {
		return "", ""
	}

	var storage [256]byte
	input := strconv.AppendUint(storage[:0], uint64(metadata.VersionRaw), 10)
	input = append(input, ',')
	input = strconv.AppendUint(input, uint64(metadata.SelectedCipher), 10)
	input = append(input, ',')
	input = appendJA3Values(input, metadata.Extensions)
	return ja3Digest(input)
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

	// Part 2: highest advertised non-GREASE TLS version. ClientHello version
	// lists are not required to be sorted, so using their first entry is wrong.
	version := highestSupportedVersion(metadata.SupportedVersions)
	if version == 0 {
		version = metadata.VersionRaw
	}
	var versionCode string
	switch version {
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
	if containsUint16(metadata.Extensions, ExtensionSNI) {
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

	// Append fixed-width JA4_a directly into the final fingerprint buffer.
	var result [36]byte
	fingerprint := append(result[:0], 't')
	fingerprint = append(fingerprint, versionCode...)
	fingerprint = append(fingerprint, sniIndicator...)
	fingerprint = append(fingerprint, byte('0'+cipherCount/10), byte('0'+cipherCount%10), byte('0'+extCount/10), byte('0'+extCount%10))
	fingerprint = appendJA4ALPN(fingerprint, metadata.ALPNProtocols)
	fingerprint = append(fingerprint, '_')

	// Sort copies, preserving the metadata's original wire ordering for JA3.
	// Common hellos fit on the stack; unusually large inputs grow normally.
	var values [128]uint16
	sorted := values[:0]
	for _, cipher := range metadata.CipherSuites {
		if !isGREASE(cipher) {
			sorted = append(sorted, cipher)
		}
	}
	slices.Sort(sorted)
	var inputStorage [1024]byte
	input := appendJA4HexValues(inputStorage[:0], sorted)
	fingerprint = appendJA4Hash(fingerprint, input)
	fingerprint = append(fingerprint, '_')

	sorted = values[:0]
	for _, extension := range metadata.Extensions {
		if !isGREASE(extension) && extension != ExtensionSNI && extension != ExtensionALPN {
			sorted = append(sorted, extension)
		}
	}
	slices.Sort(sorted)
	input = appendJA4HexValues(inputStorage[:0], sorted)
	firstSignature := true
	for _, signature := range metadata.SignatureAlgos {
		if isGREASE(signature) {
			continue
		}
		if firstSignature {
			input = append(input, '_')
			firstSignature = false
		} else {
			input = append(input, ',')
		}
		input = appendHex16(input, signature)
	}
	fingerprint = appendJA4Hash(fingerprint, input)
	ja4Fingerprint = string(fingerprint)
	return ja4Fingerprint, ja4Fingerprint
}

func highestSupportedVersion(versions []uint16) uint16 {
	var highest uint16
	for _, version := range versions {
		if !isGREASE(version) && version > highest {
			highest = version
		}
	}
	return highest
}

// isGREASE checks if a value is a GREASE value.
func isGREASE(value uint16) bool {
	// The sixteen GREASE values repeat one byte whose low nibble is 0xa.
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}

func containsUint16(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// appendJA4ALPN applies JA4's first/last byte transformation to the first ALPN value.
func appendJA4ALPN(dst []byte, protocols []string) []byte {
	if len(protocols) == 0 || len(protocols[0]) == 0 {
		return append(dst, '0', '0')
	}

	value := protocols[0]
	first, last := value[0], value[len(value)-1]
	if isASCIIAlphanumeric(first) && isASCIIAlphanumeric(last) {
		return append(dst, first, last)
	}

	return append(dst, fingerprintHex[first>>4], fingerprintHex[last&0xf])
}

func isASCIIAlphanumeric(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z'
}

const fingerprintHex = "0123456789abcdef"

func appendJA3Values(dst []byte, values []uint16) []byte {
	first := true
	for _, value := range values {
		if isGREASE(value) {
			continue
		}
		if !first {
			dst = append(dst, '-')
		}
		dst = strconv.AppendUint(dst, uint64(value), 10)
		first = false
	}
	return dst
}

func ja3Digest(input []byte) (string, string) {
	hash := md5.Sum(input)
	var encoded [32]byte
	hex.Encode(encoded[:], hash[:])
	return string(input), string(encoded[:])
}

func appendHex16(dst []byte, value uint16) []byte {
	return append(dst, fingerprintHex[value>>12], fingerprintHex[value>>8&0xf], fingerprintHex[value>>4&0xf], fingerprintHex[value&0xf])
}

func appendJA4HexValues(dst []byte, values []uint16) []byte {
	for i, value := range values {
		if i != 0 {
			dst = append(dst, ',')
		}
		dst = appendHex16(dst, value)
	}
	return dst
}

func appendJA4Hash(dst, input []byte) []byte {
	if len(input) == 0 {
		return append(dst, "000000000000"...)
	}
	hash := sha256.Sum256(input)
	return hex.AppendEncode(dst, hash[:6])
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
