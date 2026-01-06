//go:build cli || hunter || tap || all

package tls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TLS constants
const (
	// TLS record types
	RecordTypeChangeCipherSpec = 20
	RecordTypeAlert            = 21
	RecordTypeHandshake        = 22
	RecordTypeApplicationData  = 23
	RecordTypeHeartbeat        = 24

	// Handshake types
	HandshakeTypeClientHello        = 1
	HandshakeTypeServerHello        = 2
	HandshakeTypeCertificate        = 11
	HandshakeTypeServerKeyExchange  = 12
	HandshakeTypeCertificateRequest = 13
	HandshakeTypeServerHelloDone    = 14
	HandshakeTypeCertificateVerify  = 15
	HandshakeTypeClientKeyExchange  = 16
	HandshakeTypeFinished           = 20

	// TLS versions
	VersionSSL30  = 0x0300
	VersionTLS10  = 0x0301
	VersionTLS11  = 0x0302
	VersionTLS12  = 0x0303
	VersionTLS13  = 0x0304
	VersionTLS13D = 0x7F00 // TLS 1.3 draft versions start here

	// Extension types
	ExtensionSNI             = 0
	ExtensionSupportedGroups = 10
	ExtensionECPointFormats  = 11
	ExtensionSignatureAlgos  = 13
	ExtensionALPN            = 16
	ExtensionSupportedVer    = 43

	// SNI types
	SNITypeHostname = 0
)

// Parser parses TLS handshake packets.
type Parser struct{}

// NewParser creates a new TLS parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts TLS metadata from a packet.
// Returns nil if the packet is not a TLS handshake.
func (p *Parser) Parse(packet gopacket.Packet) *types.TLSMetadata {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || len(tcp.Payload) < 6 {
		return nil
	}

	return p.ParsePayload(tcp.Payload)
}

// ParsePayload parses TLS metadata from raw payload bytes.
func (p *Parser) ParsePayload(payload []byte) *types.TLSMetadata {
	if len(payload) < 6 {
		return nil
	}

	// TLS record header: ContentType(1) + Version(2) + Length(2) + data
	contentType := payload[0]
	recordVersion := binary.BigEndian.Uint16(payload[1:3])
	recordLength := binary.BigEndian.Uint16(payload[3:5])

	// Validate content type (must be Handshake)
	if contentType != RecordTypeHandshake {
		return nil
	}

	// Validate TLS version
	major := payload[1]
	minor := payload[2]
	if major != 0x03 || minor > 0x04 {
		// Only accept SSL 3.0 through TLS 1.3
		if major != 0x03 || minor < 0x00 {
			return nil
		}
	}

	// Validate record length
	if recordLength > 16384 || int(recordLength)+5 > len(payload) {
		return nil
	}

	// Parse handshake message (inside the record)
	if len(payload) < 10 {
		return nil
	}

	handshakeType := payload[5]

	metadata := &types.TLSMetadata{
		RecordVersion: recordVersion,
		HandshakeType: p.handshakeTypeName(handshakeType),
	}

	switch handshakeType {
	case HandshakeTypeClientHello:
		p.parseClientHello(payload[5:], metadata)
	case HandshakeTypeServerHello:
		metadata.IsServer = true
		p.parseServerHello(payload[5:], metadata)
	default:
		// For other handshake types, just set basic info
		metadata.Version = p.versionString(recordVersion)
		metadata.VersionRaw = recordVersion
	}

	return metadata
}

// parseClientHello parses a ClientHello message.
func (p *Parser) parseClientHello(data []byte, metadata *types.TLSMetadata) {
	if len(data) < 38 {
		return
	}

	// Handshake header: Type(1) + Length(3)
	// ClientHello: Version(2) + Random(32) + SessionIDLen(1) + ...
	pos := 4 // Skip handshake header

	// Client version (may differ from record version)
	if pos+2 > len(data) {
		return
	}
	clientVersion := binary.BigEndian.Uint16(data[pos : pos+2])
	metadata.VersionRaw = clientVersion
	metadata.Version = p.versionString(clientVersion)
	pos += 2

	// Random (32 bytes)
	pos += 32

	// Session ID
	if pos+1 > len(data) {
		return
	}
	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return
	}
	if sessionIDLen > 0 {
		metadata.SessionID = hex.EncodeToString(data[pos : pos+sessionIDLen])
	}
	pos += sessionIDLen

	// Cipher suites
	if pos+2 > len(data) {
		return
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+cipherSuitesLen > len(data) {
		return
	}
	metadata.CipherSuites = make([]uint16, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen/2; i++ {
		metadata.CipherSuites[i] = binary.BigEndian.Uint16(data[pos+i*2 : pos+i*2+2])
	}
	pos += cipherSuitesLen

	// Compression methods
	if pos+1 > len(data) {
		return
	}
	compressionLen := int(data[pos])
	pos++
	pos += compressionLen

	// Extensions
	if pos+2 > len(data) {
		return
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	p.parseExtensions(data[pos:pos+extensionsLen], metadata)

	// Calculate JA3 fingerprint
	metadata.JA3String, metadata.JA3Fingerprint = CalculateJA3(metadata)
}

// parseServerHello parses a ServerHello message.
func (p *Parser) parseServerHello(data []byte, metadata *types.TLSMetadata) {
	if len(data) < 38 {
		return
	}

	// Handshake header: Type(1) + Length(3)
	pos := 4 // Skip handshake header

	// Server version
	if pos+2 > len(data) {
		return
	}
	serverVersion := binary.BigEndian.Uint16(data[pos : pos+2])
	metadata.VersionRaw = serverVersion
	metadata.Version = p.versionString(serverVersion)
	pos += 2

	// Random (32 bytes)
	pos += 32

	// Session ID
	if pos+1 > len(data) {
		return
	}
	sessionIDLen := int(data[pos])
	pos++
	if pos+sessionIDLen > len(data) {
		return
	}
	if sessionIDLen > 0 {
		metadata.SessionID = hex.EncodeToString(data[pos : pos+sessionIDLen])
	}
	pos += sessionIDLen

	// Selected cipher suite
	if pos+2 > len(data) {
		return
	}
	metadata.SelectedCipher = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// Compression method
	if pos+1 > len(data) {
		return
	}
	metadata.Compression = data[pos]
	pos++

	// Extensions (if present)
	if pos+2 <= len(data) {
		extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if pos+extensionsLen <= len(data) {
			p.parseServerExtensions(data[pos:pos+extensionsLen], metadata)
		}
	}

	// Calculate JA3S fingerprint
	metadata.JA3SString, metadata.JA3SFingerprint = CalculateJA3S(metadata)
}

// parseExtensions parses ClientHello extensions.
func (p *Parser) parseExtensions(data []byte, metadata *types.TLSMetadata) {
	pos := 0
	for pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(data) {
			break
		}

		extData := data[pos : pos+extLen]
		metadata.Extensions = append(metadata.Extensions, extType)

		switch extType {
		case ExtensionSNI:
			metadata.SNI = p.parseSNIExtension(extData)
		case ExtensionSupportedGroups:
			metadata.SupportedGroups = p.parseSupportedGroups(extData)
		case ExtensionECPointFormats:
			metadata.ECPointFormats = p.parseECPointFormats(extData)
		case ExtensionSignatureAlgos:
			metadata.SignatureAlgos = p.parseSignatureAlgos(extData)
		case ExtensionALPN:
			metadata.ALPNProtocols = p.parseALPN(extData)
		case ExtensionSupportedVer:
			// TLS 1.3 uses supported_versions extension for real version
			if realVersion := p.parseSupportedVersions(extData); realVersion != 0 {
				metadata.VersionRaw = realVersion
				metadata.Version = p.versionString(realVersion)
			}
		}

		pos += extLen
	}
}

// parseServerExtensions parses ServerHello extensions.
func (p *Parser) parseServerExtensions(data []byte, metadata *types.TLSMetadata) {
	pos := 0
	for pos+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(data) {
			break
		}

		extData := data[pos : pos+extLen]
		metadata.Extensions = append(metadata.Extensions, extType)

		switch extType {
		case ExtensionSupportedVer:
			// TLS 1.3 uses supported_versions for real version
			if len(extData) >= 2 {
				realVersion := binary.BigEndian.Uint16(extData[:2])
				metadata.VersionRaw = realVersion
				metadata.Version = p.versionString(realVersion)
			}
		}

		pos += extLen
	}
}

// parseSNIExtension extracts the server name from the SNI extension.
func (p *Parser) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Server Name List Length (2 bytes)
	// Server Name Type (1 byte) - 0 for hostname
	// Server Name Length (2 bytes)
	// Server Name

	pos := 2 // Skip list length
	if pos+3 > len(data) {
		return ""
	}

	nameType := data[pos]
	if nameType != SNITypeHostname {
		return ""
	}
	pos++

	nameLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

// parseSupportedGroups extracts supported groups (elliptic curves).
func (p *Parser) parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	groupsLen := int(binary.BigEndian.Uint16(data[0:2]))
	if groupsLen+2 > len(data) {
		return nil
	}

	groups := make([]uint16, groupsLen/2)
	for i := 0; i < groupsLen/2; i++ {
		groups[i] = binary.BigEndian.Uint16(data[2+i*2 : 4+i*2])
	}
	return groups
}

// parseECPointFormats extracts EC point formats.
func (p *Parser) parseECPointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}

	formatsLen := int(data[0])
	if formatsLen+1 > len(data) {
		return nil
	}

	formats := make([]uint8, formatsLen)
	copy(formats, data[1:1+formatsLen])
	return formats
}

// parseSignatureAlgos extracts signature algorithms.
func (p *Parser) parseSignatureAlgos(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	algosLen := int(binary.BigEndian.Uint16(data[0:2]))
	if algosLen+2 > len(data) {
		return nil
	}

	algos := make([]uint16, algosLen/2)
	for i := 0; i < algosLen/2; i++ {
		algos[i] = binary.BigEndian.Uint16(data[2+i*2 : 4+i*2])
	}
	return algos
}

// parseALPN extracts ALPN protocols.
func (p *Parser) parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return nil
	}

	var protocols []string
	pos := 2
	for pos < 2+listLen {
		if pos >= len(data) {
			break
		}
		protoLen := int(data[pos])
		pos++
		if pos+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[pos:pos+protoLen]))
		pos += protoLen
	}
	return protocols
}

// parseSupportedVersions extracts the real TLS version from supported_versions extension.
func (p *Parser) parseSupportedVersions(data []byte) uint16 {
	if len(data) < 1 {
		return 0
	}

	// In ClientHello, this is a list; take the first/highest
	versionsLen := int(data[0])
	if versionsLen+1 > len(data) || versionsLen < 2 {
		return 0
	}

	// Return first version (typically the highest)
	return binary.BigEndian.Uint16(data[1:3])
}

// handshakeTypeName returns a human-readable name for the handshake type.
func (p *Parser) handshakeTypeName(t uint8) string {
	switch t {
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeServerKeyExchange:
		return "ServerKeyExchange"
	case HandshakeTypeCertificateRequest:
		return "CertificateRequest"
	case HandshakeTypeServerHelloDone:
		return "ServerHelloDone"
	case HandshakeTypeCertificateVerify:
		return "CertificateVerify"
	case HandshakeTypeClientKeyExchange:
		return "ClientKeyExchange"
	case HandshakeTypeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// versionString returns a human-readable TLS version string.
func (p *Parser) versionString(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSL 3.0"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		if version >= VersionTLS13D && version < 0x7F20 {
			return "TLS 1.3 (draft)"
		}
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// VersionString is a package-level helper for formatting TLS versions.
func VersionString(version uint16) string {
	p := &Parser{}
	return p.versionString(version)
}
