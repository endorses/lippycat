package protocolmeta

import (
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// TLSToProto converts shared TLS analyzer output to transport metadata.
func TLSToProto(m *types.TLSMetadata) *data.TLSMetadata {
	if m == nil {
		return nil
	}
	return &data.TLSMetadata{Version: m.Version, VersionRaw: uint32(m.VersionRaw), RecordVersion: uint32(m.RecordVersion), HandshakeType: m.HandshakeType, IsServer: m.IsServer, SessionId: m.SessionID, Sni: m.SNI, CipherSuites: uint16s(m.CipherSuites), Extensions: uint16s(m.Extensions), SupportedGroups: uint16s(m.SupportedGroups), SignatureAlgorithms: uint16s(m.SignatureAlgos), EcPointFormats: uint8s(m.ECPointFormats), AlpnProtocols: append([]string(nil), m.ALPNProtocols...), SupportedVersions: uint16s(m.SupportedVersions), SelectedCipher: uint32(m.SelectedCipher), Compression: uint32(m.Compression), Ja3: m.JA3Fingerprint, Ja3S: m.JA3SFingerprint, Ja4: m.JA4Fingerprint, CorrelatedPeer: m.CorrelatedPeer, HandshakeTimeMs: m.HandshakeTimeMs, RiskScore: m.RiskScore, RiskFlags: int32(m.RiskFlags)} // #nosec G115 -- bounded risk bitmask
}

// HTTPToProto converts shared HTTP analyzer output to transport metadata.
func HTTPToProto(m *types.HTTPMetadata, includeHeaders bool) *data.HTTPMetadata {
	if m == nil {
		return nil
	}
	result := &data.HTTPMetadata{Type: m.Type, IsServer: m.IsServer, Method: m.Method, Path: m.Path, Version: m.Version, StatusCode: uint32(m.StatusCode), StatusReason: m.StatusReason, Host: m.Host, Server: m.Server, ContentType: m.ContentType, ContentLength: m.ContentLength, UserAgent: m.UserAgent, RequestTime: m.RequestTime, ResponseTime: m.ResponseTime, IsHttps: m.IsHTTPS, HasAuth: m.HasAuth, CorrelatedResponse: m.CorrelatedResponse, RequestResponseTimeMs: m.RequestResponseTimeMs, QueryString: m.QueryString, BodyPreview: []byte(m.BodyPreview), BodySize: uint64(m.BodySize), BodyTruncated: m.BodyTruncated} // #nosec G115 -- parser validated bounded values
	if includeHeaders && len(m.Headers) > 0 {
		result.Headers = make(map[string]string, len(m.Headers))
		for key, value := range m.Headers {
			result.Headers[strings.ToLower(key)] = value
		}
	}
	return result
}

func uint16s(values []uint16) []uint32 {
	result := make([]uint32, len(values))
	for i, value := range values {
		result[i] = uint32(value)
	}
	return result
}

func uint8s(values []uint8) []uint32 {
	result := make([]uint32, len(values))
	for i, value := range values {
		result[i] = uint32(value)
	}
	return result
}
