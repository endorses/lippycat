//go:build cli || hunter || tap || all

// Package protocolmeta converts packet-level analyzer output to the protobuf
// metadata transported between capture and processor nodes.
package protocolmeta

import (
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	httpparser "github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Enrich adds flow, TLS, and HTTP metadata without replacing metadata already
// produced by protocol-specific handlers.
func Enrich(packet gopacket.Packet, metadata *data.PacketMetadata, includeHTTPHeaders bool) *data.PacketMetadata {
	if packet == nil {
		return metadata
	}
	if metadata == nil {
		metadata = &data.PacketMetadata{}
	}
	populateFlow(packet, metadata)
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && len(tcp.Payload) > 0 {
		if metadata.Tls == nil {
			metadata.Tls = tlsToProto(tls.NewParser().ParsePayload(tcp.Payload))
		}
		if metadata.Http == nil {
			metadata.Http = httpToProto(httpparser.NewParser().ParsePayload(tcp.Payload), includeHTTPHeaders)
		}
	}
	return metadata
}

func populateFlow(packet gopacket.Packet, metadata *data.PacketMetadata) {
	if network := packet.NetworkLayer(); network != nil {
		metadata.SrcIp = network.NetworkFlow().Src().String()
		metadata.DstIp = network.NetworkFlow().Dst().String()
	}
	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "tcp", uint32(transport.SrcPort), uint32(transport.DstPort)
	case *layers.UDP:
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "udp", uint32(transport.SrcPort), uint32(transport.DstPort)
	}
}

func tlsToProto(m *types.TLSMetadata) *data.TLSMetadata {
	if m == nil {
		return nil
	}
	return &data.TLSMetadata{Version: m.Version, VersionRaw: uint32(m.VersionRaw), RecordVersion: uint32(m.RecordVersion), HandshakeType: m.HandshakeType, IsServer: m.IsServer, SessionId: m.SessionID, Sni: m.SNI, CipherSuites: uint16s(m.CipherSuites), Extensions: uint16s(m.Extensions), SupportedGroups: uint16s(m.SupportedGroups), SignatureAlgorithms: uint16s(m.SignatureAlgos), EcPointFormats: uint8s(m.ECPointFormats), AlpnProtocols: append([]string(nil), m.ALPNProtocols...), SupportedVersions: uint16s(m.SupportedVersions), SelectedCipher: uint32(m.SelectedCipher), Compression: uint32(m.Compression), Ja3: m.JA3Fingerprint, Ja3S: m.JA3SFingerprint, Ja4: m.JA4Fingerprint, CorrelatedPeer: m.CorrelatedPeer, HandshakeTimeMs: m.HandshakeTimeMs, RiskScore: m.RiskScore, RiskFlags: int32(m.RiskFlags)} // #nosec G115 -- bounded risk bitmask
}

func httpToProto(m *types.HTTPMetadata, includeHeaders bool) *data.HTTPMetadata {
	if m == nil {
		return nil
	}
	result := &data.HTTPMetadata{Type: m.Type, IsServer: m.IsServer, Method: m.Method, Path: m.Path, Version: m.Version, StatusCode: uint32(m.StatusCode), StatusReason: m.StatusReason, Host: m.Host, Server: m.Server, ContentType: m.ContentType, ContentLength: m.ContentLength, UserAgent: m.UserAgent, RequestTime: m.RequestTime, ResponseTime: m.ResponseTime, IsHttps: m.IsHTTPS, HasAuth: m.HasAuth, CorrelatedResponse: m.CorrelatedResponse, RequestResponseTimeMs: m.RequestResponseTimeMs, QueryString: m.QueryString} // #nosec G115 -- validated HTTP status
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
