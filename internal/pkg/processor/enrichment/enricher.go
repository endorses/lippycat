package enrichment

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Enricher handles packet metadata enrichment through protocol detection
type Enricher struct {
	detector *detector.Detector
}

// NewEnricher creates a new packet enricher
func NewEnricher(detector *detector.Detector) *Enricher {
	return &Enricher{
		detector: detector,
	}
}

// Enrich performs centralized protocol detection and enriches packet metadata
func (e *Enricher) Enrich(packets []*data.CapturedPacket) {
	if e.detector == nil {
		return // No detector configured, skip enrichment
	}

	for _, pkt := range packets {
		// Decode packet from raw bytes (safe: link type is small enum from proto, values < 300)
		goPacket := gopacket.NewPacket(pkt.Data, layers.LinkType(pkt.LinkType), gopacket.Default) // #nosec G115

		// Run centralized detection
		result := e.detector.Detect(goPacket)

		if result != nil && result.Protocol != "unknown" {
			// Initialize metadata if not exists
			if pkt.Metadata == nil {
				pkt.Metadata = &data.PacketMetadata{}
			}

			// Populate protocol
			pkt.Metadata.Protocol = result.Protocol

			// Build info string for display (same logic as TUI bridge)
			pkt.Metadata.Info = buildInfoString(result.Protocol, result.Metadata)

			// Extract network layer info
			if netLayer := goPacket.NetworkLayer(); netLayer != nil {
				switch net := netLayer.(type) {
				case *layers.IPv4:
					pkt.Metadata.SrcIp = net.SrcIP.String()
					pkt.Metadata.DstIp = net.DstIP.String()
				case *layers.IPv6:
					pkt.Metadata.SrcIp = net.SrcIP.String()
					pkt.Metadata.DstIp = net.DstIP.String()
				}
			}

			// Extract transport layer info
			if transLayer := goPacket.TransportLayer(); transLayer != nil {
				switch trans := transLayer.(type) {
				case *layers.TCP:
					pkt.Metadata.Transport = "TCP"
					pkt.Metadata.SrcPort = uint32(trans.SrcPort)
					pkt.Metadata.DstPort = uint32(trans.DstPort)
				case *layers.UDP:
					pkt.Metadata.Transport = "UDP"
					pkt.Metadata.SrcPort = uint32(trans.SrcPort)
					pkt.Metadata.DstPort = uint32(trans.DstPort)
				}
			}

			// Populate protocol-specific metadata
			switch result.Protocol {
			case "SIP":
				if pkt.Metadata.Sip == nil {
					pkt.Metadata.Sip = &data.SIPMetadata{}
				}
				if method, ok := result.Metadata["method"].(string); ok {
					pkt.Metadata.Sip.Method = method
				}
				if fromUser, ok := result.Metadata["from_user"].(string); ok {
					pkt.Metadata.Sip.FromUser = fromUser
				}
				if toUser, ok := result.Metadata["to_user"].(string); ok {
					pkt.Metadata.Sip.ToUser = toUser
				}
				if callID, ok := result.Metadata["call_id"].(string); ok {
					pkt.Metadata.Sip.CallId = callID
				}
				if respCode, ok := result.Metadata["response_code"].(uint32); ok {
					pkt.Metadata.Sip.ResponseCode = respCode
				}

			case "RTP":
				if pkt.Metadata.Rtp == nil {
					pkt.Metadata.Rtp = &data.RTPMetadata{}
				}
				if ssrc, ok := result.Metadata["ssrc"].(uint32); ok {
					pkt.Metadata.Rtp.Ssrc = ssrc
				}
				if seqNum, ok := result.Metadata["sequence_number"].(uint16); ok {
					pkt.Metadata.Rtp.Sequence = uint32(seqNum)
				}
				if payloadType, ok := result.Metadata["payload_type"].(uint8); ok {
					pkt.Metadata.Rtp.PayloadType = uint32(payloadType)
				}
				if timestamp, ok := result.Metadata["timestamp"].(uint32); ok {
					pkt.Metadata.Rtp.Timestamp = timestamp
				}
			}
		}
	}
}

// buildInfoString creates display info string from detection metadata
func buildInfoString(protocol string, metadata map[string]interface{}) string {
	switch protocol {
	case "SSH":
		if versionStr, ok := metadata["version_string"].(string); ok {
			return versionStr
		}
		return "SSH"

	case "ICMP":
		if typeName, ok := metadata["type_name"].(string); ok {
			info := typeName
			if codeName, ok := metadata["code_name"].(string); ok && codeName != "" {
				info += " - " + codeName
			}
			return info
		}
		return "ICMP"

	case "DNS":
		return "DNS Query/Response"

	case "gRPC", "HTTP2":
		return "gRPC/HTTP2"

	case "DHCP", "BOOTP":
		if msgType, ok := metadata["message_type"].(string); ok {
			return msgType
		}
		return protocol

	case "NTP":
		if mode, ok := metadata["mode"].(string); ok {
			return "NTP " + mode
		}
		return "NTP"

	case "ARP":
		if op, ok := metadata["operation"].(string); ok {
			return op
		}
		return "ARP"

	case "OpenVPN":
		if typeName, ok := metadata["type_name"].(string); ok {
			return typeName
		}
		return "OpenVPN"

	case "WireGuard":
		if typeName, ok := metadata["type_name"].(string); ok {
			return typeName
		}
		return "WireGuard"

	case "L2TP":
		if packetType, ok := metadata["packet_type"].(string); ok {
			return packetType
		}
		return "L2TP"

	case "PPTP":
		if ctrlType, ok := metadata["control_type_name"].(string); ok {
			return ctrlType
		}
		return "PPTP"

	case "IKEv2", "IKEv1", "IKE":
		if exchangeName, ok := metadata["exchange_name"].(string); ok {
			if isResp, ok := metadata["is_response"].(bool); ok {
				if isResp {
					return exchangeName + " (response)"
				}
				return exchangeName + " (request)"
			}
			return exchangeName
		}
		return protocol

	case "SIP":
		// Check for SIP method (request) first
		if method, ok := metadata["method"].(string); ok && method != "" {
			return method
		}
		// Check for response code
		if respCode, ok := metadata["response_code"].(uint32); ok && respCode > 0 {
			return fmt.Sprintf("%d", respCode)
		}
		// Fallback to generic SIP
		return "SIP"

	case "RTP":
		// Show codec for RTP packets
		if payloadType, ok := metadata["payload_type"].(uint8); ok {
			codec := payloadTypeToCodec(payloadType)
			return codec
		}
		return "RTP stream"

	default:
		return protocol
	}
}

// payloadTypeToCodec maps RTP payload types to codec names
func payloadTypeToCodec(pt uint8) string {
	// Static payload types (0-95)
	staticCodecs := map[uint8]string{
		0:  "PCMU",
		3:  "GSM",
		4:  "G723",
		5:  "DVI4-8k",
		6:  "DVI4-16k",
		7:  "LPC",
		8:  "PCMA",
		9:  "G722",
		10: "L16-stereo",
		11: "L16-mono",
		12: "QCELP",
		13: "CN",
		14: "MPA",
		15: "G728",
		16: "DVI4-11k",
		17: "DVI4-22k",
		18: "G729",
		26: "JPEG",
		31: "H261",
		32: "MPV",
		33: "MP2T",
		34: "H263",
	}

	if codec, ok := staticCodecs[pt]; ok {
		return codec
	}

	// Dynamic payload types (96-127)
	if pt >= 96 && pt <= 127 {
		return fmt.Sprintf("Dynamic-%d", pt)
	}

	return fmt.Sprintf("PT-%d", pt)
}
