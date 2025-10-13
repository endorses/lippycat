package voip

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/monitoring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

func handleUdpPackets(pkt capture.PacketInfo, layer *layers.UDP) {
	start := time.Now()
	packet := pkt.Packet
	ctx := context.Background()

	// Start tracing span for UDP packet processing
	span, tracingCtx, finishTrace := monitoring.TracePacketProcessing(ctx, "udp")
	defer finishTrace()

	// Process through plugin system if enabled
	if err := ProcessPacketWithPlugins(tracingCtx, packet); err != nil {
		logger.Debug("Plugin processing error for UDP packet", "error", err)
		monitoring.TraceError(tracingCtx, err, "Plugin processing failed")
	}

	// Record packet processing metrics
	defer func() {
		duration := time.Since(start)
		monitoring.RecordPacket(tracingCtx, "udp", "inbound", duration)
		if span != nil {
			span.AddTag("packet_size", len(packet.Data()))
			span.AddTag("src_port", layer.SrcPort.String())
			span.AddTag("dst_port", layer.DstPort.String())
		}
	}()

	// Use buffering if buffer manager is initialized
	if globalBufferMgr != nil {
		handleUdpPacketsWithBuffer(pkt, layer, tracingCtx)
	} else {
		// Fallback to immediate processing (no buffering)
		handleUdpPacketsImmediate(pkt, layer, tracingCtx)
	}
}

func handleUdpPacketsImmediate(pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context) {
	packet := pkt.Packet

	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				logger.Debug("Failed to assert UDP layer type")
				return
			}
			payload := udp.Payload
			if !handleSipMessage(payload) {
				return
			}
			headers, body := parseSipHeaders(payload)
			callID := headers["call-id"]
			if callID != "" {
				// Validate the Call-ID for security
				if err := ValidateCallIDForSecurity(callID); err != nil {
					logger.Warn("Malicious Call-ID detected and rejected",
						"call_id", SanitizeCallIDForLogging(callID),
						"error", err,
						"source", "udp_processing")
					return
				}
				call := GetOrCreateCall(callID, pkt.LinkType)
				if call != nil {
					// Record call tracking event
					monitoring.RecordCallEvent(tracingCtx, callID, "sip_packet", map[string]interface{}{
						"protocol": "sip",
						"method":   "unknown", // Would be extracted from SIP headers
						"src_port": layer.SrcPort.String(),
						"dst_port": layer.DstPort.String(),
					})
				}

				if viper.GetViper().GetBool("writeVoip") {
					WriteSIP(callID, packet)
				} else {
					logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
				}
				bodyBytes := StringToBytes(body)
				if BytesContains(bodyBytes, []byte("m=audio")) {
					ExtractPortFromSdp(body, callID)
				}
			}
		}
	} else if IsTracked(packet) {
		callID := GetCallIDForPacket(packet)
		if viper.GetViper().GetBool("writeVoip") {
			WriteRTP(callID, packet)
		} else {
			logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
		}
	}
}

// handleUdpPacketsWithBuffer processes UDP packets with buffering for call filtering
func handleUdpPacketsWithBuffer(pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context) {
	packet := pkt.Packet

	// Handle SIP packets (port 5060)
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if !ok {
				logger.Debug("Failed to assert UDP layer type")
				return
			}
			payload := udp.Payload
			if !handleSipMessage(payload) {
				return
			}
			headers, body := parseSipHeaders(payload)
			callID := headers["call-id"]
			if callID == "" {
				return
			}

			// Validate Call-ID for security
			if err := ValidateCallIDForSecurity(callID); err != nil {
				logger.Warn("Malicious Call-ID detected and rejected",
					"call_id", SanitizeCallIDForLogging(callID),
					"error", err,
					"source", "udp_buffered")
				return
			}

			// Extract SIP metadata
			metadata := &CallMetadata{
				CallID:            callID,
				From:              headers["from"],
				To:                headers["to"],
				PAssertedIdentity: headers["p-asserted-identity"],
				Method:            detectSipMethod(string(payload)),
				SDPBody:           body,
			}

			// Buffer the SIP packet
			globalBufferMgr.AddSIPPacket(callID, packet, metadata)

			// Check filter if we have SDP (INVITE or 200 OK with m=audio)
			bodyBytes := StringToBytes(body)
			if BytesContains(bodyBytes, []byte("m=audio")) {
				matched, bufferedPackets := globalBufferMgr.CheckFilter(callID, func(m *CallMetadata) bool {
					// Check if From, To, or P-Asserted-Identity matches tracked users
					return containsUserInHeaders(map[string]string{
						"from":                m.From,
						"to":                  m.To,
						"p-asserted-identity": m.PAssertedIdentity,
					})
				})

				if matched {
					// Create call tracker entry
					call := GetOrCreateCall(callID, pkt.LinkType)
					if call != nil {
						monitoring.RecordCallEvent(tracingCtx, callID, "sip_matched", map[string]interface{}{
							"from": metadata.From,
							"to":   metadata.To,
						})
					}

					// Write all buffered packets to file
					if viper.GetViper().GetBool("writeVoip") {
						for _, buffPkt := range bufferedPackets {
							// Determine if packet is SIP or RTP and write accordingly
							if isSIPPacket(buffPkt) {
								WriteSIP(callID, buffPkt)
							} else {
								WriteRTP(callID, buffPkt)
							}
						}
					}

					// Extract RTP ports from SDP for future RTP association
					ExtractPortFromSdp(body, callID)
				}
				// If not matched, buffer is automatically discarded by CheckFilter
			}
		}
	} else {
		// Potentially RTP packet - check if it belongs to a tracked call
		callID := GetCallIDForPacket(packet)
		if callID != "" {
			// Check if this is a port we're tracking
			dstPort := layer.DstPort.String()
			srcPort := layer.SrcPort.String()

			// Try to get CallID from buffer manager's port mapping
			bufCallID, exists := globalBufferMgr.GetCallIDForRTPPort(dstPort)
			if !exists {
				bufCallID, exists = globalBufferMgr.GetCallIDForRTPPort(srcPort)
			}

			if exists {
				// This RTP packet belongs to a call we're buffering
				shouldWrite := globalBufferMgr.AddRTPPacket(bufCallID, dstPort, packet)

				if shouldWrite {
					// Call already matched, write immediately
					if viper.GetViper().GetBool("writeVoip") {
						WriteRTP(bufCallID, packet)
					}
				}
				// Otherwise packet is buffered, waiting for filter decision
			} else if IsTracked(packet) {
				// Call already decided and tracker knows about it
				if viper.GetViper().GetBool("writeVoip") {
					WriteRTP(callID, packet)
				}
			}
		}
	}
}

// isSIPPacket checks if a packet is a SIP packet (port 5060)
func isSIPPacket(packet gopacket.Packet) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok {
			return udp.SrcPort == SIPPort || udp.DstPort == SIPPort
		}
	}
	return false
}
