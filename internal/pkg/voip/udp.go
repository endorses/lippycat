package voip

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/monitoring"
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
