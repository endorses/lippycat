package voip

import (
	"bytes"
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/endorses/lippycat/internal/pkg/voip/monitoring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func handleUdpPackets(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP) {
	start := time.Now()
	packet := pkt.Packet
	ctx := context.Background()

	logger.Debug("handleUdpPackets called", "src_port", layer.SrcPort, "dst_port", layer.DstPort)

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
		logger.Debug("Using buffered UDP processing")
		handleUdpPacketsWithBuffer(tracker, pkt, layer, tracingCtx)
	} else {
		logger.Debug("Using immediate UDP processing")
		// Fallback to immediate processing (no buffering)
		handleUdpPacketsImmediate(tracker, pkt, layer, tracingCtx)
	}
}

func handleUdpPacketsWithTracker(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP) {
	handleUdpPackets(tracker, pkt, layer)
}

func handleUdpPacketsImmediate(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context) {
	packet := pkt.Packet

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			logger.Debug("Failed to assert UDP layer type")
			return
		}
		payload := udp.Payload

		// Analyze through the shared parser/selection/registry path.
		analysis := sniffSIPMessage(pkt, payload, sipParseOptions(packet, layer), tracker, true, true)
		if analysis.Stage.Outcome == pipeline.OutcomeAccepted {
			callID := analysis.SIP.CallID
			if callID != "" {
				call, _ := tracker.GetCall(callID)
				if call != nil {
					// Record call tracking event
					monitoring.RecordCallEvent(tracingCtx, callID, "sip_packet", map[string]interface{}{
						"protocol": "sip",
						"method":   "unknown", // Would be extracted from SIP headers
						"src_port": layer.SrcPort.String(),
						"dst_port": layer.DstPort.String(),
					})
				}

				delivery := (sniffSink{tracker: tracker}).HandleSIP(tracingCtx, sipflow.SinkInput{Result: analysis.SIP, Attachment: pkt})
				if delivery.Outcome != pipeline.OutcomeAccepted {
					logger.Warn("Failed to deliver UDP SIP packet", "call_id", SanitizeCallIDForLogging(callID))
				} else if !tracker.config.WriteVoIP {
					logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
				}
			}
			return // SIP packet processed, done
		}
	}

	// Not a SIP packet - check if it's RTP for a tracked call
	if tracker.IsTracked(packet) {
		// It's an RTP packet for a tracked call - inject into virtual interface
		injectPacketToVirtualInterface(pkt)

		callID := tracker.GetCallIDForPacket(packet)
		if tracker.config.WriteVoIP {
			WriteRTP(tracker, callID, packet)
		} else {
			logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
		}
	}
}

// handleUdpPacketsWithBuffer processes UDP packets with buffering for call filtering
func handleUdpPacketsWithBuffer(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context) {
	packet := pkt.Packet

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			logger.Debug("Failed to assert UDP layer type")
			return
		}
		payload := udp.Payload

		analysis := sniffSIPMessage(pkt, payload, sipParseOptions(packet, layer), tracker, false, false)
		if analysis.Stage.Outcome == pipeline.OutcomeAccepted {
			callID := analysis.SIP.CallID

			// Extract SIP metadata
			metadata := callMetadataFromSIPResult(analysis.SIP)

			// Buffer the SIP packet with link type for proper PCAP writing.
			// Returns true once the call is matched, from which point every SIP
			// packet of the call is written directly instead of buffered.
			alreadyMatched := globalBufferMgr.AddSIPPacket(callID, packet, metadata, pkt.Interface, pkt.LinkType)

			hasSDP := BytesContains(analysis.SIP.SDP, []byte("m=audio"))

			if alreadyMatched {
				// Call already passed the filter: write this packet now,
				// whether or not it carries SDP.
				if _, err := (sniffRegistry{tracker: tracker}).Observe(analysis.SIP); err != nil {
					logger.Warn("Failed to update UDP SIP call", "call_id", SanitizeCallIDForLogging(callID), "error", err)
					return
				}
				delivery := (sniffSink{tracker: tracker}).HandleSIP(tracingCtx, sipflow.SinkInput{Result: analysis.SIP, Attachment: pkt})
				if delivery.Outcome != pipeline.OutcomeAccepted {
					logger.Warn("Failed to deliver buffered UDP SIP packet", "call_id", SanitizeCallIDForLogging(callID))
				} else if !tracker.config.WriteVoIP {
					logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
				}
				return
			}

			// Check filter if we have SDP (INVITE or 200 OK with m=audio)
			if hasSDP {
				// Use callback-based filter check for flexible handling
				matched := globalBufferMgr.CheckFilterWithCallback(
					callID,
					func(m *CallMetadata) bool {
						// Check if From, To, or P-Asserted-Identity matches tracked users
						return containsUserInHeaders(map[string]string{
							"from":                m.From,
							"to":                  m.To,
							"p-asserted-identity": m.PAssertedIdentity,
						})
					},
					func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
						if _, err := (sniffRegistry{tracker: tracker}).Observe(analysis.SIP); err != nil {
							logger.Warn("Failed to update matched UDP SIP call", "call_id", SanitizeCallIDForLogging(callID), "error", err)
							return
						}
						call, _ := tracker.GetCall(callID)
						if call != nil {
							monitoring.RecordCallEvent(tracingCtx, callID, "sip_matched", map[string]interface{}{
								"from": metadata.From,
								"to":   metadata.To,
							})
						}

						// Write all buffered packets using helper
						// Preserve legacy behavior: the current matching packet is
						// injected once before the buffered PCAP writes.
						injectPacketToVirtualInterface(pkt)
						handleMatchedCallForFileWrite(tracker, callID, packets, metadata)
					},
				)
				_ = matched // Callback already handled everything
			}
			return // SIP packet processed, done
		}
	}

	// Not a SIP packet - check if it's RTP for a tracked call
	{
		// Potentially RTP packet - check if it belongs to a tracked call
		callID := tracker.GetCallIDForPacket(packet)
		if callID != "" {
			// Check if this is a port we're tracking
			dstPort := layer.DstPort.String()
			srcPort := layer.SrcPort.String()

			// Extract IP addresses for IP:PORT endpoint lookups
			var dstIP, srcIP string
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				dstIP = netLayer.NetworkFlow().Dst().String()
				srcIP = netLayer.NetworkFlow().Src().String()
			}

			// Try to get CallID from buffer manager's port mapping
			// Check IP:PORT endpoints first (more specific), then fall back to port-only
			var bufCallID string
			var exists bool

			if dstIP != "" {
				bufCallID, exists = globalBufferMgr.GetCallIDForRTPPort(dstIP + ":" + dstPort)
			}
			if !exists && srcIP != "" {
				bufCallID, exists = globalBufferMgr.GetCallIDForRTPPort(srcIP + ":" + srcPort)
			}
			// Fall back to port-only lookups
			if !exists {
				bufCallID, exists = globalBufferMgr.GetCallIDForRTPPort(dstPort)
			}
			if !exists {
				bufCallID, exists = globalBufferMgr.GetCallIDForRTPPort(srcPort)
			}

			if exists {
				// This RTP packet belongs to a call we're buffering
				// Use IP:PORT for the port parameter if available for more precise matching
				portKey := dstPort
				if dstIP != "" {
					portKey = dstIP + ":" + dstPort
				}
				shouldWrite := globalBufferMgr.AddRTPPacket(bufCallID, portKey, packet)

				if shouldWrite {
					// Call already matched, inject into virtual interface and write immediately
					injectPacketToVirtualInterface(pkt)

					if tracker.config.WriteVoIP {
						WriteRTP(tracker, bufCallID, packet)
					}
				}
				// Otherwise packet is buffered, waiting for filter decision
			} else if tracker.IsTracked(packet) {
				// Call already decided and tracker knows about it, inject into virtual interface
				injectPacketToVirtualInterface(pkt)

				if tracker.config.WriteVoIP {
					WriteRTP(tracker, callID, packet)
				}
			}
		}
	}
}

func sipParseOptions(packet gopacket.Packet, layer *layers.UDP) sharedsip.ParseOptions {
	opts := sharedsip.ParseOptions{
		Timestamp:       packet.Metadata().Timestamp,
		SourcePort:      uint16(layer.SrcPort),
		DestinationPort: uint16(layer.DstPort),
	}
	if network := packet.NetworkLayer(); network != nil {
		opts.SourceIP = network.NetworkFlow().Src().String()
		opts.DestinationIP = network.NetworkFlow().Dst().String()
	}
	return opts
}

// isSIPPacket checks if a packet is a SIP packet using content-based detection
func isSIPPacket(_ *CallTracker, packet gopacket.Packet) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok {
			payload := udp.Payload
			if len(payload) == 0 {
				return false
			}
			// Buffered packets have already been parsed by sipflow. Classify them
			// from the SIP start line here so output routing does not parse the
			// same message a second time.
			lineEnd := bytes.IndexByte(payload, '\n')
			if lineEnd < 0 {
				lineEnd = len(payload)
			}
			if lineEnd > 0 && payload[lineEnd-1] == '\r' {
				lineEnd--
			}
			return sharedsip.IsStartLine(string(payload[:lineEnd]))
		}
	}
	return false
}

// handleMatchedCallForFileWrite is a callback for BufferManager that writes packets to files
func handleMatchedCallForFileWrite(tracker *CallTracker, callID string, packets []gopacket.Packet, metadata *CallMetadata) {
	if !tracker.config.WriteVoIP {
		return
	}

	// Write all buffered packets
	for _, packet := range packets {
		if isSIPPacket(tracker, packet) {
			WriteSIP(tracker, callID, packet)
		} else {
			WriteRTP(tracker, callID, packet)
		}
	}
}
