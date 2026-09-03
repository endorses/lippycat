package voip

import (
	"bytes"
	"context"
	"strconv"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/endorses/lippycat/internal/pkg/voip/monitoring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func handleUdpPackets(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP) {
	handleUdpPacketsWithManager(tracker, pkt, layer, globalBufferMgr)
}

func handleUdpPacketsWithManager(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, buffer *BufferManager) {
	handleUdpPacketsWithManagerAndOutputs(tracker, pkt, layer, buffer, nil)
}

func handleUdpPacketsWithManagerAndOutputs(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, buffer *BufferManager, outputs *pipeline.PacketFanout) {
	start := time.Now()
	packet := pkt.Packet
	ctx := context.Background()

	logger.Debug("handleUdpPackets called", "src_port", layer.SrcPort, "dst_port", layer.DstPort)

	// Start tracing span for UDP packet processing
	span, tracingCtx, finishTrace := monitoring.TracePacketProcessing(ctx, "udp")
	defer finishTrace()

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
	if buffer != nil {
		logger.Debug("Using buffered UDP processing")
		handleUdpPacketsWithBufferAndOutputs(tracker, pkt, layer, tracingCtx, buffer, outputs)
	} else {
		logger.Debug("Using immediate UDP processing")
		// Fallback to immediate processing (no buffering)
		handleUdpPacketsImmediateWithOutputs(tracker, pkt, layer, tracingCtx, outputs)
	}
}

func handleUdpPacketsWithTracker(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP) {
	handleUdpPackets(tracker, pkt, layer)
}

func handleUdpPacketsImmediate(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context) {
	handleUdpPacketsImmediateWithOutputs(tracker, pkt, layer, tracingCtx, nil)
}

func handleUdpPacketsImmediateWithOutputs(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context, outputs *pipeline.PacketFanout) {
	packet := pkt.Packet

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			logger.Debug("Failed to assert UDP layer type")
			return
		}
		payload := udp.Payload

		// Analyze through the shared parser/selection/registry path.
		flow, analysis := sniffSIPMessageWithOutputs(pkt, payload, sipParseOptions(packet, layer), tracker, true, true, outputs)
		defer flow.Close()
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

				analysis.Attachment = pkt
				delivery := flow.Dispatch(analysis)
				if delivery.Sinks[sniffSIPSinkName].Outcome != pipeline.OutcomeAccepted {
					logger.Warn("Failed to deliver UDP SIP packet", "call_id", SanitizeCallIDForLogging(callID))
				} else if !tracker.config.WriteVoIP {
					logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
				}
			}
			return // SIP packet processed, done
		}
	}

	// Not a SIP packet - check if it's RTP for a tracked call
	resolution := tracker.ResolveMediaPacket(packet)
	if resolution.Status == callregistry.MediaResolved {
		dispatchSelectedPacket(outputs, pkt)

		callID := resolution.CallID
		if tracker.config.WriteVoIP {
			WriteRTP(tracker, callID, packet)
		} else {
			logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
		}
	}
}

// handleUdpPacketsWithBuffer processes UDP packets with buffering for call filtering
func handleUdpPacketsWithBuffer(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context, buffers ...*BufferManager) {
	buffer := globalBufferMgr
	if len(buffers) > 0 {
		buffer = buffers[0]
	}
	handleUdpPacketsWithBufferAndOutputs(tracker, pkt, layer, tracingCtx, buffer, nil)
}

func handleUdpPacketsWithBufferAndOutputs(tracker *CallTracker, pkt capture.PacketInfo, layer *layers.UDP, tracingCtx context.Context, buffer *BufferManager, outputs *pipeline.PacketFanout) {
	packet := pkt.Packet

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			logger.Debug("Failed to assert UDP layer type")
			return
		}
		payload := udp.Payload

		flow, analysis := sniffSIPMessageWithOutputs(pkt, payload, sipParseOptions(packet, layer), tracker, false, false, outputs, buffer)
		defer flow.Close()
		if analysis.Stage.Outcome == pipeline.OutcomeAccepted {
			callID := analysis.SIP.CallID

			// Extract SIP metadata
			metadata := callMetadataFromSIPResult(analysis.SIP)

			// Buffer the SIP packet with link type for proper PCAP writing.
			// Returns true once the call is matched, from which point every SIP
			// packet of the call is written directly instead of buffered.
			alreadyMatched := buffer.AddSIPResult(callID, packet, analysis.SIP, metadata, pkt.Interface, pkt.LinkType)

			hasSDP := BytesContains(analysis.SIP.SDP, []byte("m=audio"))

			if alreadyMatched {
				// Call already passed the filter: write this packet now,
				// whether or not it carries SDP.
				if _, err := (sniffRegistry{tracker: tracker}).Observe(analysis.SIP); err != nil {
					logger.Warn("Failed to update UDP SIP call", "call_id", SanitizeCallIDForLogging(callID), "error", err)
					return
				}
				analysis.Attachment = pkt
				delivery := flow.Dispatch(analysis)
				if delivery.Sinks[sniffSIPSinkName].Outcome != pipeline.OutcomeAccepted {
					logger.Warn("Failed to deliver buffered UDP SIP packet", "call_id", SanitizeCallIDForLogging(callID))
				} else if !tracker.config.WriteVoIP {
					logger.Info("SIP packet processed", "call_id", SanitizeCallIDForLogging(callID), "packet", packet)
				}
				return
			}

			// Check filter if we have SDP (INVITE or 200 OK with m=audio)
			if hasSDP {
				// Use callback-based filter check for flexible handling
				matched := buffer.CheckFilterWithTypedCallback(
					callID,
					func(m *CallMetadata) bool {
						// Check if From, To, or P-Asserted-Identity matches tracked users
						return containsUserInHeaders(map[string]string{
							"from":                m.From,
							"to":                  m.To,
							"p-asserted-identity": m.PAssertedIdentity,
						})
					},
					func(callID string, sipPackets []BufferedSIPPacket, rtpPackets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
						releaseBufferedSniffPacketsWithOutputs(tracker, callID, sipPackets, rtpPackets, interfaceName, linkType, buffer, outputs)
						call, _ := tracker.GetCall(callID)
						if call != nil {
							monitoring.RecordCallEvent(tracingCtx, callID, "sip_matched", map[string]interface{}{
								"from": metadata.From,
								"to":   metadata.To,
							})
						}

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
		resolution := tracker.ResolveMediaPacket(packet)
		if resolution.Status == callregistry.MediaResolved {
			callID := resolution.CallID
			// Check if this is a port we're tracking
			dstPort := strconv.Itoa(int(layer.DstPort))
			srcPort := strconv.Itoa(int(layer.SrcPort))

			// Extract IP addresses for IP:PORT endpoint lookups
			var dstIP, srcIP string
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				dstIP = netLayer.NetworkFlow().Dst().String()
				srcIP = netLayer.NetworkFlow().Src().String()
			}

			bufCallID := callID
			sourceEndpoint := srcIP + ":" + srcPort
			destinationEndpoint := dstIP + ":" + dstPort
			shouldWrite, accepted := buffer.AddRTPPacketForEndpoints(bufCallID, sourceEndpoint, destinationEndpoint, packet)
			if accepted {

				if shouldWrite {
					// Call already matched, inject into virtual interface and write immediately
					dispatchSelectedPacket(outputs, pkt)

					if tracker.config.WriteVoIP {
						WriteRTP(tracker, bufCallID, packet)
					}
				}
				// Otherwise packet is buffered, waiting for filter decision
			} else {
				// Call already decided and tracker knows about it, inject into virtual interface
				dispatchSelectedPacket(outputs, pkt)

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

// releaseBufferedSniffPackets publishes the original typed SIP results through
// the shared registry and queued sink, then preserves legacy RTP file output.
func releaseBufferedSniffPackets(tracker *CallTracker, callID string, sipPackets []BufferedSIPPacket, rtpPackets []gopacket.Packet, interfaceName string, linkType layers.LinkType, buffers ...*BufferManager) map[string]sipflow.SinkStats {
	var buffer *BufferManager
	if len(buffers) > 0 {
		buffer = buffers[0]
	}
	return releaseBufferedSniffPacketsWithOutputs(tracker, callID, sipPackets, rtpPackets, interfaceName, linkType, buffer, nil)
}

func releaseBufferedSniffPacketsWithOutputs(tracker *CallTracker, callID string, sipPackets []BufferedSIPPacket, rtpPackets []gopacket.Packet, interfaceName string, linkType layers.LinkType, buffer *BufferManager, outputs *pipeline.PacketFanout) map[string]sipflow.SinkStats {
	flow := newSniffSIPFlowWithOutputs(tracker, false, false, outputs, buffer)
	registry := sniffRegistry{tracker: tracker, buffer: buffer}
	for _, buffered := range sipPackets {
		if _, err := registry.Observe(buffered.Result); err != nil {
			logger.Warn("Failed to update buffered UDP SIP call", "call_id", SanitizeCallIDForLogging(callID), "error", err)
			continue
		}
		info := capture.PacketInfo{Packet: buffered.Packet, Interface: interfaceName, LinkType: linkType}
		analysis := sipflow.ProcessResult{
			SIP: buffered.Result, Stage: pipeline.Result{Outcome: pipeline.OutcomeAccepted}, Attachment: info,
		}
		delivery := flow.Dispatch(analysis)
		if delivery.Sinks[sniffSIPSinkName].Outcome != pipeline.OutcomeAccepted {
			logger.Warn("Failed to deliver buffered UDP SIP packet", "call_id", SanitizeCallIDForLogging(callID))
		}
	}
	if tracker.config.WriteVoIP {
		for _, packet := range rtpPackets {
			WriteRTP(tracker, callID, packet)
		}
	}
	for _, packet := range rtpPackets {
		dispatchSelectedPacket(outputs, capture.PacketInfo{Packet: packet, Interface: interfaceName, LinkType: linkType})
	}
	flow.Close()
	return flow.Stats()
}

func dispatchSelectedPacket(outputs *pipeline.PacketFanout, pkt capture.PacketInfo) {
	if outputs == nil {
		return
	}
	outputs.Dispatch(context.Background(), captureadapter.FromPacketInfo(pkt, pipeline.SourceLiveCapture))
}
