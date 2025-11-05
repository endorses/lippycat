package processor

import (
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// processBatch processes a received packet batch
func (p *Processor) processBatch(batch *data.PacketBatch) {
	hunterID := batch.HunterId

	logger.Debug("Received packet batch",
		"hunter_id", hunterID,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	// Update hunter statistics
	p.hunterManager.UpdatePacketStats(hunterID, uint64(len(batch.Packets)), batch.TimestampNs)

	// Queue packets for async PCAP write if configured
	if p.pcapWriter != nil {
		p.pcapWriter.QueuePackets(batch.Packets)
	}

	// Update processor statistics (atomic increment)
	p.packetsReceived.Add(uint64(len(batch.Packets)))

	// Enrich packets with protocol detection if enabled
	if p.enricher != nil {
		p.enricher.Enrich(batch.Packets)
	}

	// Aggregate VoIP call state from packet metadata
	if p.callAggregator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil) {
				p.callAggregator.ProcessPacket(packet, hunterID)
			}
		}
	}

	// Correlate SIP calls across B2BUA boundaries
	if p.callCorrelator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && packet.Metadata.Sip != nil {
				p.callCorrelator.ProcessPacket(packet, hunterID)
			}
		}
	}

	// Write VoIP packets to per-call PCAP files if configured
	// Writes separate SIP and RTP files for each call
	if p.perCallPcapWriter != nil {
		for _, packet := range batch.Packets {
			// Check if packet has SIP metadata with call-id
			if packet.Metadata != nil && packet.Metadata.Sip != nil && packet.Metadata.Sip.CallId != "" {
				callID := packet.Metadata.Sip.CallId
				from := packet.Metadata.Sip.FromUser
				to := packet.Metadata.Sip.ToUser

				// Get or create writer for this call
				writer, err := p.perCallPcapWriter.GetOrCreateWriter(callID, from, to)
				if err != nil {
					logger.Warn("Failed to get/create PCAP writer for call",
						"call_id", callID,
						"error", err)
					continue
				}

				// Write packet to appropriate file (SIP or RTP) using raw packet data
				if len(packet.Data) > 0 {
					timestamp := time.Unix(0, packet.TimestampNs)

					// Check if this is an RTP packet (has RTP metadata)
					if packet.Metadata.Rtp != nil {
						// Write to RTP PCAP file
						if err := writer.WriteRTPPacket(timestamp, packet.Data); err != nil {
							logger.Warn("Failed to write RTP packet to call PCAP",
								"call_id", callID,
								"error", err)
						}
					} else {
						// Write to SIP PCAP file
						if err := writer.WriteSIPPacket(timestamp, packet.Data); err != nil {
							logger.Warn("Failed to write SIP packet to call PCAP",
								"call_id", callID,
								"error", err)
						}
					}
				}
			}
		}
	}

	// Write non-VoIP packets to auto-rotating PCAP files if configured
	// Auto-rotates based on idle time, file size, and duration
	if p.autoRotatePcapWriter != nil {
		for _, packet := range batch.Packets {
			// Skip VoIP packets (they're handled by per-call writer)
			isVoIP := packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil)
			if isVoIP {
				continue
			}

			// Write non-VoIP packet to auto-rotating PCAP
			if len(packet.Data) > 0 {
				timestamp := time.Unix(0, packet.TimestampNs)
				if err := p.autoRotatePcapWriter.WritePacket(timestamp, packet.Data); err != nil {
					logger.Warn("Failed to write packet to auto-rotate PCAP", "error", err)
				}
			}
		}
	}

	// Forward to upstream in hierarchical mode
	if p.upstreamManager != nil {
		p.upstreamManager.Forward(batch)
	}

	// Broadcast to monitoring subscribers (TUI clients)
	p.subscriberManager.Broadcast(batch)

	// Inject packets to virtual interface if configured
	if p.vifManager != nil {
		// Convert packet batch to PacketDisplay for injection
		// We need to convert the protobuf packets to types.PacketDisplay format
		displayPackets := make([]types.PacketDisplay, 0, len(batch.Packets))
		for _, pkt := range batch.Packets {
			display := types.PacketDisplay{
				Timestamp: time.Unix(0, pkt.TimestampNs),
				RawData:   pkt.Data,                      // Raw packet bytes (includes Ethernet header if LinkType is Ethernet)
				LinkType:  layers.LinkType(pkt.LinkType), // Link layer type (Ethernet, Raw IP, etc.)
			}

			// Copy metadata if available
			if pkt.Metadata != nil {
				display.SrcIP = pkt.Metadata.SrcIp
				display.DstIP = pkt.Metadata.DstIp
				display.Protocol = pkt.Metadata.Protocol
			}

			displayPackets = append(displayPackets, display)
		}

		// Inject batch (non-blocking)
		if err := p.vifManager.InjectPacketBatch(displayPackets); err != nil {
			logger.Debug("Failed to inject packet batch to virtual interface", "error", err)
		}
	}
}
