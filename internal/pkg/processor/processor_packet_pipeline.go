//go:build processor || tap || all

// Package processor - Packet Processing Pipeline
//
// This file contains the core packet processing logic for the processor:
//   - processBatch() - Main packet processing pipeline
//
// The processBatch() method processes packets in the following order:
//  1. Update hunter statistics
//  2. Queue to unified PCAP writer (async)
//  3. Increment packet counters
//  4. Enrich packets with protocol detection (if enabled)
//  5. Aggregate VoIP calls and correlate B2BUA calls (if VoIP aggregator enabled)
//  6. Aggregate DNS tunneling statistics from hunter-provided metadata
//  7. Process LI (Lawful Interception) if enabled (build tag: li)
//  8. Write per-call PCAP files (SIP and RTP separated, if enabled)
//  9. Write auto-rotating PCAP files for non-VoIP traffic (if enabled)
//  10. Forward to upstream processor (if hierarchical mode)
//  11. Broadcast to TUI subscribers (with per-subscriber buffering)
//  12. Inject to virtual interface (if enabled)
//
// Key Design Decisions:
//   - Non-blocking: All I/O operations are async (queues, channels, goroutines)
//   - Per-subscriber buffering: Slow TUI clients don't block hunters
//   - Separate VoIP handling: Per-call PCAP writer handles VoIP, auto-rotate handles non-VoIP
//   - Flow control: Based on processor state (PCAP queue), not subscriber drops
package processor

import (
	"strconv"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// processBatch processes a received packet batch using the source.PacketBatch abstraction.
// This supports both gRPC (distributed) and local (standalone tap) packet sources.
func (p *Processor) processBatch(batch *source.PacketBatch) {
	sourceID := batch.SourceID

	logger.Debug("Received packet batch",
		"source_id", sourceID,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	// Update hunter statistics (only for gRPC sources with hunter IDs)
	if p.hunterManager != nil && sourceID != "" && sourceID != "local" {
		p.hunterManager.UpdatePacketStats(sourceID, uint64(len(batch.Packets)), batch.TimestampNs)
	}

	// Queue packets for async PCAP write if configured
	if p.pcapWriter != nil {
		p.pcapWriter.QueuePackets(batch.Packets)
	}

	// Update processor statistics (atomic increment)
	p.packetsReceived.Add(uint64(len(batch.Packets)))

	// Process TLS session keys from packets (for decryption support)
	if p.tlsKeylogWriter != nil {
		for _, packet := range batch.Packets {
			if packet.TlsKeys != nil {
				p.tlsKeylogWriter.ProcessPacketKeys(packet)
			}
		}
	}

	// Enrich packets with protocol detection if enabled
	if p.enricher != nil {
		p.enricher.Enrich(batch.Packets)
	}

	// Aggregate VoIP call state from packet metadata
	if p.callAggregator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil) {
				p.callAggregator.ProcessPacket(packet, sourceID)
			}
		}
	}

	// Correlate SIP calls across B2BUA boundaries
	if p.callCorrelator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && packet.Metadata.Sip != nil {
				p.callCorrelator.ProcessPacket(packet, sourceID)
			}
		}
	}

	// Aggregate DNS tunneling statistics from hunter-provided metadata
	// This builds a cross-hunter view of suspicious domains
	if p.dnsTunneling != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && packet.Metadata.Dns != nil {
				dnsProto := packet.Metadata.Dns
				// Convert proto DNS metadata to types.DNSMetadata for analysis
				dnsMeta := &types.DNSMetadata{
					QueryName:      dnsProto.QueryName,
					QueryType:      dnsProto.QueryType,
					IsResponse:     dnsProto.IsResponse,
					TunnelingScore: dnsProto.TunnelingScore,
					EntropyScore:   dnsProto.EntropyScore,
				}
				// Extract source IP from packet metadata for tracking
				srcIP := ""
				if packet.Metadata != nil {
					srcIP = packet.Metadata.SrcIp
				}
				// AnalyzeWithContext updates aggregated domain statistics with hunter/source tracking
				p.dnsTunneling.AnalyzeWithContext(dnsMeta, sourceID, srcIP)
			}
		}
	}

	// Process LI (Lawful Interception) if enabled
	// This is a no-op if built without -tags li or if LI is not enabled
	if p.isLIEnabled() {
		for _, pkt := range batch.Packets {
			// Skip packets without matched filter IDs (not targeted by LI)
			if len(pkt.MatchedFilterIds) == 0 {
				continue
			}

			// Convert to PacketDisplay for LI processing
			display := types.PacketDisplay{
				Timestamp: time.Unix(0, pkt.TimestampNs),
				RawData:   pkt.Data,
				LinkType:  layers.LinkType(pkt.LinkType),
			}
			if pkt.Metadata != nil {
				display.SrcIP = pkt.Metadata.SrcIp
				display.DstIP = pkt.Metadata.DstIp
				display.Protocol = pkt.Metadata.Protocol
				display.SrcPort = strconv.FormatUint(uint64(pkt.Metadata.SrcPort), 10)
				display.DstPort = strconv.FormatUint(uint64(pkt.Metadata.DstPort), 10)
			}

			// Use per-packet filter IDs for LI correlation
			p.processLIPacket(&display, pkt.MatchedFilterIds)
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
					linkType := layers.LinkType(packet.LinkType)

					// Check if this is an RTP packet (has RTP metadata)
					if packet.Metadata.Rtp != nil {
						// Write to RTP PCAP file
						if err := writer.WriteRTPPacket(timestamp, packet.Data, linkType); err != nil {
							logger.Warn("Failed to write RTP packet to call PCAP",
								"call_id", callID,
								"error", err)
						}
					} else {
						// Write to SIP PCAP file
						if err := writer.WriteSIPPacket(timestamp, packet.Data, linkType); err != nil {
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
				linkType := layers.LinkType(packet.LinkType)
				if err := p.autoRotatePcapWriter.WritePacket(timestamp, packet.Data, linkType); err != nil {
					logger.Warn("Failed to write packet to auto-rotate PCAP", "error", err)
				}
			}
		}
	}

	// Convert to protobuf batch for upstream forwarding and subscriber broadcast
	protoBatch := batch.ToProtoBatch()

	// Forward to upstream in hierarchical mode
	if p.upstreamManager != nil {
		p.upstreamManager.Forward(protoBatch)
	}

	// Broadcast to monitoring subscribers (TUI clients)
	p.subscriberManager.Broadcast(protoBatch)

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
			p.vifInjectionErrors.Add(1)
			logger.Warn("Failed to inject packet batch to virtual interface", "error", err)
		}
	}
}
