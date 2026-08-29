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
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// processBatch processes a received packet batch using the source.PacketBatch abstraction.
// This supports both gRPC (distributed) and local (standalone tap) packet sources.
func (p *Processor) processBatch(batch *source.PacketBatch) {
	// Complete local lifecycle transitions after the processing attempt on every
	// exit path, including normalization/encoding failures.
	defer batch.RunAfterProcess()

	sourceID := batch.SourceID
	protoBatch, err := batch.ToProtoBatchE()
	if err != nil {
		logger.Error("Failed to project normalized packet batch", "error", err, "source_id", sourceID, "sequence", batch.Sequence)
		return
	}
	packets := protoBatch.Packets

	logger.Debug("Received packet batch",
		"source_id", sourceID,
		"sequence", batch.Sequence,
		"packets", len(packets))

	// Update hunter statistics (only for gRPC sources with hunter IDs)
	if p.hunterManager != nil && sourceID != "" && sourceID != "local" {
		p.hunterManager.UpdatePacketStats(sourceID, uint64(len(packets)), batch.TimestampNs)
	}

	// Queue packets for async PCAP write if configured
	if p.pcapWriter != nil {
		p.pcapWriter.QueuePackets(packets)
	}

	// Update processor statistics (atomic increment)
	p.packetsReceived.Add(uint64(len(packets)))

	// Process TLS session keys from packets (for decryption support)
	if p.tlsKeylogWriter != nil {
		for _, packet := range packets {
			if packet.TlsKeys != nil {
				p.tlsKeylogWriter.ProcessPacketKeys(packet)
			}
		}
	}

	// Enrich packets with protocol detection if enabled
	if p.enricher != nil {
		p.enricher.Enrich(packets)
	}

	p.trackConnections(sourceID, packets)

	// Normalize protocol metadata after enrichment and before forwarding/broadcasting.
	p.emitProtocolEvents(sourceID, packets)

	// Aggregate VoIP call state from packet metadata
	if p.callAggregator != nil {
		for _, packet := range packets {
			if packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil) {
				p.callAggregator.ProcessPacket(packet, sourceID)
			}
		}
	}

	// Correlate SIP calls across B2BUA boundaries
	if p.callCorrelator != nil {
		for _, packet := range packets {
			if packet.Metadata != nil && packet.Metadata.Sip != nil {
				p.callCorrelator.ProcessPacket(packet, sourceID)
			}
		}
	}

	// Aggregate DNS tunneling statistics from hunter-provided metadata
	// This builds a cross-hunter view of suspicious domains
	if p.dnsTunneling != nil {
		for _, packet := range packets {
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
		for _, pkt := range packets {
			// Skip packets without matched filter IDs (not targeted by LI)
			if len(pkt.MatchedFilterIds) == 0 {
				continue
			}
			logger.Info("LI processing packet with filter IDs",
				"filter_ids", pkt.MatchedFilterIds,
				"has_sip", pkt.Metadata != nil && pkt.Metadata.Sip != nil,
				"has_rtp", pkt.Metadata != nil && pkt.Metadata.Rtp != nil,
			)

			// Convert to PacketDisplay for LI processing
			display := types.PacketDisplay{
				Timestamp: time.Unix(0, pkt.TimestampNs),
				RawData:   pkt.Data,
				LinkType:  layers.LinkType(pkt.LinkType),
				NodeID:    batch.SourceID,
			}
			if pkt.Metadata != nil {
				display.SrcIP = pkt.Metadata.SrcIp
				display.DstIP = pkt.Metadata.DstIp
				display.Protocol = pkt.Metadata.Protocol
				display.SrcPort = strconv.FormatUint(uint64(pkt.Metadata.SrcPort), 10)
				display.DstPort = strconv.FormatUint(uint64(pkt.Metadata.DstPort), 10)

				// Convert protobuf SIP/RTP metadata to VoIPMetadata for LI encoding
				if pkt.Metadata.Rtp != nil {
					// RTP packet (may also have SIP metadata for CallID correlation)
					display.VoIPData = &types.VoIPMetadata{
						IsRTP:       true,
						SSRC:        pkt.Metadata.Rtp.Ssrc,
						PayloadType: uint8(pkt.Metadata.Rtp.PayloadType),
						SequenceNum: uint16(pkt.Metadata.Rtp.Sequence),
						Timestamp:   pkt.Metadata.Rtp.Timestamp,
					}
					// Copy CallID from SIP metadata if present (VoIP processor sets this for correlated RTP)
					if pkt.Metadata.Sip != nil {
						display.VoIPData.CallID = pkt.Metadata.Sip.CallId
					}
				} else if pkt.Metadata.Sip != nil {
					// SIP signaling packet
					display.VoIPData = &types.VoIPMetadata{
						CallID:     pkt.Metadata.Sip.CallId,
						Method:     pkt.Metadata.Sip.Method,
						CSeqMethod: pkt.Metadata.Sip.CseqMethod,
						Status:     int(pkt.Metadata.Sip.ResponseCode),
						From:       pkt.Metadata.Sip.FromUri,
						To:         pkt.Metadata.Sip.ToUri,
						FromTag:    pkt.Metadata.Sip.FromTag,
						ToTag:      pkt.Metadata.Sip.ToTag,
						User:       pkt.Metadata.Sip.FromUser,
					}
					if pkt.Metadata.Sip.AccessNetworkInfo != nil {
						display.VoIPData.AccessNetworkInfo = &types.AccessNetworkInfo{
							AccessType: pkt.Metadata.Sip.AccessNetworkInfo.AccessType,
							CellID:     pkt.Metadata.Sip.AccessNetworkInfo.CellId,
							BSSID:      pkt.Metadata.Sip.AccessNetworkInfo.Bssid,
							LocalIP:    pkt.Metadata.Sip.AccessNetworkInfo.LocalIp,
						}
					}
					if pkt.Metadata.Sip.VisitedNetworkId != "" {
						display.VoIPData.VisitedNetworkID = pkt.Metadata.Sip.VisitedNetworkId
					}
				}
			}

			// Use per-packet filter IDs for LI correlation
			p.processLIPacket(&display, pkt.MatchedFilterIds)
		}
	}

	// Write VoIP packets to per-call PCAP files if configured
	// Writes separate SIP and RTP files for each call
	if p.sessionOutputManager != nil {
		for _, packet := range packets {
			// Check if packet has SIP metadata with call-id
			if packet.Metadata != nil && packet.Metadata.Sip != nil && packet.Metadata.Sip.CallId != "" {
				callID := packet.Metadata.Sip.CallId
				from := packet.Metadata.Sip.FromUser
				to := packet.Metadata.Sip.ToUser

				// Write packet to appropriate file (SIP or RTP) using raw packet data
				if len(packet.Data) > 0 {
					timestamp := time.Unix(0, packet.TimestampNs)
					linkType := layers.LinkType(packet.LinkType)
					if err := p.sessionOutputManager.WritePacket(
						callID, from, to, timestamp, packet.Data, linkType, packet.Metadata.Rtp != nil,
					); err != nil && !errors.Is(err, errSessionOutputClosed) {
						logger.Warn("Failed to write packet to call PCAP",
							"call_id", callID,
							"error", err)
					}
				}
			}
		}
	}

	// Write non-VoIP packets to auto-rotating PCAP files if configured
	// Auto-rotates based on idle time, file size, and duration
	if p.autoRotatePcapWriter != nil {
		for _, packet := range packets {
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

	if err := refreshEnvelopes(batch, packets); err != nil {
		logger.Error("Failed to retain processed packet metadata", "error", err, "source_id", batch.SourceID, "sequence", batch.Sequence)
		return
	}
	protoBatch, err = batch.ToProtoBatchE()
	if err != nil {
		logger.Error("Failed to encode processed packet batch", "error", err, "source_id", batch.SourceID, "sequence", batch.Sequence)
		return
	}

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
		displayPackets := make([]types.PacketDisplay, 0, len(packets))
		for _, pkt := range packets {
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

// refreshEnvelopes retains metadata produced by protobuf-backed analyzers while
// preserving the normalized capture and source provenance as authoritative.
func refreshEnvelopes(batch *source.PacketBatch, packets []*data.CapturedPacket) error {
	if len(batch.Envelopes) != len(packets) {
		return fmt.Errorf("envelope count %d differs from projected packet count %d", len(batch.Envelopes), len(packets))
	}
	for i, packet := range packets {
		current := batch.Envelopes[i]
		normalized, err := grpcadapter.FromCapturedPacket(packet, current.Source)
		if err != nil {
			return fmt.Errorf("normalize projected packet %d: %w", i, err)
		}
		current.Metadata = normalized.Metadata
		current.TLSKeys = normalized.TLSKeys
		current.Stages = current.Stages.With(pipeline.StageAnalyzed)
	}
	return nil
}

func (p *Processor) trackConnections(sourceID string, packets []*data.CapturedPacket) {
	if p.connTracker == nil || p.eventDispatcher == nil {
		return
	}
	var newest time.Time
	for _, raw := range packets {
		if raw == nil || raw.Metadata == nil {
			continue
		}
		flow, err := flowTuple(raw.Metadata)
		if err != nil {
			continue
		}
		ts := time.Unix(0, raw.TimestampNs)
		if raw.TimestampNs == 0 {
			ts = time.Now()
		}
		if ts.After(newest) {
			newest = ts
		}
		scope := events.CaptureScopeFull
		if len(raw.MatchedFilterIds) > 0 {
			scope = events.CaptureScopeFiltered
		}
		env, err := p.flowIdentity.Enrich(events.Envelope{Timestamp: ts, NodeID: sourceID, Flow: flow, CaptureScope: scope})
		if err != nil {
			continue
		}
		packet := gopacket.NewPacket(raw.Data, layers.LinkType(raw.LinkType), gopacket.NoCopy) // #nosec G115 -- pcap link type
		for _, ev := range mustObserve(p.connTracker, conntrack.FromPacket(packet, env, raw.Metadata.Protocol)) {
			p.eventDispatcher.Enqueue(ev)
		}
	}
	if !newest.IsZero() && newest.UnixNano() >= p.connExpireAt.Load() {
		p.connExpireAt.Store(newest.Add(time.Second).UnixNano())
		for _, ev := range p.connTracker.Expire(newest) {
			p.eventDispatcher.Enqueue(ev)
		}
	}
}

func mustObserve(t *conntrack.Tracker, o conntrack.Observation) []events.ConnEvent {
	evs, err := t.Observe(o)
	if err != nil {
		logger.Debug("Skipping invalid connection observation", "error", err)
		return nil
	}
	return evs
}
