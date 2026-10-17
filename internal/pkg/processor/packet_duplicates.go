//go:build processor || tap || all

package processor

import (
	"strconv"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
)

// packetDuplicateObservation is derived separately for every downstream acceptance
// owner. Raw transport receipts/counters, call selection and LI authorization
// precede or bypass these boundaries; they never inherit an unrelated sink's
// suppression decision. Untrusted origins or missing domain mappings retain
// packets and count as ambiguous coverage, rather than trusting wire metadata.
func (p *Processor) packetDuplicateObservation(batch *source.PacketBatch, index int, consumer string) *packetdedup.Observation {
	if p.packetDuplicates == nil || batch == nil || !batch.MediaSourceTrusted || index < 0 || index >= len(batch.Envelopes) {
		return nil
	}
	envelope := batch.Envelopes[index]
	domain, ok := p.mediaSourceDomain(envelope)
	if !ok || envelope == nil || envelope.Source.NodeID == "" {
		return nil
	}
	observation := &packetdedup.Observation{Consumer: consumer, Domain: strconv.FormatUint(uint64(domain), 10), Source: envelope.Source.NodeID, CapturedAt: envelope.CaptureTime, Packet: envelope.Data, LinkType: envelope.LinkType, Flow: "unparsed"}
	if packet := envelope.Packet(); packet != nil && packet.NetworkLayer() != nil {
		observation.Flow = packet.NetworkLayer().NetworkFlow().String()
		if transport := packet.TransportLayer(); transport != nil {
			observation.Flow += "/" + transport.TransportFlow().String()
		}
	}
	return observation
}
func (p *Processor) beginPacketConsumer(batch *source.PacketBatch, index int, consumer string) (*packetdedup.Claim, bool) {
	if p.packetDuplicates == nil {
		return nil, true
	}
	observation := p.packetDuplicateObservation(batch, index, consumer)
	if observation == nil {
		observation = &packetdedup.Observation{Consumer: consumer}
	}
	decision, claim := p.packetDuplicates.Begin(*observation)
	switch decision {
	case packetdedup.Duplicate:
		return nil, false
	case packetdedup.Accept:
		return claim, true
	default:
		// InFlight cannot prove acceptance. Retaining it gives reduced suppression
		// coverage under contention without blocking packet processing or losing an
		// eligible alternate after the current owner rejects admission.
		return nil, true
	}
}

func finishPacketConsumer(claim *packetdedup.Claim, accepted bool) {
	if claim == nil {
		return
	}
	if accepted {
		claim.Commit()
	} else {
		claim.Abort()
	}
}

type selectedConsumerPackets struct {
	packets []*data.CapturedPacket
	claims  []*packetdedup.Claim
	indices []int
}

func (p *Processor) selectPacketConsumer(batch *source.PacketBatch, packets []*data.CapturedPacket, consumer string) selectedConsumerPackets {
	selected := selectedConsumerPackets{}
	for index, packet := range packets {
		claim, include := p.beginPacketConsumer(batch, index, consumer)
		if !include {
			continue
		}
		selected.packets = append(selected.packets, packet)
		selected.claims = append(selected.claims, claim)
		selected.indices = append(selected.indices, index)
	}
	return selected
}
func (selected selectedConsumerPackets) finish(accepted bool) {
	for _, claim := range selected.claims {
		finishPacketConsumer(claim, accepted)
	}
}

func (p *Processor) queueUnifiedPCAPPackets(batch *source.PacketBatch, packets []*data.CapturedPacket) {
	if p.packetDuplicates == nil {
		p.pcapWriter.QueuePackets(packets)
		return
	}
	selected := p.selectPacketConsumer(batch, packets, "pcap/unified")
	if len(selected.packets) > 0 {
		selected.finish(p.pcapWriter.QueuePackets(selected.packets))
	}
}

func (p *Processor) emitConsumerProtocolEvents(batch *source.PacketBatch, packets []*data.CapturedPacket) {
	if p.packetDuplicates == nil {
		p.emitProtocolEventsWithScope(batch.SourceID, batch.CaptureEpoch, packets)
		return
	}
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	if p.eventRuntime == nil || !p.wantsEventAnalysisLocked() {
		return
	}
	selected := p.selectPacketConsumer(batch, packets, "analysis/events")
	if len(selected.packets) == 0 {
		return
	}
	producer, provenance := p.eventSource(batch.SourceID)
	accepted, err := p.eventRuntime.ObserveCapturedAccepted(eventanalysis.Source{NodeID: producer, CaptureSource: provenance.CaptureSource, CaptureEpoch: batch.CaptureEpoch, ProcessorNodeIDs: provenance.ProcessorNodeIDs}, selected.packets)
	for index, claim := range selected.claims {
		finishPacketConsumer(claim, index < len(accepted) && accepted[index])
	}
	if err != nil {
		logger.Warn("Failed to analyze normalized protocol events", "source_id", batch.SourceID, "error", err)
	}
}

// monitorConsumerPackets is called after the subscriber's registered hunter/BPF
// eligibility filter and before its queue accepts ownership. Packet pointers
// originate from this batch; the manager clones only after selection finishes.
func (p *Processor) monitorConsumerPackets(batch *source.PacketBatch, packets []*data.CapturedPacket, clientID string, eligible *data.PacketBatch) (*data.PacketBatch, func(bool)) {
	selected := selectedConsumerPackets{}
	next := proto.Clone(eligible).(*data.PacketBatch)
	next.Packets = nil
	for _, packet := range eligible.Packets {
		original := -1
		for index, candidate := range packets {
			if candidate == packet {
				original = index
				break
			}
		}
		claim, include := p.beginPacketConsumer(batch, original, "monitor/"+clientID)
		if include {
			next.Packets = append(next.Packets, packet)
			selected.claims = append(selected.claims, claim)
		}
	}
	return next, selected.finish
}

func (p *Processor) forwardConsumerPackets(batch *source.PacketBatch, packets []*data.CapturedPacket, projected *data.PacketBatch) {
	if p.packetDuplicates == nil {
		p.upstreamManager.Forward(projected)
		return
	}
	selected := p.selectPacketConsumer(batch, packets, "upstream/packets")
	if len(selected.packets) == 0 {
		return
	}
	next := proto.Clone(projected).(*data.PacketBatch)
	next.Packets = selected.packets
	selected.finish(p.upstreamManager.TryForward(next))
}

// injectConsumerPacket converts before calling the truthful single-packet
// queue API. The batch injection API can skip conversion failures while
// returning nil and therefore cannot establish a duplicate-suppression claim.
func (p *Processor) injectConsumerPacket(batch *source.PacketBatch, index int, packet types.PacketDisplay) error {
	claim, include := p.beginPacketConsumer(batch, index, "vinterface")
	if !include {
		return nil
	}
	var raw []byte
	var err error
	if p.config.VirtualInterfaceType == "tun" {
		raw, err = vinterface.ConvertToIP(&packet)
	} else {
		raw, err = vinterface.ConvertToEthernet(&packet)
	}
	if err == nil {
		// The asynchronous queue must own bytes beyond the capture batch lifetime.
		err = p.vifManager.InjectPacket(append([]byte(nil), raw...))
	}
	finishPacketConsumer(claim, err == nil)
	return err
}

// writeConsumerSessionPacket obtains the ordinary call admission before claiming
// output ownership and includes its incarnation in the consumer key. Reused
// Call-IDs cannot inherit suppression from an independent earlier lifecycle.
func (p *Processor) writeConsumerSessionPacket(batch *source.PacketBatch, index int, packet *data.CapturedPacket, admission *CallAdmission) error {
	meta := packet.Metadata.Sip
	owned := false
	if p.packetDuplicates != nil && p.sessionOutputManager.writer != nil && admission == nil && p.callLifecycle != nil {
		var err error
		admission, err = p.callLifecycle.Admit(meta.CallId)
		if err != nil {
			return err
		}
		owned = true
	}
	if owned {
		defer admission.Release()
	}
	var claim *packetdedup.Claim
	if admission != nil && p.sessionOutputManager.writer != nil {
		var include bool
		claim, include = p.beginPacketConsumer(batch, index, "pcap/session/"+admission.Incarnation().String())
		if !include {
			return nil
		}
	}
	var err error
	if admission != nil {
		err = p.sessionOutputManager.writePacketWithAdmission(admission, meta.CallId, meta.FromUser, meta.ToUser, time.Unix(0, packet.TimestampNs), packet.Data, layers.LinkType(packet.LinkType), packet.Metadata.Rtp != nil)
	} else {
		err = p.sessionOutputManager.WritePacket(meta.CallId, meta.FromUser, meta.ToUser, time.Unix(0, packet.TimestampNs), packet.Data, layers.LinkType(packet.LinkType), packet.Metadata.Rtp != nil)
	}
	finishPacketConsumer(claim, err == nil)
	return err
}

// duplicateCallPacketAllowed preserves the admission veto performed by the call
// monitor even when its state-update consumer has already accepted an overlap.
// Suppression is not authorization to bypass finalized/restarted-call guards.
func (p *Processor) duplicateCallPacketAllowed(packet *data.CapturedPacket) bool {
	if p.callAggregator == nil || packet == nil || packet.Metadata == nil {
		return false
	}
	if p.sessionOutputManager != nil {
		if monitor, ok := p.sessionOutputManager.monitor.(*CallCompletionMonitor); ok {
			if monitor == nil || monitor.aggregator == nil {
				return false
			}
			monitor.transitionMu.Lock()
			defer monitor.transitionMu.Unlock()
			if meta := packet.Metadata.Sip; meta != nil && (monitor.lifecycle.HasCompletedCall(meta.CallId) || monitor.aggregator.WasFinalized(meta.CallId)) {
				return false
			}
		}
	}
	return p.callAggregator.AcceptSIP(packet.Metadata.Sip) && p.callAggregator.AcceptRTP(packet)
}
