//go:build processor || tap || all

package processor

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// normalizeRADIUS revalidates transported observations before presentation or
// events. Legacy raw traffic gets local observational association only; neither
// path confers LI authorization through generic filter IDs.
func (p *Processor) normalizeRADIUS(sourceID string, packets []*data.CapturedPacket) {
	p.radiusMu.Lock()
	defer p.radiusMu.Unlock()
	for _, packet := range packets {
		if packet == nil {
			continue
		}
		claimed := packet.Radius != nil
		observation, err := grpcadapter.RADIUSFromProto(packet)
		if err != nil {
			logger.Warn("Invalid RADIUS provenance", "source_id", sourceID, "error", err)
			packet.Radius = nil
		}
		if observation == nil {
			if p.radiusCapture == nil {
				p.radiusCapture, err = radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "processor:" + p.config.ProcessorID, SourceID: "legacy"})
				if err != nil {
					logger.Error("Initialize RADIUS observations", "error", err)
					continue
				}
			}
			decoded := gopacket.NewPacket(packet.Data, layers.LinkType(packet.LinkType), gopacket.Default)
			decoded.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, packet.TimestampNs), CaptureLength: int(packet.CaptureLength), Length: int(packet.OriginalLength)}
			observation = p.radiusCapture.Process(decoded, layers.LinkType(packet.LinkType), fmt.Sprintf("%d:%s:%d:%d:%s", len(sourceID), sourceID, packet.InterfaceIndex, len(packet.InterfaceName), packet.InterfaceName), nil)
		}
		if observation != nil || claimed {
			packet.MatchedFilterIds, packet.DirectMatchedFilterIds, packet.InheritedMatchedFilterIds = nil, nil, nil
		}
		if observation == nil {
			continue
		}
		packet.Radius = grpcadapter.RADIUSToProto(observation)
		if packet.Metadata == nil {
			packet.Metadata = &data.PacketMetadata{}
		}
		m := types.RADIUSMetadataFromObservation(observation)
		packet.Metadata.Protocol, packet.Metadata.Info = "RADIUS", m.Summary()
		packet.Metadata.SrcIp, packet.Metadata.DstIp = observation.Endpoints.Source.Addr().String(), observation.Endpoints.Destination.Addr().String()
		packet.Metadata.SrcPort, packet.Metadata.DstPort = uint32(observation.Endpoints.Source.Port()), uint32(observation.Endpoints.Destination.Port())
		packet.Metadata.Transport = "udp"
		// Conflicting peer-supplied protocol metadata cannot route RADIUS into VoIP.
		packet.Metadata.Sip, packet.Metadata.Rtp = nil, nil
		packet.Metadata.Dns, packet.Metadata.Email, packet.Metadata.Tls, packet.Metadata.Http = nil, nil, nil, nil
	}
}
