//go:build (processor || tap || all) && li

package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func (p *Processor) processLIRADIUSPacket(display *types.PacketDisplay, packet *data.CapturedPacket, batch *source.PacketBatch) {
	if p.liManager == nil || batch == nil || !batch.RADIUSSourceTrusted {
		return
	}
	observation, err := grpcadapter.RADIUSFromProto(packet)
	if err != nil || observation == nil || observation.Scope.OriginNodeID != batch.SourceID {
		return
	}
	display.RADIUSData = types.RADIUSMetadataFromObservation(observation)
	p.liManager.ProcessPacketWithProvenance(display, li.PacketFilterProvenance{RADIUS: observation, RADIUSTrusted: true})
}
