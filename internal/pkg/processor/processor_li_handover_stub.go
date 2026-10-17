//go:build (processor || tap || all) && !li

package processor

import (
	"context"
	"errors"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func (p *Processor) rejectLIOwnedFilterMutation(string) error { return nil }

func (p *Processor) liCapturePolicyFilters() ([]*management.Filter, error) {
	return nil, errors.New("LI capture policy requires an LI build")
}

func (p *Processor) startLIHandoverPolicy(context.Context) error {
	if p.config.LIHandover.Enabled {
		return errors.New("LI handover requires an LI build")
	}
	return nil
}

func (p *Processor) closeLIHandoverPolicy() {}

func (p *Processor) buildLICapturePolicy(snapshot *management.PolicySnapshot, _ time.Time) error {
	if snapshot.GetOwnerKind() == "li" || p.config.LIHandover.Enabled {
		return errors.New("LI capture policy requires an LI-enabled owner")
	}
	return nil
}

func (p *Processor) validateLICapturePolicy(batch *data.PacketBatch) error {
	if p.config.LIHandover.Enabled {
		return errors.New("LI handover requires an LI build")
	}
	// Non-LI relays may transport authenticated opaque capture provenance.
	// They never interpret it as permission to generate LI product.
	return nil
}

func (p *Processor) processLIPacketWithCapturePolicy(packet *types.PacketDisplay, direct, inherited []string, admission *CallAdmission, _ []byte) {
	p.processLIPacketWithAdmission(packet, direct, inherited, admission)
}
