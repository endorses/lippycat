//go:build (processor || tap || all) && !li

// Package processor - LI Integration Stub
//
// This file provides stub LI methods when built without -tags li.
// All methods are no-ops to avoid LI overhead in non-LI builds.
package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// initLIManager is a no-op when LI is not compiled in.
func (p *Processor) initLIManager() {}

type liStoragePreparation struct{}

func (p *Processor) prepareLIStorage() error { return nil }
func (p *Processor) initLIRuntime()          {}

func (p *Processor) validateLIConfiguration() error { return nil }

// startLIManager is a no-op when LI is not compiled in.
func (p *Processor) startLIManager() error { return nil }

// stopLIManager is a no-op when LI is not compiled in.
func (p *Processor) stopLIManager() error { return nil }

// processLIPacket is a no-op when LI is not compiled in.
func (p *Processor) processLIPacket(_ *types.PacketDisplay, _ []string) {}

func (p *Processor) processLIPacketWithProvenance(_ *types.PacketDisplay, _, _ []string) {}

func (p *Processor) processLIPacketWithAdmission(_ *types.PacketDisplay, _, _ []string, _ *CallAdmission) {
}

// isLIEnabled always returns false when LI is not compiled in.
func (p *Processor) isLIEnabled() bool { return false }

func (p *Processor) populateLIEncodingStats(_ *management.ProcessorStats) {}

func (p *Processor) populateLICallCorrelationStats(_ *management.ProcessorStats) {}

func (p *Processor) populateLIDeliveryStats(_ *management.ProcessorStats) {}

func (p *Processor) processLIRADIUSPacket(_ *types.PacketDisplay, _ *data.CapturedPacket, _ *source.PacketBatch) {
}

func (p *Processor) liCorrelationKeyring() *securestore.Keyring { return nil }
