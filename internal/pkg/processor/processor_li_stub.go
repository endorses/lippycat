//go:build (processor || tap || all) && !li

// Package processor - LI Integration Stub
//
// This file provides stub LI methods when built without -tags li.
// All methods are no-ops to avoid LI overhead in non-LI builds.
package processor

import (
	"github.com/endorses/lippycat/internal/pkg/types"
)

// initLIManager is a no-op when LI is not compiled in.
func (p *Processor) initLIManager() {}

// startLIManager is a no-op when LI is not compiled in.
func (p *Processor) startLIManager() error { return nil }

// stopLIManager is a no-op when LI is not compiled in.
func (p *Processor) stopLIManager() {}

// processLIPacket is a no-op when LI is not compiled in.
func (p *Processor) processLIPacket(_ *types.PacketDisplay, _ []string) {}

// isLIEnabled always returns false when LI is not compiled in.
func (p *Processor) isLIEnabled() bool { return false }
