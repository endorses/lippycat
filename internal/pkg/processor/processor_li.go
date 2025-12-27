//go:build li

// Package processor - LI Integration (Lawful Interception)
//
// This file provides LI Manager integration when built with -tags li.
// It creates the LI manager with proper filter pusher integration.
package processor

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// processorFilterPusher adapts the processor's filter management system
// to the li.FilterPusher interface.
type processorFilterPusher struct {
	p *Processor
}

// UpdateFilter implements li.FilterPusher.
func (pfp *processorFilterPusher) UpdateFilter(filter *management.Filter) error {
	_, err := pfp.p.filterManager.Update(filter)
	return err
}

// DeleteFilter implements li.FilterPusher.
func (pfp *processorFilterPusher) DeleteFilter(filterID string) error {
	_, err := pfp.p.filterManager.Delete(filterID)
	return err
}

// Ensure processorFilterPusher implements li.FilterPusher.
var _ li.FilterPusher = (*processorFilterPusher)(nil)

// initLIManager creates and configures the LI Manager.
// Called during processor initialization.
func (p *Processor) initLIManager() {
	if !p.config.LIEnabled {
		logger.Debug("LI not enabled in config")
		return
	}

	// Create filter pusher adapter
	filterPusher := &processorFilterPusher{p: p}

	// Create LI manager config
	config := li.ManagerConfig{
		Enabled:       true,
		X1ListenAddr:  p.config.LIX1ListenAddr,
		X1TLSCertFile: p.config.LIX1TLSCertFile,
		X1TLSKeyFile:  p.config.LIX1TLSKeyFile,
		X1TLSCAFile:   p.config.LIX1TLSCAFile,
		ADMFEndpoint:  p.config.LIADMFEndpoint,
		NEIdentifier:  p.config.ProcessorID,
		FilterPusher:  filterPusher,
	}

	// Deactivation callback - called when a task is implicitly deactivated
	// (e.g., EndTime expiration with ImplicitDeactivationAllowed=true)
	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		logger.Info("LI task implicitly deactivated",
			"xid", task.XID,
			"reason", reason,
		)
		// TODO: In Phase 4, this will send notification to ADMF via X1 client
	}

	// Create LI manager
	p.liManager = li.NewManager(config, deactivationCallback)

	// Set packet processor callback for X2/X3 delivery
	p.liManager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		// TODO: In Phase 2/3, this will encode and deliver X2/X3 PDUs
		logger.Debug("LI packet match",
			"xid", task.XID,
			"delivery_type", task.DeliveryType,
			"src_ip", pkt.SrcIP,
			"dst_ip", pkt.DstIP,
		)
	})

	logger.Info("LI Manager initialized",
		"x1_listen", p.config.LIX1ListenAddr,
		"admf_endpoint", p.config.LIADMFEndpoint,
	)
}

// startLIManager starts the LI Manager.
// Called during processor startup.
func (p *Processor) startLIManager() error {
	if p.liManager == nil {
		return nil
	}
	return p.liManager.Start()
}

// stopLIManager stops the LI Manager.
// Called during processor shutdown.
func (p *Processor) stopLIManager() {
	if p.liManager == nil {
		return
	}
	p.liManager.Stop()
}

// processLIPacket processes a packet through the LI system.
// Called from processBatch() for each packet that may have LI relevance.
//
// Note: Currently this is a placeholder. Full filter ID plumbing requires:
// 1. Hunters to include matched filter IDs in packet batches
// 2. LocalSource to use MatchPacketWithIDs and include filter IDs
// This will be implemented in a subsequent step.
func (p *Processor) processLIPacket(pkt *types.PacketDisplay, matchedFilterIDs []string) {
	if p.liManager == nil || !p.liManager.IsEnabled() {
		return
	}
	p.liManager.ProcessPacket(pkt, matchedFilterIDs)
}

// isLIEnabled returns whether LI is enabled on this processor.
func (p *Processor) isLIEnabled() bool {
	return p.liManager != nil && p.liManager.IsEnabled()
}
