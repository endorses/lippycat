//go:build li

// Package processor - LI Integration (Lawful Interception)
//
// This file provides LI Manager integration when built with -tags li.
// It creates the LI manager with proper filter pusher integration.
package processor

import (
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// LI encoders and delivery - initialized when LI is enabled
var (
	liX2Encoder *x2x3.X2Encoder
	liX3Encoder *x2x3.X3Encoder
)

// LI statistics
var (
	liX2Encoded atomic.Uint64
	liX3Encoded atomic.Uint64
	liX2Errors  atomic.Uint64
	liX3Errors  atomic.Uint64
	liX2Skipped atomic.Uint64
	liX3Skipped atomic.Uint64
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

	// Parse keepalive interval
	var keepaliveInterval time.Duration
	if p.config.LIADMFKeepalive != "" && p.config.LIADMFKeepalive != "0" {
		var err error
		keepaliveInterval, err = time.ParseDuration(p.config.LIADMFKeepalive)
		if err != nil {
			logger.Warn("Invalid LI ADMF keepalive interval, using default",
				"value", p.config.LIADMFKeepalive,
				"error", err,
			)
			keepaliveInterval = 30 * time.Second
		}
	}

	// Create LI manager config
	config := li.ManagerConfig{
		Enabled:       true,
		X1ListenAddr:  p.config.LIX1ListenAddr,
		X1TLSCertFile: p.config.LIX1TLSCertFile,
		X1TLSKeyFile:  p.config.LIX1TLSKeyFile,
		X1TLSCAFile:   p.config.LIX1TLSCAFile,
		ADMFEndpoint:  p.config.LIADMFEndpoint,
		NEIdentifier:  p.config.ProcessorID,
		X1Client: li.X1ClientConfig{
			TLSCertFile:       p.config.LIADMFTLSCertFile,
			TLSKeyFile:        p.config.LIADMFTLSKeyFile,
			TLSCAFile:         p.config.LIADMFTLSCAFile,
			KeepaliveInterval: keepaliveInterval,
		},
		FilterPusher: filterPusher,
	}

	// Deactivation callback - called when a task is implicitly deactivated
	// (e.g., EndTime expiration with ImplicitDeactivationAllowed=true)
	// The LI Manager automatically reports these to ADMF via X1 client.
	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		logger.Info("LI task implicitly deactivated",
			"xid", task.XID,
			"reason", reason,
		)
	}

	// Create LI manager
	p.liManager = li.NewManager(config, deactivationCallback)

	// Initialize X2/X3 encoders
	liX2Encoder = x2x3.NewX2Encoder()
	liX3Encoder = x2x3.NewX3Encoder()
	logger.Info("LI X2/X3 encoders initialized")

	// Set packet processor callback for X2/X3 delivery
	p.liManager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		// Determine what to deliver based on task configuration
		deliverX2 := task.DeliveryType == li.DeliveryX2Only || task.DeliveryType == li.DeliveryX2andX3
		deliverX3 := task.DeliveryType == li.DeliveryX3Only || task.DeliveryType == li.DeliveryX2andX3

		// Encode and log X2 (IRI - signaling) for SIP packets
		if deliverX2 && pkt.VoIPData != nil && !pkt.VoIPData.IsRTP {
			pdu, err := liX2Encoder.EncodeIRI(pkt, task.XID)
			if err != nil {
				liX2Errors.Add(1)
				logger.Debug("X2 encode error",
					"xid", task.XID,
					"error", err,
				)
			} else if pdu != nil {
				liX2Encoded.Add(1)
				// PDU is ready for delivery
				// Note: Actual delivery requires delivery client with MDF connection
				// For now, log the encoded PDU details for monitoring
				logger.Debug("X2 IRI encoded",
					"xid", task.XID,
					"correlation_id", pdu.Header.CorrelationID,
					"attributes", len(pdu.Attributes),
					"destinations", len(task.DestinationIDs),
				)
			} else {
				// nil PDU means packet doesn't require IRI (e.g., 1xx response)
				liX2Skipped.Add(1)
			}
		}

		// Encode and log X3 (CC - content) for RTP packets
		if deliverX3 && pkt.VoIPData != nil && pkt.VoIPData.IsRTP {
			pdu, err := liX3Encoder.EncodeCC(pkt, task.XID)
			if err != nil {
				liX3Errors.Add(1)
				logger.Debug("X3 encode error",
					"xid", task.XID,
					"error", err,
				)
			} else if pdu != nil {
				liX3Encoded.Add(1)
				// PDU is ready for delivery
				// Note: Actual delivery requires delivery client with MDF connection
				// For now, log the encoded PDU details for monitoring
				logger.Debug("X3 CC encoded",
					"xid", task.XID,
					"correlation_id", pdu.Header.CorrelationID,
					"payload_size", len(pdu.Payload),
					"destinations", len(task.DestinationIDs),
				)
			} else {
				liX3Skipped.Add(1)
			}
		}
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

// LIEncodingStats contains X2/X3 encoding statistics.
type LIEncodingStats struct {
	X2Encoded uint64
	X2Errors  uint64
	X2Skipped uint64
	X3Encoded uint64
	X3Errors  uint64
	X3Skipped uint64
}

// getLIEncodingStats returns current LI encoding statistics.
func (p *Processor) getLIEncodingStats() LIEncodingStats {
	return LIEncodingStats{
		X2Encoded: liX2Encoded.Load(),
		X2Errors:  liX2Errors.Load(),
		X2Skipped: liX2Skipped.Load(),
		X3Encoded: liX3Encoded.Load(),
		X3Errors:  liX3Errors.Load(),
		X3Skipped: liX3Skipped.Load(),
	}
}
