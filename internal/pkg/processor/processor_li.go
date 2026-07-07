//go:build (processor || tap || all) && li

// Package processor - LI Integration (Lawful Interception)
//
// This file provides LI Manager integration when built with -tags li.
// It creates the LI manager with proper filter pusher integration.
package processor

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

// LI encoders and delivery - initialized when LI is enabled
var (
	liX2Encoder      *x2x3.X2Encoder
	liX3Encoder      *x2x3.X3Encoder
	liDeliveryMgr    *delivery.Manager
	liDeliveryClient *delivery.Client
	liReorderBuffers sync.Map // map[string]*delivery.ReorderBuffer keyed by "xid-destID"
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

	// In tap/local mode, also apply the filter directly to the local capture engine.
	// filterManager.Update() only broadcasts to hunters via gRPC channels, which are
	// absent in tap mode. The filterTarget (LocalTarget) handles BPF filter updates.
	if pfp.p.filterTarget != nil {
		if _, targetErr := pfp.p.filterTarget.ApplyFilter(filter); targetErr != nil {
			logger.Warn("Failed to apply LI filter to local capture target",
				"filter_id", filter.Id,
				"error", targetErr,
			)
			if err == nil {
				err = targetErr
			}
		}
	}

	return err
}

// DeleteFilter implements li.FilterPusher.
func (pfp *processorFilterPusher) DeleteFilter(filterID string) error {
	_, err := pfp.p.filterManager.Delete(filterID)

	// Also remove from local capture target (see UpdateFilter comment).
	if pfp.p.filterTarget != nil {
		if _, targetErr := pfp.p.filterTarget.RemoveFilter(filterID); targetErr != nil {
			logger.Warn("Failed to remove LI filter from local capture target",
				"filter_id", filterID,
				"error", targetErr,
			)
			if err == nil {
				err = targetErr
			}
		}
	}

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
		FilterPusher:      filterPusher,
		SyncOnStartup:     p.config.LIADMFSyncOnStartup,
		SyncTimeout:       p.config.LIADMFSyncTimeout,
		ReconcileInterval: p.config.LIADMFReconcileInterval,
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

	// Initialize delivery client if TLS certs are configured
	if p.config.LIDeliveryTLSCertFile != "" && p.config.LIDeliveryTLSKeyFile != "" {
		destConfig := delivery.DefaultConfig()
		destConfig.TLSCertFile = p.config.LIDeliveryTLSCertFile
		destConfig.TLSKeyFile = p.config.LIDeliveryTLSKeyFile
		destConfig.TLSCAFile = p.config.LIDeliveryTLSCAFile
		destConfig.InitialBackoff = p.config.LIDeliveryInitialBackoff
		destConfig.MaxBackoff = p.config.LIDeliveryMaxBackoff
		destConfig.KeepAliveIdle = p.config.LIDeliveryKeepAliveIdle
		destConfig.KeepAliveInterval = p.config.LIDeliveryKeepAliveInterval
		destConfig.KeepAliveCount = p.config.LIDeliveryKeepAliveCount
		if len(p.config.LIDeliveryTLSPinnedCert) > 0 {
			destConfig.TLSPinnedCerts = p.config.LIDeliveryTLSPinnedCert
		}

		var err error
		liDeliveryMgr, err = delivery.NewManager(destConfig)
		if err != nil {
			logger.Error("Failed to create LI delivery manager", "error", err)
		} else {
			clientConfig := delivery.DefaultClientConfig()
			clientConfig.QueueSize = p.config.LIDeliveryQueueSize
			clientConfig.SendTimeout = p.config.LIDeliverySendTimeout
			clientConfig.ShutdownTimeout = p.config.LIDeliveryShutdownTimeout
			liDeliveryClient = delivery.NewClient(liDeliveryMgr, clientConfig)
			logger.Info("LI delivery client initialized",
				"cert", p.config.LIDeliveryTLSCertFile,
				"ca", p.config.LIDeliveryTLSCAFile,
			)
		}
	} else {
		logger.Warn("LI delivery TLS certs not configured, X2/X3 PDUs will be encoded but not delivered")
	}

	// Set packet processor callback for X2/X3 encoding and delivery
	p.liManager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		// Determine what to deliver based on task configuration
		deliverX2 := task.DeliveryType == li.DeliveryX2Only || task.DeliveryType == li.DeliveryX2andX3
		deliverX3 := task.DeliveryType == li.DeliveryX3Only || task.DeliveryType == li.DeliveryX2andX3

		// Encode and deliver X2 (IRI - signaling) for SIP packets
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
				// Add NFID (processor/NE ID) and IPID (hunter/capture point)
				attrBuilder := x2x3.NewAttributeBuilder()
				pdu.AddAttribute(attrBuilder.NFID(p.config.ProcessorID))
				if pkt.NodeID != "" {
					pdu.AddAttribute(attrBuilder.IPID(pkt.NodeID))
				}
				// Matched target identifier (ETSI attr 17). Only set when the
				// task has a single target, so the identity is unambiguous;
				// with multiple targets the MDF falls back to the XID.
				if len(task.Targets) == 1 {
					pdu.AddAttribute(attrBuilder.MatchedTargetIdentifier(task.Targets[0].Value))
				}
				data, err := pdu.MarshalBinary()
				if err != nil {
					logger.Warn("X2 PDU marshal error", "xid", task.XID, "error", err)
				} else if liDeliveryClient != nil && len(task.DestinationIDs) > 0 {
					if err := liDeliveryClient.SendX2(task.XID, task.DestinationIDs, data); err != nil {
						logger.Debug("X2 delivery queued failed", "xid", task.XID, "error", err)
					} else {
						logger.Debug("X2 IRI queued",
							"xid", task.XID,
							"correlation_id", pdu.Header.CorrelationID,
							"size", len(data),
							"destinations", len(task.DestinationIDs),
						)
					}
				} else {
					logger.Debug("X2 IRI encoded (no delivery client or destinations)",
						"xid", task.XID,
						"correlation_id", pdu.Header.CorrelationID,
						"attributes", len(pdu.Attributes),
					)
				}
			} else {
				liX2Skipped.Add(1)
			}
		}

		// Encode and deliver X3 (CC - content) for RTP packets
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
				// Add NFID (processor/NE ID) and IPID (hunter/capture point)
				attrBuilder := x2x3.NewAttributeBuilder()
				pdu.AddAttribute(attrBuilder.NFID(p.config.ProcessorID))
				if pkt.NodeID != "" {
					pdu.AddAttribute(attrBuilder.IPID(pkt.NodeID))
				}
				// Matched target identifier (ETSI attr 17). Only set when the
				// task has a single target, so the identity is unambiguous;
				// with multiple targets the MDF falls back to the XID.
				if len(task.Targets) == 1 {
					pdu.AddAttribute(attrBuilder.MatchedTargetIdentifier(task.Targets[0].Value))
				}
				data, err := pdu.MarshalBinary()
				if err != nil {
					logger.Warn("X3 PDU marshal error", "xid", task.XID, "error", err)
				} else if liDeliveryClient != nil && len(task.DestinationIDs) > 0 {
					// Route through reorder buffer per destination
					ssrc := pkt.VoIPData.SSRC
					rtpSeq := pkt.VoIPData.SequenceNum
					for _, destID := range task.DestinationIDs {
						did := destID // capture for closure
						bufKey := fmt.Sprintf("%s-%s", task.XID, did)
						buf, _ := liReorderBuffers.LoadOrStore(bufKey, delivery.NewReorderBuffer(
							func(orderedPDU []byte) {
								dids := []uuid.UUID{did}
								if sendErr := liDeliveryClient.SendX3(task.XID, dids, orderedPDU); sendErr != nil {
									logger.Debug("X3 delivery failed", "xid", task.XID, "error", sendErr)
								}
							},
							60*time.Millisecond,
						))
						buf.(*delivery.ReorderBuffer).DeliverX3(ssrc, rtpSeq, data)
					}
					logger.Debug("X3 CC queued via reorder buffer",
						"xid", task.XID,
						"correlation_id", pdu.Header.CorrelationID,
						"ssrc", pkt.VoIPData.SSRC,
						"rtp_seq", pkt.VoIPData.SequenceNum,
						"size", len(data),
						"destinations", len(task.DestinationIDs),
					)
				} else {
					logger.Debug("X3 CC encoded (no delivery client or destinations)",
						"xid", task.XID,
						"correlation_id", pdu.Header.CorrelationID,
						"payload_size", len(pdu.Payload),
					)
				}
			} else {
				liX3Skipped.Add(1)
			}
		}
	})

	logger.Info("LI Manager initialized",
		"x1_listen", p.config.LIX1ListenAddr,
		"admf_endpoint", p.config.LIADMFEndpoint,
		"delivery_enabled", liDeliveryClient != nil,
	)
}

// startLIManager starts the LI Manager and delivery client.
// Called during processor startup.
func (p *Processor) startLIManager() error {
	if p.liManager == nil {
		return nil
	}

	// Start delivery infrastructure
	if liDeliveryMgr != nil {
		liDeliveryMgr.Start()
	}
	if liDeliveryClient != nil {
		liDeliveryClient.Start()
	}

	// Register destination callback to bridge new destinations to delivery manager
	if liDeliveryMgr != nil {
		p.liManager.SetDestinationCreatedCallback(func(dest *li.Destination) {
			if err := liDeliveryMgr.AddDestination(dest); err != nil {
				logger.Warn("Failed to add delivery destination",
					"did", dest.DID,
					"address", dest.Address,
					"port", dest.Port,
					"error", err,
				)
			} else {
				logger.Info("Delivery destination added",
					"did", dest.DID,
					"address", dest.Address,
					"port", dest.Port,
				)
			}
		})
		p.liManager.SetDestinationModifiedCallback(func(dest *li.Destination) {
			if err := liDeliveryMgr.UpdateDestination(dest); err != nil {
				logger.Warn("Failed to update delivery destination",
					"did", dest.DID,
					"address", dest.Address,
					"port", dest.Port,
					"error", err,
				)
			}
		})
		p.liManager.SetDestinationRemovedCallback(func(did uuid.UUID) {
			if liDeliveryClient != nil {
				liDeliveryClient.RemoveDestination(did)
			}
			if err := liDeliveryMgr.RemoveDestination(did); err != nil &&
				!errors.Is(err, delivery.ErrDestinationNotFound) {
				logger.Warn("Failed to remove delivery destination",
					"did", did,
					"error", err,
				)
			}
		})
	}

	// Start periodic cleanup of idle reorder buffers (no packets for 60s)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				liReorderBuffers.Range(func(key, value any) bool {
					buf := value.(*delivery.ReorderBuffer)
					lastUsed := buf.LastUsed()
					if lastUsed.IsZero() || time.Since(lastUsed) > 60*time.Second {
						buf.Stop()
						liReorderBuffers.Delete(key)
						logger.Debug("Cleaned up idle reorder buffer", "key", key)
						return true
					}
					// Buffer still active overall, but prune per-SSRC streams whose
					// calls have ended. Without this the streams map grows by ~2
					// entries per completed call for the lifetime of the XID.
					if buf.CleanupIdleStreams(60 * time.Second) {
						buf.Stop()
						liReorderBuffers.Delete(key)
					}
					return true
				})
			}
		}
	}()

	// Start the LI Manager (syncs tasks/destinations from ADMF)
	if err := p.liManager.Start(); err != nil {
		return err
	}

	// Bridge existing destinations from LI Manager registry to delivery manager
	if liDeliveryMgr != nil {
		dests := p.liManager.ListDestinations()
		for _, dest := range dests {
			if err := liDeliveryMgr.AddDestination(dest); err != nil {
				logger.Warn("Failed to add delivery destination",
					"did", dest.DID,
					"address", dest.Address,
					"port", dest.Port,
					"error", err,
				)
			} else {
				logger.Info("Delivery destination added",
					"did", dest.DID,
					"address", dest.Address,
					"port", dest.Port,
				)
			}
		}
	}

	return nil
}

// stopLIManager stops the LI Manager and delivery client.
// Called during processor shutdown.
func (p *Processor) stopLIManager() {
	if p.liManager == nil {
		return
	}
	p.liManager.Stop()

	if liDeliveryClient != nil {
		liDeliveryClient.Stop()
	}
	if liDeliveryMgr != nil {
		liDeliveryMgr.Stop()
	}
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
