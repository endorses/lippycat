//go:build (processor || tap || all) && li

// Package processor - LI Integration (Lawful Interception)
//
// This file provides LI Manager integration when built with -tags li.
// It creates the LI manager with proper filter pusher integration.
package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/uuid"
)

// LI encoders and delivery - initialized when LI is enabled
var (
	liX2Encoder      *x2x3.X2Encoder
	liX3Encoder      *x2x3.X3Encoder
	liSequencer      *x2x3.Sequencer
	liDeliveryMgr    *delivery.Manager
	liDeliveryClient *delivery.Client
	liReorderBuffers sync.Map // map[string]*delivery.ReorderBuffer keyed by "xid-destID"
	// liMediaDirection derives the Payload Direction of RTP media for
	// identity-based targets from the call's observed SIP signalling.
	liMediaDirection *li.MediaDirectionResolver
	liPinnedCalls    sync.Map // map[uuid.UUID]*sync.Map of Call-ID retention leases
)

// LI statistics
var (
	liX2Encoded             atomic.Uint64
	liX3Encoded             atomic.Uint64
	liX2Errors              atomic.Uint64
	liX3Errors              atomic.Uint64
	liX2Skipped             atomic.Uint64
	liX3Skipped             atomic.Uint64
	liNoEncoder             atomic.Uint64
	liX3FinalizedSuppressed atomic.Uint64
	liX3BufferedDiscarded   atomic.Uint64
	liX3LastLateWarning     atomic.Int64
)

const liLateX3WarningInterval = time.Minute

func sanitizedCallID(callID string) string {
	sum := sha256.Sum256([]byte(callID))
	return hex.EncodeToString(sum[:8])
}

// recordLateX3Suppression is the single-owner accounting point for an X3 PDU
// rejected by lifecycle admission. It emits at most one sanitized warning per
// interval across the processor, keeping log cardinality bounded.
func recordLateX3Suppression(callID string, generation uint64, reason string) {
	total := liX3FinalizedSuppressed.Add(1)
	now := time.Now().UnixNano()
	last := liX3LastLateWarning.Load()
	if now-last < liLateX3WarningInterval.Nanoseconds() || !liX3LastLateWarning.CompareAndSwap(last, now) {
		return
	}
	logger.Warn("late X3 content rejected",
		"call_id_hash", sanitizedCallID(callID),
		"generation", generation,
		"reason", reason,
		"suppressed_total", total,
	)
}

func recordBufferedX3Discard(count int) {
	if count > 0 {
		liX3BufferedDiscarded.Add(uint64(count)) // #nosec G115 -- bounded buffer count
	}
}

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

// ListFilterIDs implements li.FilterLister, including filters loaded from disk
// at startup that this process did not create.
func (pfp *processorFilterPusher) ListFilterIDs() []string {
	filters := pfp.p.filterManager.GetAll()
	ids := make([]string, 0, len(filters))
	for _, f := range filters {
		ids = append(ids, f.Id)
	}
	return ids
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
		StateFile:         p.config.LIStateFile,
	}

	// Deactivation callback - called when a task is implicitly deactivated
	// (e.g., EndTime expiration with ImplicitDeactivationAllowed=true)
	// The LI Manager automatically reports these to ADMF via X1 client.
	deactivationCallback := func(task *li.InterceptTask, reason li.DeactivationReason) {
		liPinnedCalls.Delete(task.XID)
		if liSequencer != nil {
			liSequencer.ClearXID(task.XID)
		}
		if liMediaDirection != nil {
			liMediaDirection.ClearXID(task.XID)
		}
		prefix := task.XID.String() + "-"
		liReorderBuffers.Range(func(key, value any) bool {
			keyString, ok := key.(string)
			if ok && strings.HasPrefix(keyString, prefix) {
				// Expiry/deactivation is an enforcement boundary. Buffered X3
				// packets must be discarded, not flushed after the task ended.
				recordBufferedX3Discard(value.(*delivery.ReorderBuffer).DiscardCount())
				liReorderBuffers.Delete(key)
			}
			return true
		})
		logger.Info("LI task implicitly deactivated",
			"xid", task.XID,
			"reason", reason,
		)
	}

	// Create LI manager
	p.liManager = li.NewManager(config, deactivationCallback)

	// Initialize X2/X3 encoders
	liSequencer = x2x3.NewSequencer(0)
	liX2Encoder = x2x3.NewX2EncoderWithSequencer(liSequencer, "", p.config.ProcessorID)
	liX3Encoder = x2x3.NewX3EncoderWithSequencer(liSequencer, "", p.config.ProcessorID)
	logger.Info("LI X2/X3 encoders initialized")

	// Media direction resolver: RTP carries no SIP identity, so the direction of
	// media for an identity target is derived from the call's signalling.
	liMediaDirection = li.NewMediaDirectionResolver(li.MediaDirectionConfig{})
	if p.callLifecycle != nil {
		p.callLifecycle.Subscribe(func(event CallFinalizationEvent) {
			liMediaDirection.ClearCall(event.CallID)
			liPinnedCalls.Range(func(_, value any) bool {
				value.(*sync.Map).Delete(event.CallID)
				return true
			})
			liReorderBuffers.Range(func(_, value any) bool {
				discarded := value.(*delivery.ReorderBuffer).DiscardCall(event.CallID, event.Generation)
				liX3BufferedDiscarded.Add(uint64(discarded)) // #nosec G115 -- bounded buffer count
				return true
			})
		})
	}

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
		destConfig.X2KeepaliveEnabled = p.config.LIDeliveryX2KeepaliveEnabled
		destConfig.X2KeepaliveTimeP1 = p.config.LIDeliveryX2KeepaliveTimeP1
		destConfig.X2KeepaliveTimeP2 = p.config.LIDeliveryX2KeepaliveTimeP2
		destConfig.X3KeepaliveEnabled = p.config.LIDeliveryX3KeepaliveEnabled
		destConfig.X3KeepaliveTimeP1 = p.config.LIDeliveryX3KeepaliveTimeP1
		destConfig.X3KeepaliveTimeP2 = p.config.LIDeliveryX3KeepaliveTimeP2
		destConfig.X2AcknowledgeInboundKeepalive = p.config.LIDeliveryX2AcknowledgeInboundKeepalive
		destConfig.X3AcknowledgeInboundKeepalive = p.config.LIDeliveryX3AcknowledgeInboundKeepalive
		destConfig.DeliveryFault = func(did uuid.UUID, err error) { p.liManager.ReportDeliveryError(did, 1, err.Error()) }
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

	if p.config.LIMetadataEventsEnabled {
		sink, err := li.NewMetadataSink(li.MetadataSinkConfig{Enabled: true, Profile: p.config.LIMetadataDeliveryProfile, Manager: p.liManager, Sender: liDeliveryClient, NFID: p.config.ProcessorID, AllowFileMetadata: p.config.LIMetadataAllowFileMetadata})
		if err != nil {
			logger.Error("Failed to initialize LI metadata event sink", "error", err)
		} else if err := p.eventDispatcher.Register(sink, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP, events.KindConn, events.KindFileMetadata, events.KindFileContent); err != nil {
			logger.Error("Failed to register LI metadata event sink", "error", err)
		} else {
			logger.Info("LI metadata event sink initialized", "profile", p.config.LIMetadataDeliveryProfile)
		}
	}

	// Set packet processor callback for X2/X3 encoding and delivery
	p.liManager.SetPacketProcessor(func(task *li.InterceptTask, pkt *types.PacketDisplay) {
		// Determine what to deliver based on task configuration
		deliverX2 := task.DeliveryType == li.DeliveryX2Only || task.DeliveryType == li.DeliveryX2andX3
		deliverX3 := task.DeliveryType == li.DeliveryX3Only || task.DeliveryType == li.DeliveryX2andX3
		if deliverX3 && pkt.VoIPData != nil && !pkt.VoIPData.IsRTP && pkt.VoIPData.CallID != "" {
			callsAny, _ := liPinnedCalls.LoadOrStore(task.XID, &sync.Map{})
			calls := callsAny.(*sync.Map)
			calls.LoadOrStore(pkt.VoIPData.CallID, struct{}{})
			if pkt.VoIPData.Method == "BYE" || pkt.VoIPData.Method == "CANCEL" {
				calls.Delete(pkt.VoIPData.CallID)
			}
		}

		// Learn the target's media endpoints from signalling before any delivery
		// gating: X3-only tasks deliver no IRI but their media still needs a
		// direction, which only the signalling can supply.
		if len(task.Targets) == 1 && pkt.VoIPData != nil && !pkt.VoIPData.IsRTP {
			liMediaDirection.ObserveSIP(task.XID, task.Targets[0], pkt)
		}

		// Encode and deliver X2 (IRI - signaling) for SIP packets
		if deliverX2 && pkt.VoIPData != nil && !pkt.VoIPData.IsRTP {
			pdu, err := liX2Encoder.EncodeIRI(pkt, task.XID)
			if err != nil {
				liX2Errors.Add(1)
				logger.Warn("X2 encode error",
					"xid", task.XID,
					"call_id", voip.SanitizeCallIDForLogging(pkt.VoIPData.CallID),
					"error", err,
				)
			} else if pdu != nil {
				liX2Encoded.Add(1)
				attrBuilder := x2x3.NewAttributeBuilder()
				// Matched target identifier (ETSI attr 17) and Payload Direction.
				// Only set when the task has a single target, so the identity is
				// unambiguous; with multiple targets the MDF falls back to the XID
				// and the direction stays Unknown.
				if len(task.Targets) == 1 {
					pdu.AddAttribute(attrBuilder.MatchedTargetIdentifier(task.Targets[0].Value))
					pdu.Header.PayloadDirection = liMediaDirection.PayloadDirection(task.XID, task.Targets[0], pkt)
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
			taskAdmission, taskActive := p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
			if !taskActive {
				return
			}
			defer taskAdmission.Release()

			callID := pkt.VoIPData.CallID
			var admission *CallAdmission
			ownsAdmission := false
			if callID != "" && p.callLifecycle != nil {
				if shared, ok := p.liPacketAdmissions.Load(pkt); ok {
					admission = shared.(*CallAdmission)
				} else {
					var admissionErr error
					admission, admissionErr = p.callLifecycle.Admit(callID)
					if admissionErr != nil {
						recordLateX3Suppression(callID, 0, "initial_admission")
						return
					}
					ownsAdmission = true
					defer admission.Release()
				}
			}
			if callID != "" {
				callsAny, _ := liPinnedCalls.LoadOrStore(task.XID, &sync.Map{})
				callsAny.(*sync.Map).LoadOrStore(callID, struct{}{})
			}
			pdu, err := liX3Encoder.EncodeCC(pkt, task.XID)
			if err != nil {
				liX3Errors.Add(1)
				logger.Debug("X3 encode error",
					"xid", task.XID,
					"error", err,
				)
			} else if pdu != nil {
				liX3Encoded.Add(1)
				attrBuilder := x2x3.NewAttributeBuilder()
				// Matched target identifier (ETSI attr 17) and Payload Direction.
				// Only set when the task has a single target, so the identity is
				// unambiguous; with multiple targets the MDF falls back to the XID
				// and the direction stays Unknown. RTP carries no SIP identity, so
				// for an identity target the direction comes from the media
				// endpoints learned from the call's signalling, resolved once per
				// SSRC; it stays Unknown when that signalling was not observed.
				if len(task.Targets) == 1 {
					pdu.AddAttribute(attrBuilder.MatchedTargetIdentifier(task.Targets[0].Value))
					pdu.Header.PayloadDirection = liMediaDirection.PayloadDirection(task.XID, task.Targets[0], pkt)
				}
				data, err := pdu.MarshalBinary()
				if err != nil {
					logger.Warn("X3 PDU marshal error", "xid", task.XID, "error", err)
				} else if liDeliveryClient != nil && len(task.DestinationIDs) > 0 {
					// Route through reorder buffer per destination
					ssrc := pkt.VoIPData.SSRC
					rtpSeq := pkt.VoIPData.SequenceNum
					generation := uint64(0)
					if admission != nil {
						generation = admission.Generation()
					}
					for destinationIndex, destID := range task.DestinationIDs {
						did := destID // capture for closure
						insertionTaskAdmission := taskAdmission
						insertionCallAdmission := admission
						insertionOwnsCallAdmission := ownsAdmission
						if destinationIndex > 0 {
							var taskStillActive bool
							insertionTaskAdmission, taskStillActive = p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
							if !taskStillActive {
								return
							}
							if ownsAdmission && callID != "" && p.callLifecycle != nil {
								var insertionErr error
								insertionCallAdmission, insertionErr = p.callLifecycle.AdmitGeneration(callID, generation)
								if insertionErr != nil {
									insertionTaskAdmission.Release()
									recordLateX3Suppression(callID, generation, "destination_admission")
									return
								}
								insertionOwnsCallAdmission = true
							}
						}
						bufKey := fmt.Sprintf("%s-%s", task.XID, did)
						buf, _ := liReorderBuffers.LoadOrStore(bufKey, delivery.NewCallAwareReorderBuffer(
							func(entry delivery.ReorderEntry) {
								deliveryTaskAdmission, taskStillActive := p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
								if !taskStillActive {
									// The reorder buffer may have drained this entry just
									// before task finalization acquired its barrier. In that
									// case DiscardCount cannot see it, so this callback owns
									// the entry's single terminal accounting event.
									recordBufferedX3Discard(1)
									return
								}
								defer deliveryTaskAdmission.Release()

								var sendAdmission *CallAdmission
								if entry.CallID != "" && p.callLifecycle != nil {
									var sendErr error
									sendAdmission, sendErr = p.callLifecycle.AdmitGeneration(entry.CallID, entry.Generation)
									if sendErr != nil {
										recordLateX3Suppression(entry.CallID, entry.Generation, "delayed_send_admission")
										return
									}
									defer sendAdmission.Release()
								}
								dids := []uuid.UUID{did}
								if sendErr := liDeliveryClient.SendX3(task.XID, dids, entry.PDU); sendErr != nil {
									logger.Debug("X3 delivery failed", "xid", task.XID, "error", sendErr)
								}
							},
							60*time.Millisecond,
						))
						buf.(*delivery.ReorderBuffer).DeliverCallX3AfterCommit(callID, generation, ssrc, rtpSeq, data, func() {
							// DeliverCallX3 may synchronously invoke its delivery
							// callback. Release the outer admissions after insertion
							// so that callback can safely re-admit even when a task
							// deactivation writer is already waiting.
							insertionTaskAdmission.Release()
							if insertionOwnsCallAdmission && insertionCallAdmission != nil {
								insertionCallAdmission.Release()
							}
						})
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

func (p *Processor) validateLIConfiguration() error {
	if p.liManager == nil {
		return nil
	}
	return p.liManager.ValidateConfiguration()
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
	liMediaDirection.Close()
}

// processLIPacket processes a packet through the LI system.
// Called from processBatch() for each packet that may have LI relevance.
//
// Note: Currently this is a placeholder. Full filter ID plumbing requires:
// 1. Hunters to include matched filter IDs in packet batches
// 2. LocalSource to use MatchPacketWithIDs and include filter IDs
// This will be implemented in a subsequent step.
func (p *Processor) processLIPacket(pkt *types.PacketDisplay, matchedFilterIDs []string) {
	p.processLIPacketWithProvenance(pkt, matchedFilterIDs, nil)
}

func (p *Processor) processLIPacketWithProvenance(pkt *types.PacketDisplay, directFilterIDs, inheritedFilterIDs []string) {
	p.processLIPacketWithAdmission(pkt, directFilterIDs, inheritedFilterIDs, nil)
}

func (p *Processor) processLIPacketWithAdmission(pkt *types.PacketDisplay, directFilterIDs, inheritedFilterIDs []string, admission *CallAdmission) {
	if p.liManager == nil || !p.liManager.IsEnabled() {
		return
	}
	// Finalization cleanup may already have removed the call's inherited LI
	// filter, so account and reject terminal media before task lookup. The packet
	// callback performs the admission that covers encoding for live calls.
	if admission == nil && pkt != nil && pkt.VoIPData != nil && pkt.VoIPData.IsRTP && pkt.VoIPData.CallID != "" && p.callLifecycle != nil {
		probeAdmission, err := p.callLifecycle.Admit(pkt.VoIPData.CallID)
		if err != nil {
			recordLateX3Suppression(pkt.VoIPData.CallID, 0, "pipeline_admission")
			return
		}
		probeAdmission.Release()
	}
	provenance := li.PacketFilterProvenance{
		DirectFilterIDs:    directFilterIDs,
		InheritedFilterIDs: inheritedFilterIDs,
	}
	if pkt != nil && pkt.VoIPData != nil && pkt.VoIPData.IsRTP && len(inheritedFilterIDs) > 0 {
		// The capture pipeline stamps Call-ID only after authoritative endpoint
		// resolution, and inherited IDs come from that same single call cache.
		provenance.AuthoritativeCallID = pkt.VoIPData.CallID
		provenance.InheritedFromCallID = pkt.VoIPData.CallID
	}
	if admission != nil {
		p.liPacketAdmissions.Store(pkt, admission)
		defer p.liPacketAdmissions.Delete(pkt)
	}
	p.liManager.ProcessPacketWithProvenance(pkt, provenance)
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
	NoEncoder uint64

	// DirectionResolvedMedia counts RTP streams (SSRCs) whose Payload Direction
	// was derived from the call's observed signalling.
	DirectionResolvedMedia uint64
	// DirectionUnknownRTP counts RTP packets delivered without a direction.
	DirectionUnknownRTP   uint64
	X3FinalizedSuppressed uint64
	X3BufferedDiscarded   uint64
}

// getLIEncodingStats returns current LI encoding statistics.
func (p *Processor) getLIEncodingStats() LIEncodingStats {
	dirStats := liMediaDirection.Stats()
	return LIEncodingStats{
		X2Encoded:              liX2Encoded.Load(),
		X2Errors:               liX2Errors.Load(),
		X2Skipped:              liX2Skipped.Load(),
		X3Encoded:              liX3Encoded.Load(),
		X3Errors:               liX3Errors.Load(),
		X3Skipped:              liX3Skipped.Load(),
		NoEncoder:              liNoEncoder.Load(),
		DirectionResolvedMedia: dirStats.ResolvedFromMedia,
		DirectionUnknownRTP:    dirStats.UnknownRTP,
		X3FinalizedSuppressed:  liX3FinalizedSuppressed.Load(),
		X3BufferedDiscarded:    liX3BufferedDiscarded.Load(),
	}
}

func (p *Processor) populateLIEncodingStats(dst *management.ProcessorStats) {
	if dst == nil || !p.isLIEnabled() {
		return
	}
	stats := p.getLIEncodingStats()
	managerStats := p.liManager.Stats()
	dst.LiEncoding = &management.LIEncodingStats{
		X2Encoded:                    stats.X2Encoded,
		X2Errors:                     stats.X2Errors,
		X2Skipped:                    stats.X2Skipped,
		X3Encoded:                    stats.X3Encoded,
		X3Errors:                     stats.X3Errors,
		X3Skipped:                    stats.X3Skipped,
		NoEncoder:                    stats.NoEncoder,
		DirectionResolvedMedia:       stats.DirectionResolvedMedia,
		DirectionUnknownRtp:          stats.DirectionUnknownRTP,
		X3FinalizedOrStaleSuppressed: stats.X3FinalizedSuppressed,
		X3BufferedDiscarded:          stats.X3BufferedDiscarded,
		InheritedProvenanceRejected:  managerStats.InheritedProvenanceRejected,
	}
	if p.packetSource != nil {
		sourceStats := p.packetSource.Stats()
		dst.LiEncoding.RtpOwnershipUnresolved = sourceStats.RTPOwnershipUnresolved
		dst.LiEncoding.RtpOwnershipAmbiguous = sourceStats.RTPOwnershipAmbiguous
		dst.LiEncoding.IdentityInheritanceSuppressed = sourceStats.IdentityInheritanceSuppressed
	}
}
