//go:build hunter || all

package hunter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/packetforwarding"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

func (h *Hunter) configureReliablePackets() error {
	if h.config.ForwardMode == "" {
		h.config.ForwardMode = "packets"
	}
	config, err := h.config.Packets.Normalize()
	if err != nil {
		return err
	}
	h.config.Packets = config
	if h.config.FilterPolicy.Owner == "li" && (config.DeliveryProfile != "reliable" || config.Spool.Protection != "encrypted" || h.config.ForwardMode != "packets") {
		return errors.New("LI-owned capture requires reliable encrypted raw packets")
	}
	if h.config.FilterPolicy.Owner == "li" {
		if h.config.VoIPSignallingPolicy == "all" {
			return errors.New("LI-owned capture requires task-selected signalling; signalling-policy all is unsupported")
		}
		if h.config.NoFilterPolicy != "" && h.config.NoFilterPolicy != "deny" {
			return errors.New("LI-owned capture requires no-filter-policy deny")
		}
		h.config.NoFilterPolicy = "deny"
	}
	if config.DeliveryProfile != "reliable" {
		return nil
	}
	if viper.GetString("hunter.http.tls_keylog") != "" || viper.GetString("hunter.http.tls_keylog_pipe") != "" || viper.GetString("http.tls_keylog") != "" || viper.GetBool("http.tls_decryption_enabled") {
		return errors.New("reliable raw packets do not support HTTP TLS keylog capture: matched-session key attachment and acknowledged key delivery are not implemented")
	}
	if h.config.ForwardMode != "packets" || h.config.EventFallbackToPackets {
		return errors.New("reliable raw packets require packet mode without event fallback")
	}
	if !h.config.TLSEnabled || h.config.TLSSkipVerify || h.config.TLSCertFile == "" || h.config.TLSKeyFile == "" {
		return errors.New("reliable raw packets require verified mutual TLS")
	}
	if h.config.DiskBufferEnabled {
		return errors.New("reliable raw packets cannot use legacy destructive disk overflow; preserve/migrate it explicitly")
	}
	verifier, err := packetreceipt.LoadVerifier(config.DestinationID, config.TrustedCert)
	if err != nil {
		return err
	}
	spoolConfig, err := config.SpoolConfig(h.config.HunterID)
	if err != nil {
		return err
	}
	var storageKeys []*securestore.Keyring
	if spoolConfig.Keys != nil {
		storageKeys = append(storageKeys, spoolConfig.Keys)
	}
	if keyring := h.filterManager.CapturePolicyStorageKeyring(); keyring != nil {
		storageKeys = append(storageKeys, keyring)
	}
	if err := securestore.CheckIndependent(storageKeys...); err != nil {
		return fmt.Errorf("capture storage keys must be independent: %w", err)
	}
	spool, err := packetspool.Open(spoolConfig)
	if err != nil {
		return err
	}
	h.packetSpool, h.packetReceiptVerifier = spool, verifier
	return nil
}

func (h *Hunter) openReliablePacketStream(lifetime, setup context.Context, conn grpc.ClientConnInterface) (data.DataService_StreamPacketsClient, error) {
	// The connection manager owns the setup deadline and zero-batch readiness
	// probe. The stream itself belongs to the long-lived generation context.
	return packetforwarding.Open(lifetime, conn, h.packetSpool, h.packetReceiptVerifier)
}

func (h *Hunter) reliablePacketStreamFactory() func(context.Context, context.Context, grpc.ClientConnInterface) (data.DataService_StreamPacketsClient, error) {
	if h.packetSpool == nil {
		return nil
	}
	return h.openReliablePacketStream
}

func (h *Hunter) retainPacketBatch(batch *pipeline.PacketBatch) error {
	wire, err := grpcadapter.ToPacketBatch(batch)
	if err != nil {
		h.cancel()
		return err
	}
	result, err := h.packetSpool.Enqueue(wire)
	if err != nil && !result.Committed {
		// An unaccounted/uncertain storage failure stops production. Enforcing a
		// configured retention policy returns a committed drop/loss record.
		logger.Error("Raw packet retention fault; stopping hunter", "error", err)
		h.cancel()
	}
	if result.Dropped {
		h.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
	}
	return err
}

func (h *Hunter) startReliablePacketProducer() {
	if h.packetSpool == nil {
		return
	}
	config := h.packetForwardingConfig()
	config.BatchSink = h.retainPacketBatch
	h.packetProducer = forwarding.New(config, h.statsCollector, h.captureManager, h.ctx, nil)
	h.configurePacketProcessor(h.packetProducer)
	h.wg.Add(1)
	go h.packetProducer.ForwardPackets(&h.wg)
	if h.config.FilterPolicy.Owner == "li" {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-h.ctx.Done():
					return
				case <-ticker.C:
				}
				quiesceCtx, cancel := context.WithTimeout(h.ctx, h.config.Failover.AttemptTimeout)
				err := h.packetProducer.WithCaptureBoundary(func() error { return h.filterManager.QuiesceExpiredPolicy(quiesceCtx) })
				cancel()
				if err != nil && h.ctx.Err() == nil {
					logger.Error("Unable to stop expired capture policy", "error", err)
					h.cancel()
					return
				}
			}
		}()
	}
}

func (h *Hunter) closeReliablePackets() {
	if h.packetProducer != nil {
		if err := h.packetProducer.Close(); err != nil {
			logger.Error("Close raw packet producer", "error", err)
		}
	}
	if h.packetSpool != nil {
		if err := h.packetSpool.Close(); err != nil {
			logger.Error("Close raw packet spool", "error", err)
		}
	}
}

// Close releases persistent ownership after construction or a completed run.
// Callers must first cancel and join Start when a run is still active.
func (h *Hunter) Close() error {
	var err error
	if h.packetProducer != nil {
		err = errors.Join(err, h.packetProducer.Close())
	}
	if h.packetSpool != nil {
		err = errors.Join(err, h.packetSpool.Close())
	}
	if h.filterManager != nil {
		err = errors.Join(err, h.filterManager.CloseSharedPolicy())
	}
	return err
}

func (h *Hunter) packetForwardingConfig() forwarding.Config {
	return forwarding.Config{ObservationDomain: h.captureObservationDomain, ValidateCaptureSelection: h.captureSelectionAllowed, RequireCaptureProvenance: h.config.FilterPolicy.Owner == "li", RADIUSPorts: h.config.RADIUSPorts, RADIUSScope: h.config.RADIUSScope, RADIUSOnly: h.config.RADIUSOnly, RADIUSCorrelation: h.config.RADIUSCorrelation, RADIUSMatcher: h.config.RADIUSMatcher, HunterID: h.config.HunterID, BatchSize: h.config.BatchSize, BatchTimeout: h.config.BatchTimeout, BufferSize: h.config.BufferSize, DiskBufferEnabled: h.config.DiskBufferEnabled, DiskBufferDir: h.config.DiskBufferDir, DiskBufferMaxSize: h.config.DiskBufferMaxSize, IncludeHTTPHeaders: viper.GetBool("logs.include_http_headers"), CaptureAllowed: h.filterManager.CaptureAllowed, InitialCapturePolicy: h.filterManager.EffectiveCapturePolicy()}
}

// ApplyCaptureSnapshot keeps signed authority changes on the same boundary as
// packet matching and retained raw batches; control reconnection stays separate.
func (h *Hunter) ApplyCaptureSnapshot(encoded []byte, apply func() error) error {
	if h.packetProducer == nil {
		return apply()
	}
	ctx, cancel := context.WithTimeout(h.ctx, h.config.Failover.AttemptTimeout)
	defer cancel()
	if err := h.captureManager.Quiesce(ctx); err != nil {
		return err
	}
	buffer := h.captureManager.GetPacketBuffer()
	if buffer != nil {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for buffer.Snapshot().TotalLength() > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
	return h.packetProducer.ApplyCapturePolicy(encoded, apply)
}

func (h *Hunter) configurePacketProcessor(manager *forwarding.Manager) {
	if h.packetProcessor != nil {
		manager.SetPacketProcessor(h.packetProcessor)
	}
	if h.applicationFilter != nil {
		manager.SetApplicationFilter(h.applicationFilter)
	}
	if h.dnsProcessor != nil {
		manager.SetDNSMetadataProvider(h.dnsProcessor)
	}
}

func (h *Hunter) reliableSenderConfig(stream data.DataService_StreamPacketsClient) (forwarding.Config, error) {
	transport, ok := stream.(*packetforwarding.Stream)
	if !ok {
		return forwarding.Config{}, fmt.Errorf("reliable raw stream adapter missing")
	}
	config := h.packetForwardingConfig()
	config.ExternalProducer = true
	timeout := h.config.SendTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	config.DurableSendNext = func(ctx context.Context, _ data.DataService_StreamPacketsClient, wait func(context.Context) error) (uint64, error) {
		count, err := transport.SendNext(ctx, wait, timeout)
		if err == nil {
			h.packetReplay.Add(count)
		}
		return count, err
	}
	return config, nil
}

func (h *Hunter) rawPacketStatus() *management.RawPacketStatus {
	status := &management.RawPacketStatus{Profile: h.config.Packets.DeliveryProfile, PolicyRevision: h.filterManager.PolicyRevision()}
	if h.packetSpool == nil {
		return status
	}
	spool := h.packetSpool.Status()
	status.AckScope = spool.Identity.AckScope
	status.DestinationId = spool.Identity.DestinationID
	status.ProducerSessionId = spool.Identity.SessionID
	status.QueuedRecords = uint64(spool.PendingRecords)
	status.QueuedBytes = spool.LogicalBytes
	status.OldestAgeNs = int64(spool.OldestAge)
	status.AckedSequence = spool.AckedSequence
	status.Replayed = h.packetReplay.Load()
	status.Dropped = spool.DroppedRecords
	return status
}
