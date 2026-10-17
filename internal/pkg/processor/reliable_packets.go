//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type PacketCustodyConfig struct {
	Enabled            bool                      `mapstructure:"enabled"`
	Store              packetreceipt.StoreConfig `mapstructure:"store"`
	AuthorityID        string                    `mapstructure:"authority"`
	SigningCertificate string                    `mapstructure:"signing_cert"`
	SigningKey         string                    `mapstructure:"signing_key"`
}

type packetCustody struct {
	// Current authority is deliberately volatile and bounded by accepted records.
	// Restoring retained payload never restores current capture selection.
	currentMu  sync.Mutex
	current    map[currentPacketKey]bool
	replayed   atomic.Uint64
	duplicates atomic.Uint64
	late       atomic.Uint64
	watermarks map[string]int64 // bounded by the store's permanent session limit
	store      *packetreceipt.Store
	signer     *packetreceipt.Signer
	wake       chan struct{}
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

type currentPacketKey struct {
	source, session, epoch, destination, scope string
	sequence                                   uint64
}

func captureRecordKey(id *data.RawPacketIdentity, sequence uint64) currentPacketKey {
	return currentPacketKey{id.SourceId, id.ProducerSessionId, id.CaptureEpoch, id.DestinationId, id.AckScope, sequence}
}

func (p *Processor) initPacketCustody() error {
	config := p.config.PacketCustody
	if !config.Enabled {
		return nil
	}
	if !p.config.TLSEnabled || !p.config.TLSClientAuth {
		return errors.New("reliable raw custody requires mutual TLS")
	}
	if p.config.LIEnabled && config.Store.Protection != "encrypted" {
		return errors.New("LI raw custody requires encrypted storage")
	}
	if config.AuthorityID != config.Store.DestinationID {
		return errors.New("raw receipt authority must match the logical destination")
	}
	signer, err := packetreceipt.LoadSigner(config.AuthorityID, config.SigningCertificate, config.SigningKey)
	if err != nil {
		return err
	}
	store, err := packetreceipt.Open(config.Store)
	if err != nil {
		return err
	}
	p.packetCustody = &packetCustody{store: store, signer: signer, wake: make(chan struct{}, 1), watermarks: make(map[string]int64), current: make(map[currentPacketKey]bool)}
	return nil
}

func (p *Processor) startPacketCustody(ctx context.Context) {
	runtime := p.packetCustody
	if runtime == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	runtime.cancel = cancel
	runtime.wg.Add(1)
	go func() {
		defer runtime.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for ctx.Err() == nil {
			if !p.filterProcessingBlocked() {
				runtime.currentMu.Lock()
				pending, err := runtime.store.Pending(1)
				current := false
				if len(pending) > 0 {
					current = runtime.current[captureRecordKey(pending[0].Identity, pending[0].Batch.Sequence)]
				}
				runtime.currentMu.Unlock()
				if err != nil {
					logger.Error("Raw custody replay fault", "error", err)
					p.blockFilterProcessing()
					return
				}
				if len(pending) > 0 {
					item := pending[0]
					batch, err := source.FromProtoBatchE(item.Batch)
					if err != nil {
						logger.Error("Accepted raw packet conversion failed", "error", err)
						p.blockFilterProcessing()
						return
					}
					batch.RADIUSSourceTrusted = true // verified identity/delegation was required before durable acceptance
					batch.MediaSourceTrusted = true
					batch.HistoricalReplay = !current
					if p.mediaControl != nil {
						for _, envelope := range batch.Envelopes {
							if envelope.CaptureTime.Before(p.mediaControl.started) {
								batch.HistoricalReplay = true
								break
							}
						}
					}
					key := item.Identity.SourceId + "\x00" + item.Identity.ProducerSessionId + "\x00" + item.Identity.CaptureEpoch
					watermark := runtime.watermarks[key]
					for _, packet := range item.Batch.Packets {
						if packet.TimestampNs > 0 && packet.TimestampNs < watermark {
							runtime.late.Add(1)
						}
						if packet.TimestampNs > watermark {
							watermark = packet.TimestampNs
						}
					}
					runtime.watermarks[key] = watermark
					p.processBatch(batch)
					if p.filterProcessingBlocked() {
						continue
					}
					digest, err := packetreceipt.BatchDigest(item.Batch)
					if err == nil {
						err = runtime.store.Processed(item.Identity, item.Batch.Sequence, digest)
					}
					if err != nil {
						logger.Error("Raw custody processing checkpoint failed", "error", err)
						p.blockFilterProcessing()
						return
					}
					runtime.currentMu.Lock()
					delete(runtime.current, captureRecordKey(item.Identity, item.Batch.Sequence))
					runtime.currentMu.Unlock()
					runtime.replayed.Add(uint64(len(item.Batch.Packets)))
					continue
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-runtime.wake:
			case <-ticker.C:
			}
		}
	}()
}

func (p *Processor) closePacketCustody() error {
	if p.packetCustody == nil {
		return nil
	}
	if p.packetCustody.cancel != nil {
		p.packetCustody.cancel()
	}
	p.packetCustody.wg.Wait()
	return p.packetCustody.store.Close()
}

func (p *Processor) registerPacketCustody(registrar grpc.ServiceRegistrar) {
	data.RegisterReliablePacketServiceServer(registrar, p)
}

func (p *Processor) rawPacketStatus() *management.RawPacketStatus {
	status := &management.RawPacketStatus{Profile: "best_effort"}
	if p.sharedPolicy != nil {
		status.PolicyRevision = p.sharedPolicy.state.Revision()
	}
	if p.packetCustody == nil {
		return status
	}
	stats := p.packetCustody.store.Stats()
	status.Profile = "reliable"
	status.DestinationId = p.config.PacketCustody.Store.DestinationID
	status.QueuedRecords = uint64(stats.PendingRecords)
	status.QueuedBytes = stats.PendingBytes
	status.OldestAgeNs = int64(stats.OldestAge)
	status.Replayed = p.packetCustody.replayed.Load()
	status.Duplicates = p.packetCustody.duplicates.Load()
	status.Late = p.packetCustody.late.Load()
	return status
}

func (p *Processor) StreamReliablePackets(stream data.ReliablePacketService_StreamReliablePacketsServer) error {
	open, err := stream.Recv()
	if err != nil {
		return err
	}
	if open.ProtocolVersion != packetreceipt.ProtocolVersion || packetreceipt.ValidIdentity(open.Identity) != nil || open.Batch != nil || len(open.Losses) > 0 || open.LossGeneration != 0 || open.RetireSession {
		return status.Error(codes.InvalidArgument, "reliable raw stream requires version 1 identity open")
	}
	id := open.Identity
	var contract *hunter.PacketStreamContract
	var relayGeneration uint64
	if open.RelayId == "" {
		if !radiusStreamSourceTrusted(stream.Context(), id.SourceId) {
			return status.Error(codes.Unauthenticated, "reliable raw source must match verified client certificate")
		}
		var ok bool
		contract, ok = p.hunterManager.AdmitPacketStream(id.SourceId)
		if !ok {
			return status.Error(codes.FailedPrecondition, "reliable raw stream requires packet-mode registration")
		}
	} else if !p.reliableRelayAuthorized(stream.Context(), open.RelayId, id.SourceId) {
		return status.Error(codes.PermissionDenied, "reliable raw relay origin delegation rejected")
	} else {
		registered := p.downstreamManager.Get(open.RelayId)
		if registered == nil {
			return status.Error(codes.FailedPrecondition, "raw relay registration expired")
		}
		relayGeneration = registered.GetForwardingContract().PacketGeneration
	}
	validateGeneration := func() bool {
		if contract != nil {
			return p.hunterManager.ValidatePacketStream(id.SourceId, contract)
		}
		current := p.downstreamManager.Get(open.RelayId)
		return current != nil && current.GetForwardingContract().PacketGeneration == relayGeneration && p.reliableRelayAuthorized(stream.Context(), open.RelayId, id.SourceId)
	}
	// Central scope traverses relays without claiming local custody. Only the
	// configured destination can sign the receipt that retires origin data.
	if id.AckScope == "central" && (p.packetCustody == nil || p.config.PacketCustody.Store.DestinationID != id.DestinationId) {
		return p.proxyReliablePackets(stream, open, validateGeneration)
	}
	if p.packetCustody == nil || p.config.PacketCustody.Store.DestinationID != id.DestinationId {
		return status.Error(codes.FailedPrecondition, "requested durable raw destination unavailable")
	}
	if p.upstreamManager != nil && p.upstreamManager.Configured() {
		return status.Error(codes.FailedPrecondition, "receiver custody with an external upstream requires retained upstream delivery; use central scope")
	}
	ready := &data.RawPacketReceipt{Identity: proto.Clone(id).(*data.RawPacketIdentity)}
	if err := p.packetCustody.signer.Sign(ready); err != nil {
		return status.Error(codes.Internal, "raw receipt signing unavailable")
	}
	if err := stream.Send(&data.ReliablePacketControl{ProtocolVersion: 1, Identity: id, Receipt: ready, Control: &data.StreamControl{FlowControl: p.flowController.Determine()}}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if message.ProtocolVersion != 1 || !proto.Equal(message.Identity, id) || message.RelayId != open.RelayId {
			return status.Error(codes.InvalidArgument, "reliable raw stream contract changed")
		}
		if !validateGeneration() {
			return status.Error(codes.FailedPrecondition, "raw source registration replaced")
		}
		if open.RelayId != "" && !p.reliableRelayAuthorized(stream.Context(), open.RelayId, id.SourceId) {
			return status.Error(codes.PermissionDenied, "raw origin delegation revoked")
		}
		if p.filterProcessingBlocked() {
			return status.Error(codes.Unavailable, "raw policy not ready")
		}
		if message.Batch != nil {
			if err := p.validateLICapturePolicy(message.Batch); err != nil {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			if _, err := source.FromProtoBatchE(message.Batch); err != nil {
				return status.Error(codes.InvalidArgument, "invalid raw packet batch")
			}
		}
		p.packetCustody.currentMu.Lock()
		receipt, duplicate, err := p.packetCustody.store.Accept(message)
		if err == nil && !duplicate && message.Batch != nil && message.CurrentCapture && len(p.packetCustody.current) < p.config.PacketCustody.Store.MaxRecords {
			p.packetCustody.current[captureRecordKey(id, message.Batch.Sequence)] = true
		}
		p.packetCustody.currentMu.Unlock()
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "raw custody rejected: %v", err)
		}
		if duplicate && message.Batch != nil {
			p.packetCustody.duplicates.Add(uint64(len(message.Batch.Packets)))
		}
		if err := p.packetCustody.signer.Sign(receipt); err != nil {
			return status.Error(codes.Internal, "raw receipt signing unavailable")
		}
		select {
		case p.packetCustody.wake <- struct{}{}:
		default:
		}
		if err := stream.Send(&data.ReliablePacketControl{ProtocolVersion: 1, Identity: id, Receipt: receipt, Control: &data.StreamControl{AckSequence: receipt.Sequence, FlowControl: p.flowController.Determine()}}); err != nil {
			return err
		}
	}
}

func (p *Processor) reliableRelayAuthorized(ctx context.Context, relayID, origin string) bool {
	if !radiusStreamSourceTrusted(ctx, relayID) {
		return false
	}
	registered := p.downstreamManager.Get(relayID)
	if registered == nil || registered.GetForwardingContract().Mode != management.ForwardingMode_FORWARDING_MODE_PACKETS {
		return false
	}
	for _, allowed := range p.config.RelayOrigins[relayID] {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (p *Processor) proxyReliablePackets(stream data.ReliablePacketService_StreamReliablePacketsServer, open *data.ReliablePacketMessage, validateGeneration func() bool) error {
	if p.upstreamManager == nil {
		return status.Error(codes.FailedPrecondition, "central receipt route unavailable")
	}
	upstream, err := p.upstreamManager.OpenReliablePacketStream(stream.Context())
	if err != nil {
		return status.Error(codes.Unavailable, "central receipt route unavailable")
	}
	defer func() {
		if err := upstream.CloseSend(); err != nil {
			logger.Error("Close reliable relay upstream", "error", err)
		}
	}()
	message := proto.Clone(open).(*data.ReliablePacketMessage)
	message.RelayId = p.config.ProcessorID
	if err := upstream.Send(message); err != nil {
		return err
	}
	ready, err := upstream.Recv()
	if err != nil {
		return err
	}
	if err := stream.Send(ready); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if message.ProtocolVersion != 1 || !proto.Equal(message.Identity, open.Identity) || message.RelayId != open.RelayId {
			return status.Error(codes.InvalidArgument, "raw relay stream contract changed")
		}
		if !validateGeneration() {
			return status.Error(codes.FailedPrecondition, "raw source registration replaced")
		}
		if open.RelayId != "" && !p.reliableRelayAuthorized(stream.Context(), open.RelayId, open.Identity.SourceId) {
			return status.Error(codes.PermissionDenied, "raw relay delegation revoked")
		}
		message = proto.Clone(message).(*data.ReliablePacketMessage)
		message.RelayId = p.config.ProcessorID
		if err := upstream.Send(message); err != nil {
			return err
		}
		receipt, err := upstream.Recv()
		if err != nil {
			return err
		}
		if !proto.Equal(receipt.Identity, open.Identity) {
			return fmt.Errorf("central raw receipt route identity mismatch")
		}
		if err := stream.Send(receipt); err != nil {
			return err
		}
	}
}
