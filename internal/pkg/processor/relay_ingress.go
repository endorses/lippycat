//go:build processor || tap || all

package processor

import (
	"fmt"
	"io"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func normalizeRelayOrigins(config map[string][]string) (map[string][]string, error) {
	result := make(map[string][]string, len(config))
	for relay, origins := range config {
		if relay == "" || strings.ContainsAny(relay, " \t\r\n\x00*/\\") {
			return nil, fmt.Errorf("invalid delegated relay identity %q", relay)
		}
		if len(origins) == 0 {
			return nil, fmt.Errorf("relay %q has no delegated origins", relay)
		}
		seen := map[string]bool{}
		for _, origin := range origins {
			if origin == "" || strings.ContainsAny(origin, " \t\r\n\x00*/\\") {
				return nil, fmt.Errorf("invalid origin delegated to relay %q", relay)
			}
			if !seen[origin] {
				result[relay] = append(result[relay], origin)
				seen[origin] = true
			}
		}
	}
	return result, nil
}

// StreamRelayPackets authorizes the immediate processor and each original
// capture source separately. Direct StreamPackets admission is unchanged.
func (p *Processor) StreamRelayPackets(stream data.RelayDataService_StreamRelayPacketsServer) error {
	open, err := stream.Recv()
	if err != nil {
		return err
	}
	if open.GetProtocolVersion() != 1 || open.GetRelayId() == "" || open.GetBatch() != nil {
		return status.Error(codes.InvalidArgument, "relay stream requires version 1 open without a packet batch")
	}
	relayID := open.GetRelayId()
	if !radiusStreamSourceTrusted(stream.Context(), relayID) {
		return status.Error(codes.Unauthenticated, "relay identity must match a verified client certificate")
	}
	if len(p.config.RelayOrigins[relayID]) == 0 {
		return status.Error(codes.PermissionDenied, "relay has no configured origin delegation")
	}
	registered := p.downstreamManager.Get(relayID)
	if registered == nil {
		return status.Error(codes.FailedPrecondition, "relay requires current processor registration")
	}
	contract := registered.GetForwardingContract()
	if contract.Mode != management.ForwardingMode_FORWARDING_MODE_PACKETS {
		return status.Error(codes.FailedPrecondition, "relay registration is not packet mode")
	}
	learnedEvidenceVersions := p.acceptLearnedEvidenceVersions(open.LearnedEvidenceVersions)
	if err := stream.Send(&data.StreamControl{LearnedEvidenceVersions: learnedEvidenceVersions, FlowControl: p.flowController.Determine()}); err != nil {
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
		if message.GetProtocolVersion() != 1 || message.GetRelayId() != relayID || message.GetBatch() == nil {
			return status.Error(codes.InvalidArgument, "relay stream identity or envelope changed")
		}
		current := p.downstreamManager.Get(relayID)
		if current != registered || current.GetForwardingContract().PacketGeneration != contract.PacketGeneration || current.GetForwardingContract().Mode != management.ForwardingMode_FORWARDING_MODE_PACKETS {
			return status.Error(codes.FailedPrecondition, "relay registration was replaced")
		}
		batch := message.GetBatch()
		allowed := false
		for _, origin := range p.config.RelayOrigins[relayID] {
			if origin == batch.GetHunterId() {
				allowed = true
				break
			}
		}
		if !allowed {
			return status.Error(codes.PermissionDenied, "relay is not delegated this capture origin")
		}
		if p.filterProcessingBlocked() {
			return status.Error(codes.Unavailable, "filter policy is faulted")
		}
		if err := learnedwire.ValidateBatchEvidence(batch, p.acceptLearnedEvidenceVersions(learnedEvidenceVersions)); err != nil {
			return status.Errorf(codes.FailedPrecondition, "relayed evidence contract: %v", err)
		}
		internal, err := source.FromProtoBatchE(batch)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid relayed packet batch: %v", err)
		}
		// Verified relay-to-origin delegation establishes transport origin trust;
		// the normal RADIUS decoder and LI admission still validate each claim.
		internal.RADIUSSourceTrusted = true
		internal.MediaSourceTrusted = true
		p.processBatch(internal)
		if p.filterProcessingBlocked() {
			return status.Error(codes.Unavailable, "filter policy is faulted")
		}
		if err := stream.Send(&data.StreamControl{AckSequence: batch.Sequence, FlowControl: p.flowController.Determine()}); err != nil {
			return err
		}
	}
}
