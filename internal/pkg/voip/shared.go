package voip

import (
	"context"
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
)

// Shared variables and helpers used by both CLI and hunter builds

var (
	globalBufferMgr *BufferManager
)

// virtualInterfacePacketSink makes optional VoIP virtual-interface output an
// ordinary normalized packet sink. Selection happens before dispatch; the sink
// has no knowledge of SIP/RTP or call tracking.
type virtualInterfacePacketSink struct {
	manager vinterface.Manager
	timing  *vinterface.TimingReplayer
}

func (s *virtualInterfacePacketSink) HandlePacket(_ context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
	if s.timing != nil {
		s.timing.WaitForPacketTime(env.CaptureTime)
	}
	display := capture.ConvertPacketToDisplay(captureadapter.ToPacketInfo(env))
	display.RawData = append([]byte(nil), env.Data...)
	display.LinkType = env.LinkType
	if err := s.manager.InjectPacketBatch([]types.PacketDisplay{display}); err != nil {
		if errors.Is(err, vinterface.ErrQueueFull) {
			return pipeline.Result{Outcome: pipeline.OutcomeDropped, DropReason: pipeline.DropQueueFull}
		}
		return pipeline.Result{Outcome: pipeline.OutcomeRetryableFailure, Err: fmt.Errorf("inject packet: %w", err)}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func (s *virtualInterfacePacketSink) Close(context.Context) error {
	if s.manager == nil {
		return nil
	}
	err := s.manager.Shutdown()
	s.manager = nil
	if err != nil {
		return fmt.Errorf("shut down virtual interface: %w", err)
	}
	return nil
}

// containsUserInHeaders checks if any of the SIP headers contain a surveiled user
// Returns true if there are NO filters configured (promiscuous mode) OR if a match is found
func containsUserInHeaders(headers map[string]string) bool {
	// If no SIP users are configured, accept all VoIP traffic (promiscuous/testing mode)
	hasSurveiled := sipusers.HasSurveiled()
	logger.Debug("containsUserInHeaders check",
		"has_surveiled", hasSurveiled,
		"headers", headers)
	if !hasSurveiled {
		logger.Debug("Promiscuous mode - accepting all VoIP traffic")
		return true
	}

	// Check if any header matches a surveiled user
	for _, field := range []string{"from", "to", "p-asserted-identity"} {
		val := headers[field]
		if sipusers.IsSurveiled(val) {
			logger.Debug("Matched surveilled user", "field", field, "value", val)
			return true
		}
	}
	logger.Debug("No match found - rejecting packet")
	return false
}
