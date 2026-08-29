//go:build cli || all

package sniff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/pipeline/pcapsink"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
)

type localEnvelopePipeline struct {
	fanout *pipeline.PacketFanout
	count  int
}

func (p *localEnvelopePipeline) process(in <-chan capture.PacketInfo, kind pipeline.SourceKind) {
	for info := range in {
		env := captureadapter.FromPacketInfo(info, kind)
		p.count++
		for _, named := range p.fanout.Dispatch(context.Background(), env) {
			result := named.Result
			if result.Err != nil {
				logger.Error("Local packet sink failed", "sink", named.Name, "outcome", result.Outcome, "error", result.Err, "interface", env.Source.InterfaceName)
			}
		}
	}
}

func (p *localEnvelopePipeline) close() {
	if err := p.fanout.Close(context.Background()); err != nil {
		logger.Error("Failed to close local packet sinks", "error", err)
	}
}

type cliEnvelopeSink struct {
	w      io.Writer
	format string
	quiet  bool
	json   *json.Encoder
}

func newCLIEnvelopeSink(w io.Writer, format string, quiet bool) *cliEnvelopeSink {
	s := &cliEnvelopeSink{w: w, format: format, quiet: quiet}
	if format == "json" {
		s.json = json.NewEncoder(w)
	}
	return s
}

func (s *cliEnvelopeSink) HandlePacket(_ context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
	if s.quiet {
		return pipeline.Result{Outcome: pipeline.OutcomeFiltered}
	}
	info := captureadapter.ToPacketInfo(env)
	if s.json != nil {
		if err := s.json.Encode(capture.ConvertPacketToDisplay(info)); err != nil {
			return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("encode packet JSON: %w", err)}
		}
		return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
	}
	if _, err := fmt.Fprintln(s.w, info.Packet); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write packet text: %w", err)}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func (*cliEnvelopeSink) Close(context.Context) error { return nil }

func newPCAPEnvelopeSink(path string) (*pcapsink.Sink, error) { return pcapsink.New(path) }

type virtualInterfaceEnvelopeSink struct {
	manager vinterface.Manager
	timing  *vinterface.TimingReplayer
}

func (s *virtualInterfaceEnvelopeSink) HandlePacket(_ context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
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

func (s *virtualInterfaceEnvelopeSink) Close(context.Context) error {
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

func startVirtualInterfaceSink(cfg vinterface.Config, replayTiming bool, startupDelay time.Duration) (*virtualInterfaceEnvelopeSink, error) {
	mgr, err := vinterface.NewManager(cfg)
	if err != nil {
		return nil, err
	}
	if err := mgr.Start(); err != nil {
		if closeErr := mgr.Shutdown(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("clean up virtual interface: %w", closeErr))
		}
		return nil, err
	}
	if startupDelay > 0 {
		time.Sleep(startupDelay)
	}
	return &virtualInterfaceEnvelopeSink{manager: mgr, timing: vinterface.NewTimingReplayer(replayTiming)}, nil
}
