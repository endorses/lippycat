//go:build cli || all

package sniff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/pcapgo"
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

type pcapEnvelopeSink struct {
	file          *os.File
	writer        *pcapgo.Writer
	headerWritten bool
}

func newPCAPEnvelopeSink(path string) (*pcapEnvelopeSink, error) {
	// #nosec G304 -- path is the explicit --write-file destination.
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create PCAP file %q: %w", path, err)
	}
	return &pcapEnvelopeSink{file: f, writer: pcapgo.NewWriter(f)}, nil
}

func (s *pcapEnvelopeSink) HandlePacket(_ context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
	if !s.headerWritten {
		if err := s.writer.WriteFileHeader(65535, env.LinkType); err != nil {
			return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write PCAP header: %w", err)}
		}
		s.headerWritten = true
	}
	info := captureadapter.ToPacketInfo(env)
	if err := s.writer.WritePacket(info.Packet.Metadata().CaptureInfo, env.Data); err != nil {
		return pipeline.Result{Outcome: pipeline.OutcomePermanentFailure, Err: fmt.Errorf("write PCAP packet: %w", err)}
	}
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}

func (s *pcapEnvelopeSink) Close(context.Context) error {
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	if err != nil {
		return fmt.Errorf("close PCAP file: %w", err)
	}
	return nil
}

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
