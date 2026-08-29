//go:build tui || all

package tui

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
)

// displaySamplingPolicy contains the live-display shedding decision. Replay
// losslessness is expressed as policy configuration, not scattered bridge
// conditionals.
type displaySamplingPolicy struct {
	preserveAll     bool
	recent          *timeRingBuffer
	lastRateCheck   time.Time
	ratio           float64
	lastUpdateCount int64
}

func newDisplaySamplingPolicy(preserveAll bool) *displaySamplingPolicy {
	return &displaySamplingPolicy{preserveAll: preserveAll, recent: newTimeRingBuffer(25000), lastRateCheck: time.Now(), ratio: 1}
}

func (p *displaySamplingPolicy) shouldDisplay(env *pipeline.PacketEnvelope, packetCount, displayedCount int64, pending int) bool {
	if p.preserveAll || env.Source.Kind == pipeline.SourcePCAPReplay {
		return true
	}
	if packetCount-p.lastUpdateCount >= 1000 {
		now := time.Now()
		p.recent.push(now)
		if now.Sub(p.lastRateCheck) > constants.TUITickInterval {
			p.recent.trimBefore(now.Add(-2 * time.Second))
			p.lastRateCheck = now
		}
		p.ratio = p.currentRatio(now)
		p.lastUpdateCount = packetCount
	}
	if isSIPPacket(env.Packet()) {
		return true
	}
	return p.ratio >= 1 || float64(packetCount)*p.ratio >= float64(displayedCount+int64(pending)+1)
}

func (p *displaySamplingPolicy) currentRatio(now time.Time) float64 {
	count := p.recent.len()
	if count < 10 || now.Sub(p.recent.oldest()).Seconds() < 0.1 {
		atomic.StoreInt64(&bridgeStats.SamplingRatio, 1000)
		return 1
	}
	rate := float64(count) / now.Sub(p.recent.oldest()).Seconds()
	ratio := 1000 / rate
	if ratio > 1 {
		ratio = 1
	} else if ratio < 0.01 {
		ratio = 0.01
	}
	atomic.StoreInt64(&bridgeStats.SamplingRatio, int64(ratio*1000))
	return ratio
}

// tuiSIPReassemblyStage is the optional TCP SIP classification stage. Keeping
// it behind this small lifecycle API prevents the TUI delivery bridge from
// owning assembler details.
type tuiSIPReassemblyStage struct {
	cancel    context.CancelFunc
	assembler *pipeline.ReassemblyEngine
}

func newTUISIPReassemblyStage(tracker *CallTracker, aggregator *LocalCallAggregator) *tuiSIPReassemblyStage {
	ctx, cancel := context.WithCancel(context.Background())
	handler := NewTUISIPHandler(tracker, aggregator)
	factory := voip.NewSipStreamFactoryWithConfig(ctx, handler, *voip.GetConfig(), tracker.IsCallActive)
	assembler := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	stage := &tuiSIPReassemblyStage{cancel: cancel, assembler: assembler}
	go func() {
		defer handler.Close()
		if err := assembler.Run(ctx); err != nil {
			logger.Error("TUI TCP reassembly engine stopped", "error", err)
		}
	}()
	return stage
}

func (s *tuiSIPReassemblyStage) process(env *pipeline.PacketEnvelope) {
	if !IsVoIPModeEnabled() || env == nil || env.Packet() == nil {
		return
	}
	pkt := env.Packet()
	if pkt.Layer(layers.LayerTypeTCP) == nil || pkt.NetworkLayer() == nil {
		return
	}
	count := atomic.AddInt64(&bridgeStats.TCPPacketsToAssembler, 1)
	if count%100 == 1 {
		tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		logger.Debug("TCP packets fed to assembler", "total_count", count, "payload_len", len(tcp.Payload))
	}
	if err := s.assembler.Assemble(env); err != nil {
		logger.Error("Failed to assemble TUI TCP packet", "error", err)
	}
}

func (s *tuiSIPReassemblyStage) close() {
	s.cancel()
	if err := s.assembler.Close(); err != nil {
		logger.Error("Failed to close TUI TCP reassembly engine", "error", err)
	}
}
