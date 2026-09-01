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
	lastRateCheck   time.Time
	ratio           float64
	lastPacketCount int64
	selectionCredit float64
}

func newDisplaySamplingPolicy(preserveAll bool, now ...time.Time) *displaySamplingPolicy {
	started := time.Now()
	if len(now) > 0 {
		started = now[0]
	}
	return &displaySamplingPolicy{preserveAll: preserveAll, lastRateCheck: started, ratio: 1}
}

func (p *displaySamplingPolicy) shouldDisplay(env *pipeline.PacketEnvelope, packetCount int64, now time.Time) bool {
	if p.preserveAll || env.Source.Kind == pipeline.SourcePCAPReplay {
		return true
	}
	if elapsed := now.Sub(p.lastRateCheck); elapsed >= constants.TUITickInterval {
		packetDelta := packetCount - p.lastPacketCount
		p.ratio = samplingRatio(packetDelta, elapsed)
		p.lastRateCheck = now
		p.lastPacketCount = packetCount
		atomic.StoreInt64(&bridgeStats.SamplingRatio, int64(p.ratio*1000))
	}
	if isSIPPacket(env.Packet()) {
		return true
	}
	if p.ratio >= 1 {
		return true
	}
	p.selectionCredit += p.ratio
	if p.selectionCredit < 1 {
		return false
	}
	p.selectionCredit--
	return true
}

// samplingRatio defines a detail-display budget independent of ingress. Exact
// ingress statistics are collected before this policy runs. The minimum keeps a
// small diagnostic sample visible even during extreme overload.
func samplingRatio(packetDelta int64, elapsed time.Duration) float64 {
	if packetDelta <= 0 || elapsed <= 0 {
		return 1
	}
	const detailDisplayBudgetPPS = 1000.0
	rate := float64(packetDelta) / elapsed.Seconds()
	ratio := detailDisplayBudgetPPS / rate
	if ratio > 1 {
		ratio = 1
	} else if ratio < 0.01 {
		ratio = 0.01
	}
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
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stage.publishStats()
			}
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
	s.publishStats()
}

func (s *tuiSIPReassemblyStage) publishStats() {
	snapshot := s.assembler.LimitStats()
	atomic.StoreInt64(&bridgeStats.ReassemblyNormalDiscontinuities, int64(snapshot.NormalDiscontinuities))               // #nosec G115 -- diagnostic counters
	atomic.StoreInt64(&bridgeStats.ReassemblyNormalMissingBytes, int64(snapshot.NormalMissingBytes))                     // #nosec G115 -- diagnostic counters
	atomic.StoreInt64(&bridgeStats.ReassemblyExplicitFlushDiscontinuities, int64(snapshot.ExplicitFlushDiscontinuities)) // #nosec G115 -- diagnostic counters
	atomic.StoreInt64(&bridgeStats.ReassemblyExplicitFlushMissingBytes, int64(snapshot.ExplicitFlushMissingBytes))       // #nosec G115 -- diagnostic counters
}

func (s *tuiSIPReassemblyStage) close() {
	s.cancel()
	if err := s.assembler.Close(); err != nil {
		logger.Error("Failed to close TUI TCP reassembly engine", "error", err)
	}
	s.publishStats()
}
