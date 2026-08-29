//go:build cli || all

package voip

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket/layers"
)

// ProcessorWorkerStats describes bounded flow-shard queue pressure.
type ProcessorWorkerStats struct {
	QueueDepth    int
	HighWaterMark uint64
	Drops         uint64
}

type processorWorkerCounters struct {
	highWater atomic.Uint64
	drops     atomic.Uint64
	queue     chan *pipeline.PacketEnvelope
}

var currentProcessorWorkers atomic.Pointer[[]*processorWorkerCounters]

// ProcessorWorkersStats returns a point-in-time snapshot for observability.
func ProcessorWorkersStats() []ProcessorWorkerStats {
	workers := currentProcessorWorkers.Load()
	if workers == nil {
		return nil
	}
	result := make([]ProcessorWorkerStats, len(*workers))
	for i, worker := range *workers {
		result[i] = ProcessorWorkerStats{QueueDepth: len(worker.queue), HighWaterMark: worker.highWater.Load(), Drops: worker.drops.Load()}
	}
	return result
}

func StartVoipSniffer(devices []pcaptypes.PcapInterface, filter string) {
	startVoipSniffer(devices, filter, false)
}

func startVoipSniffer(devices []pcaptypes.PcapInterface, filter string, isOffline bool) {
	ctx := context.Background()
	config := GetConfig()
	var callOutput CallOutput = NoopCallOutput{}
	if config.WriteVoIP {
		callOutput = NewSessionOutputManager(config)
	}
	tracker := NewCallTrackerWithOutput(config, callOutput)
	var packetOutputs *pipeline.PacketFanout
	defer func() {
		if err := callOutput.Shutdown(); err != nil {
			logger.Error("Failed to shut down VoIP session output", "error", err)
		}
	}()
	defer tracker.Shutdown()
	logger.InfoContext(ctx, "Starting VoIP sniffer",
		"device_count", len(devices),
		"filter", filter)

	// Initialize virtual interface FIRST if enabled (before processing any packets)
	// This allows early permission check and avoids wasting time processing packets
	if config.VirtualInterface {
		vifName := config.VIFName
		if vifName == "" {
			vifName = "lc0"
		}

		cfg := vinterface.DefaultConfig()
		cfg.Name = vifName

		// Read interface type from config (default: tap)
		if vifType := config.VIFType; vifType != "" {
			cfg.Type = vifType
		}

		// Read buffer size from config (default: 4096)
		if bufferSize := config.VIFBufferSize; bufferSize > 0 {
			cfg.BufferSize = bufferSize
		}

		// Read network namespace from config (default: empty)
		if netNS := config.VIFNetNS; netNS != "" {
			cfg.NetNS = netNS
		}

		// Read privilege dropping user from config (default: empty)
		if dropPrivUser := config.VIFDropPrivilegesUser; dropPrivUser != "" {
			cfg.DropPrivilegesUser = dropPrivUser
		}

		var err error
		vifMgr, err := vinterface.NewManager(cfg)
		if err != nil {
			// Provide helpful error message for common errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", vifName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else if errors.Is(err, vinterface.ErrInterfaceExists) {
				logger.Error("Virtual interface already exists",
					"error", err,
					"interface_name", vifName,
					"solution", "Delete existing interface or choose a different name with --vif-name")
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", vifName)
			}
			logger.Warn("Continuing without virtual interface")
		} else {
			err = vifMgr.Start()
			if err != nil {
				// Provide helpful error message for common errors
				if errors.Is(err, vinterface.ErrPermissionDenied) {
					logger.Error("Virtual interface requires elevated privileges",
						"error", err,
						"interface_name", vifName,
						"solution", "Run with sudo or add CAP_NET_ADMIN capability")
				} else if errors.Is(err, vinterface.ErrInterfaceExists) {
					logger.Error("Virtual interface already exists",
						"error", err,
						"interface_name", vifName,
						"solution", "Delete existing interface or choose a different name with --vif-name")
				} else {
					logger.Error("Failed to start virtual interface",
						"error", err,
						"interface_name", vifName)
				}
				logger.Warn("Continuing without virtual interface")
				vifMgr = nil
			}
		}

		if vifMgr != nil {
			logger.Info("Virtual interface started successfully",
				"interface_name", vifMgr.Name())

			// Initialize timing replayer for virtual interface
			replayTiming := config.VIFReplayTiming
			vifSink := &virtualInterfacePacketSink{manager: vifMgr, timing: vinterface.NewTimingReplayer(replayTiming)}
			packetOutputs, err = pipeline.NewPacketFanout(pipeline.SinkRegistration{Name: "virtual-interface", Sink: vifSink})
			if err != nil {
				logger.Error("Failed to compose VoIP packet sinks", "error", err)
				if shutdownErr := vifMgr.Shutdown(); shutdownErr != nil {
					logger.Error("Failed to clean up virtual interface", "error", shutdownErr)
				}
				vifMgr = nil
			}

			// Wait for external tools (tcpdump, Wireshark) to attach
			startupDelay := config.VIFStartupDelay
			if startupDelay > 0 {
				logger.Info("Waiting for monitoring tools to attach...",
					"delay", startupDelay)
				time.Sleep(startupDelay)
			}
			logger.Info("Starting packet injection")
		}

		// Ensure cleanup on exit
		defer func() {
			if vifMgr != nil {
				stats := vifMgr.Stats()
				logger.Info("Virtual interface statistics",
					"packets_injected", stats.PacketsInjected,
					"packets_dropped", stats.PacketsDropped,
					"injection_errors", stats.InjectionErrors,
					"conversion_errors", stats.ConversionErrors)

				if packetOutputs != nil {
					if err := packetOutputs.Close(context.Background()); err != nil {
						logger.Error("Error shutting down virtual interface", "error", err)
					}
				} else {
					if err := vifMgr.Shutdown(); err != nil {
						logger.Error("Error shutting down virtual interface", "error", err)
					}
				}
				if packetOutputs != nil {
					logger.Info("Virtual interface shutdown successfully")
				}
			}
		}()
	}

	bufferManager := NewBufferManager(5*time.Second, 200)
	defer bufferManager.Close()
	logger.Info("Initialized VoIP buffer manager", "max_age", "5s", "max_size", 200)

	// Create handler for local file writing
	handler := newLocalFileHandlerWithOutputs(tracker, bufferManager, packetOutputs)
	streamFactory := NewSipStreamFactoryWithConfig(ctx, handler, *tracker.config, tracker.IsCallActive)
	// VoIP owns its (connection-aware reassembly) assembler internally rather
	// than threading it through the shared capture-layer signatures, which stay
	// typed to the legacy *tcpassembly.Assembler for the other protocols.
	assembler := pipeline.NewReassemblyEngine(streamFactory, pipeline.DefaultReassemblyConfig())
	defer func() {
		if err := assembler.Close(); err != nil {
			logger.Error("Failed to close VoIP reassembly engine", "error", err)
		}
	}()
	go func() {
		if err := assembler.Run(ctx); err != nil {
			logger.Error("VoIP reassembly engine stopped", "error", err)
		}
	}()
	kind := pipeline.SourceLiveCapture
	if isOffline {
		kind = pipeline.SourcePCAPReplay
	}
	processor := func(ch <-chan capture.PacketInfo) {
		envelopes := make(chan *pipeline.PacketEnvelope)
		go func() {
			defer close(envelopes)
			if err := captureadapter.Stream(ctx, ch, envelopes, kind); err != nil {
				logger.Error("VoIP ingress normalization stopped", "error", err)
			}
		}()
		startProcessorWithBufferAndOutputs(tracker, bufferManager, envelopes, assembler, isOffline, packetOutputs)
	}

	if isOffline {
		// For offline mode, run until PCAP is fully read
		capture.RunOfflineOrdered(devices, filter, processor)
	} else {
		// For live mode, run with signal handler (waits for Ctrl+C)
		capture.RunWithSignalHandler(devices, filter, processor)
	}
}

func StartLiveVoipSniffer(interfaces, filter string) {
	capture.StartLiveSniffer(interfaces, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startVoipSniffer(devices, filter, false)
	})
}

func StartOfflineVoipSniffer(readFiles []string, filter string) {
	capture.StartOfflineSnifferOrdered(readFiles, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startVoipSniffer(devices, filter, true)
	})
}

func startProcessor(tracker *CallTracker, ch <-chan *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offlineMode ...bool) {
	bufferManager := globalBufferMgr
	if bufferManager == nil {
		bufferManager = NewBufferManager(5*time.Second, 200)
		defer bufferManager.Close()
	}
	startProcessorWithBuffer(tracker, bufferManager, ch, assembler, offlineMode...)
}

func startProcessorWithBuffer(tracker *CallTracker, bufferManager *BufferManager, ch <-chan *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offlineMode ...bool) {
	offline := len(offlineMode) > 0 && offlineMode[0]
	startProcessorWithBufferAndOutputs(tracker, bufferManager, ch, assembler, offline, nil)
}

func startProcessorWithBufferAndOutputs(tracker *CallTracker, bufferManager *BufferManager, ch <-chan *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offline bool, outputs *pipeline.PacketFanout) {

	// Note: Virtual interface is now initialized in StartVoipSniffer() before packet processing begins
	// This allows early permission checking and avoids wasting time if permissions are insufficient

	numWorkers := getProcessorWorkerCount(tracker.config)
	if offline || numWorkers <= 1 {
		// Single-threaded path (original behaviour / offline-ordered mode).
		for pkt := range ch {
			processOnePacketWithOutputs(tracker, bufferManager, pkt, assembler, offline, outputs)
		}
	} else {
		// Flow-sharded worker pool. Each flow (both directions) is pinned to one
		// worker via a symmetric hash, so RTP-stream ordering and per-call state
		// stay consistent while distinct calls parallelise across cores. All shared
		// state touched by the handlers is mutex-protected: CallTracker.callMap and
		// portToCallID (tracker.mu), per-call PCAP writers (sipWriterMu/rtpWriterMu),
		// the buffer manager (bm.mu) and the async writer. TCP is pinned to worker 0
		// because the reassembly assembler is not concurrency-safe (TCP/SIP volume is
		// negligible here).
		logger.Info("VoIP processor starting flow-sharded workers", "workers", numWorkers)
		workerBuf := getProcessorWorkerBuffer(tracker.config)
		workers := make([]chan *pipeline.PacketEnvelope, numWorkers)
		counters := make([]*processorWorkerCounters, numWorkers)
		var lastOverloadLog atomic.Int64
		var wg sync.WaitGroup
		for i := range workers {
			workers[i] = make(chan *pipeline.PacketEnvelope, workerBuf)
			counters[i] = &processorWorkerCounters{queue: workers[i]}
			wg.Add(1)
			go func(in <-chan *pipeline.PacketEnvelope) {
				defer wg.Done()
				for pkt := range in {
					processOnePacketWithOutputs(tracker, bufferManager, pkt, assembler, offline, outputs)
				}
			}(workers[i])
		}
		currentProcessorWorkers.Store(&counters)
		defer currentProcessorWorkers.Store(nil)

		for pkt := range ch {
			if pkt == nil {
				continue
			}
			packet := pkt.Packet()
			netLayer := packet.NetworkLayer()
			transLayer := packet.TransportLayer()
			if netLayer == nil || transLayer == nil {
				continue
			}
			idx := 0
			if _, isTCP := transLayer.(*layers.TCP); !isTCP {
				// FastHash() (uint64) is direction-independent, so both legs of a
				// flow land on the same worker.
				h := netLayer.NetworkFlow().FastHash() ^ transLayer.TransportFlow().FastHash()
				idx = int(h % uint64(numWorkers))
			}
			select {
			case workers[idx] <- pkt:
				depth := uint64(len(workers[idx]))
				for old := counters[idx].highWater.Load(); depth > old && !counters[idx].highWater.CompareAndSwap(old, depth); old = counters[idx].highWater.Load() {
				}
			default:
				drops := counters[idx].drops.Add(1)
				now := time.Now().UnixNano()
				last := lastOverloadLog.Load()
				if now-last >= int64(time.Second) && lastOverloadLog.CompareAndSwap(last, now) {
					logger.Warn("VoIP processor worker queue full; dropping packet to preserve global progress", "worker", idx, "queue_capacity", workerBuf, "worker_drops", drops)
				}
			}
		}
		for _, w := range workers {
			close(w)
		}
		wg.Wait()
	}

	logger.Info("VoIP processor finished")
}

func startProcessorWithTracker(tracker *CallTracker, ch <-chan *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offlineMode ...bool) {
	startProcessor(tracker, ch, assembler, offlineMode...)
}

// processOnePacket dispatches a single packet to the appropriate transport handler.
// Safe to call from multiple worker goroutines concurrently as long as packets of
// the same flow are delivered to the same worker (see startProcessor) and shared
// call/registry/writer state remains mutex-protected.
func processOnePacket(tracker *CallTracker, bufferManager *BufferManager, env *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offline bool) {
	processOnePacketWithOutputs(tracker, bufferManager, env, assembler, offline, nil)
}

func processOnePacketWithOutputs(tracker *CallTracker, bufferManager *BufferManager, env *pipeline.PacketEnvelope, assembler tcpPacketAssembler, offline bool, outputs *pipeline.PacketFanout) {
	if env == nil {
		return
	}
	packet := env.Packet()
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return
	}
	pkt := captureadapter.ToPacketInfo(env)
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		handleTcpPacketsWithConfig(pkt, layer, assembler, tracker.config, offline)
	case *layers.UDP:
		handleUdpPacketsWithManagerAndOutputs(tracker, pkt, layer, bufferManager, outputs)
	}
}

// getProcessorWorkerCount returns the number of flow-sharded VoIP processing
// workers. Configurable via voip.processor_workers; defaults to NumCPU-2 (leaving
// headroom for the capture/decode goroutine and async writers), minimum 1.
// A value of 1 selects the original single-threaded path.
func getProcessorWorkerCount(configs ...*Config) int {
	var config *Config
	if len(configs) > 0 {
		config = configs[0]
	}
	if config != nil && config.ProcessorWorkers >= 1 {
		return config.ProcessorWorkers
	}
	n := runtime.NumCPU() - 2
	if n < 1 {
		n = 1
	}
	return n
}

// getProcessorWorkerBuffer returns the per-worker input channel depth.
// Configurable via voip.processor_worker_buffer; defaults to 8192.
func getProcessorWorkerBuffer(configs ...*Config) int {
	var config *Config
	if len(configs) > 0 {
		config = configs[0]
	}
	if config != nil && config.ProcessorWorkerBuffer > 0 {
		return config.ProcessorWorkerBuffer
	}
	return 8192
}
