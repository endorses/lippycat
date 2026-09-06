//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	tlspkg "github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
)

// OfflineAnalysisConfig is captured by the model before starting a worker.
// Workers never read UI settings or mutate the active capture's global state.
type OfflineAnalysisConfig struct {
	// locatorOrdering selects the migration path internally until its production gate.
	locatorOrdering bool
	BackingPolicy   offline.BackingPolicy
	Inputs          []string
	BPFFilter       string
	VoIP            bool
	TLSKeylog       string
	EventCapacity   int
	MaxCalls        int
	ESP             capture.OfflineESPConfig
	Analysis        LocalEventAnalysisOptions
	SIPConfig       voip.Config
}

type offlineIndexedSession struct {
	export       *offlineExportState
	browser      *offlineBrowser
	filter       *offlineFilterOwner
	related      *offlineRelatedOwner
	Dataset      offline.Dataset
	sortCleanup  io.Closer        // Per-open scratch cleanup retained only after removal failure.
	builder      *offline.Builder // Retained only until publication or successful cleanup.
	EventStore   *store.EventStore
	Calls        []types.CallInfo
	Tracker      *CallTracker
	TLSDecryptor *TLSDecryptor
}

func (s *offlineIndexedSession) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	if s.export != nil {
		s.export.cancel()
		<-s.export.done
	}
	if s.filter != nil {
		closeErr = errors.Join(closeErr, s.filter.close())
	}
	if s.related != nil {
		s.related.close()
	}
	if s.browser != nil {
		closeErr = errors.Join(closeErr, s.browser.close())
	}
	if s.TLSDecryptor != nil {
		s.TLSDecryptor.Stop()
	}
	if s.sortCleanup != nil {
		if err := s.sortCleanup.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		} else {
			s.sortCleanup = nil
		}
	}
	if s.builder != nil {
		if err := s.builder.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		} else {
			s.builder = nil
		}
	}
	if s.Dataset != nil {
		return errors.Join(closeErr, s.Dataset.Close())
	}
	return closeErr
}

// Conversion has explicit flow ownership: live callers retain their existing
// caches, while every index worker gets separate bounded caches.
type sipFlowState interface {
	markTCP(string)
	markUDP(string)
	isTCP(string) bool
	isUDP(string) bool
}
type liveSIPFlows struct{}

func (liveSIPFlows) markTCP(k string)    { markTCPSIPFlow(k) }
func (liveSIPFlows) markUDP(k string)    { markUDPSIPFlow(k) }
func (liveSIPFlows) isTCP(k string) bool { return isTCPSIPFlow(k) }
func (liveSIPFlows) isUDP(k string) bool { return isUDPSIPFlow(k) }

type offlineSIPFlows struct {
	mu       sync.Mutex
	tcp, udp map[string]time.Time
	now      time.Time
}

func newOfflineSIPFlows() *offlineSIPFlows {
	return &offlineSIPFlows{tcp: make(map[string]time.Time), udp: make(map[string]time.Time)}
}
func (f *offlineSIPFlows) mark(m map[string]time.Time, k string) {
	if len(m) >= tcpSIPFlowCacheMaxSize {
		var oldest string
		var ts time.Time
		for key, t := range m {
			if oldest == "" || t.Before(ts) {
				oldest, ts = key, t
			}
		}
		delete(m, oldest)
	}
	m[k] = f.now
}
func (f *offlineSIPFlows) markTCP(k string) { f.mu.Lock(); defer f.mu.Unlock(); f.mark(f.tcp, k) }
func (f *offlineSIPFlows) markUDP(k string) { f.mu.Lock(); defer f.mu.Unlock(); f.mark(f.udp, k) }
func (f *offlineSIPFlows) has(m map[string]time.Time, k string) bool {
	ts, ok := m[k]
	if ok && f.now.Sub(ts) > tcpSIPFlowCacheMaxAge {
		delete(m, k)
		return false
	}
	return ok
}
func (f *offlineSIPFlows) isTCP(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.has(f.tcp, k)
}
func (f *offlineSIPFlows) isUDP(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.has(f.udp, k)
}

// indexOfflineDataset owns and joins all reader/analyzer resources. Only a fully
// drained, flushed session transfers to the model. Packet records bypass the
// presentation queues and contribute to storage statistics exactly once.
func indexOfflineDataset(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
	return indexOfflineDatasetObserved(ctx, storage, generation, cfg, report, nil)
}

// indexOfflineDatasetObserved exposes phase boundaries to the acceptance harness.
// The optional observer runs synchronously and must not call storage methods.
func indexOfflineDatasetObserved(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration)) (result *offlineIndexedSession, err error) {
	phase, phaseStart := "setup", time.Now()
	mark := func(next string) {
		if next == phase {
			return
		}
		if observe != nil {
			observe(phase, time.Since(phaseStart))
		}
		phase, phaseStart = next, time.Now()
	}
	defer func() { mark("finished") }()

	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.BackingPolicy, err = offline.ParseBackingPolicy(string(cfg.BackingPolicy)); err != nil {
		return nil, err
	}
	ctx = capture.WithOfflineESPConfig(ctx, cfg.ESP)
	ctx = capture.WithOfflineBackingPolicy(ctx, cfg.BackingPolicy)
	sources := make([]offline.SourcePosition, len(cfg.Inputs))
	for i, path := range cfg.Inputs {
		sources[i] = offline.SourcePosition{ArgumentIndex: uint32(i), Path: path}
	}
	builder, err := storage.NewBuilder(generation, sources)
	if err != nil {
		return nil, err
	}
	session := &offlineIndexedSession{builder: builder, EventStore: store.NewEventStore(cfg.EventCapacity), Tracker: NewCallTrackerWithCapacity(cfg.MaxCalls)}
	defer func() {
		if err != nil {
			result = nil
			if cleanupErr := session.Close(); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
				// The controller must own failed cleanup so cancellation,
				// reopen, or shutdown can retry removal and release its budget.
				result = session
			}
		}
	}()
	started := time.Now()
	last := time.Time{}
	progress := offline.Progress{Token: offline.Token{Dataset: generation}, State: offline.Reading, Sources: uint32(len(cfg.Inputs))}
	publish := func(force bool) {
		if report != nil && (force || time.Since(last) >= 100*time.Millisecond) {
			progress.Elapsed = time.Since(started)
			progress.DiskBytes = storage.Resources().DiskBytes
			report(progress)
			last = time.Now()
		}
	}
	publish(true)
	sortProgress := func(p capture.OfflineSortProgress) {
		switch p.Phase {
		case "Reading":
			progress.State = offline.Reading
		case "Sorting":
			mark("ordering")
			progress.State = offline.Sorting
		case "Replaying":
			mark("analysis_and_storage")
			progress.State = offline.Indexing
		}
		progress.LogicalPackets, progress.ScannedBytes = p.LogicalPackets, p.BytesScanned
		if progress.State == offline.Indexing {
			progress.TotalPackets = p.LogicalPackets
			progress.LogicalPackets, progress.ScannedBytes = 0, 0
		}
		publish(true)
	}
	var prepared *capture.OfflineLocatorStream
	if cfg.locatorOrdering {
		mark("scan")
		var prepareErr error
		openErr := capture.StartOfflineSnifferOrdered(cfg.Inputs, cfg.BPFFilter, func(devices []pcaptypes.PcapInterface, filter string) {
			prepared, prepareErr = capture.PrepareOfflineLocatorStream(ctx, devices, filter, storage, sortProgress)
			if prepared != nil {
				session.sortCleanup = prepared
			}
		})
		if err = errors.Join(openErr, prepareErr); err != nil {
			return nil, err
		}
	}
	if cfg.TLSKeylog != "" {
		session.TLSDecryptor, err = newOfflineTLSDecryptor(ctx, cfg.TLSKeylog)
		if err != nil {
			return nil, fmt.Errorf("offline TLS keys: %w", err)
		}
	}
	agg := NewLocalCallAggregator(nil, session.Tracker)
	agg.silent = true
	if cfg.MaxCalls > 0 {
		agg.aggregator = voip.NewCallAggregatorWithCapacity(cfg.MaxCalls)
	}
	flows := newOfflineSIPFlows()
	protocols := detector.NewWithDefaultSignatures()
	defer protocols.Shutdown()
	tlsParser := tlspkg.NewParser()
	analysis := cfg.Analysis
	if analysis.NodeID == "" {
		analysis.NodeID = "watch-local"
	}
	if analysis.AnalysisProfile == "" {
		analysis.AnalysisProfile = "watch-eventanalysis-v1"
	}
	mark("identity")
	if analysis.InputIdentity == "" {
		if prepared != nil {
			identities := prepared.Identities()
			digests := make([][32]byte, len(identities))
			for i, identity := range identities {
				digests[i] = identity.Digest
			}
			analysis.InputIdentity = events.OfflineInputIdentityFromDigests(digests)
		} else {
			analysis.InputIdentity, err = events.OfflineInputIdentityContext(ctx, cfg.Inputs)
		}
		if err != nil {
			return nil, err
		}
	}
	mark("analysis_setup")
	producer, err := events.NewOfflineProducer(analysis.NodeID, events.OfflineSession{InputIdentity: analysis.InputIdentity, AnalysisProfile: analysis.AnalysisProfile, SourceOrdering: append([]string(nil), cfg.Inputs...)})
	if err != nil {
		return nil, err
	}
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 1024, SinkQueueSize: 1024, DropPolicy: events.DropNew, Producer: producer})
	if err != nil {
		return nil, err
	}
	sink := newLocalEventSink(256, true, func(batch types.EventBatch) {
		session.EventStore.AddBatch(batch.Events)
		for _, loss := range batch.Losses {
			session.EventStore.RecordTransportLoss(loss.Kind.String(), eventLossCount(loss))
		}
		if batch.CompatibilityOmissions > 0 {
			session.EventStore.RecordTransportLoss("compatibility_omission", batch.CompatibilityOmissions)
		}
	})
	if err = dispatcher.Register(sink); err != nil {
		return nil, errors.Join(err, sink.Close(context.Background()))
	}
	runtime, err := eventanalysis.New(eventanalysis.Config{Dispatcher: dispatcher, LosslessDelivery: true, LiveExpiry: false})
	if err != nil {
		return nil, errors.Join(err, dispatcher.Close(context.Background()))
	}
	if err = dispatcher.Start(ctx); err != nil {
		runtime.Close()
		return nil, errors.Join(err, dispatcher.Close(context.Background()))
	}
	defer func() { runtime.Close(); err = errors.Join(err, dispatcher.Close(context.Background())) }()
	var indexedPackets uint64
	var assembler *pipeline.ReassemblyEngine
	var handler *TUISIPHandler
	var sipFactory *offlineSIPFactory
	reassemblyConfig := pipeline.DefaultReassemblyConfig()
	var nextSIPFlush time.Time
	if cfg.VoIP {
		handler = NewTUISIPHandler(session.Tracker, agg)
		handler.markFlow = flows.markTCP
		sipFactory = newOfflineSIPFactory(handler, cfg.SIPConfig)
		sipFactory.OnEvent = func(id offline.PacketID, event sharedsip.Event) error {
			if uint64(id) < indexedPackets {
				sipFactory.LastEvent = nil
				return builder.UpdateDetail(ctx, id, func(detail *offline.Detail) error { applyOfflineSIPEvent(&detail.Packet, event); return nil })
			}
			return nil
		}
		assembler = pipeline.NewReassemblyEngine(sipFactory, reassemblyConfig)
		defer func() { err = errors.Join(err, assembler.Close()); handler.Close() }()
	}
	consume := func(readCtx context.Context, ch <-chan capture.PacketInfo) error {
		for info := range ch {
			if err := readCtx.Err(); err != nil {
				return err
			}
			env := captureadapter.FromPacketInfo(info, pipeline.SourcePCAPReplay)
			flows.mu.Lock()
			flows.now = env.CaptureTime
			flows.mu.Unlock()
			if sipFactory != nil {
				sipFactory.LastEvent = nil
				sipFactory.CurrentID = offline.PacketID(indexedPackets)
				if nextSIPFlush.IsZero() || !env.CaptureTime.Before(nextSIPFlush) {
					// Expiry may release old queued messages. Their completion
					// belongs to the original packet, not the incoming packet.
					sipFactory.Flushing = true
					flushErr := assembler.FlushOlderThan(env.CaptureTime.Add(-reassemblyConfig.IdleTimeout))
					sipFactory.Flushing = false
					if err := errors.Join(flushErr, sipFactory.Err()); err != nil {
						return err
					}
					nextSIPFlush = env.CaptureTime.Add(reassemblyConfig.FlushInterval)
				}
			}
			if assembler != nil && info.Packet.NetworkLayer() != nil && info.Packet.Layer(layers.LayerTypeTCP) != nil {
				if err := assembler.AssembleWithContext(env, offlineSIPContext(info.Packet.Metadata().CaptureInfo, sipFactory.CurrentID)); err != nil {
					return err
				}
			}
			if sipFactory != nil {
				if err := sipFactory.Err(); err != nil {
					return err
				}
			}
			source := eventanalysis.Source{NodeID: analysis.NodeID, CaptureSource: "pcap", InputFile: info.SourcePath, InterfaceIndex: info.SourceInterfaceID, CaptureScope: analysis.CaptureScope, Partial: analysis.Partial}
			// The local event adapter currently enriches IP TCP/UDP flows
			// only. Other logical packets still belong in the dataset even
			// when they cannot produce a normalized connection event.
			if offlinePacketSupportsEventAnalysis(info) {
				if err := runtime.ObservePacket(source, info); err != nil {
					return err
				}
			}
			// LosslessDelivery drains before every event admission. Packets
			// without events need no barrier; Close drains the final event
			// and EOF output before the session can be published.
			packet := convertEnvelopeWithState(env, session.Tracker, protocols, flows)
			if sipFactory != nil && sipFactory.LastEvent != nil {
				applyOfflineSIPEvent(&packet, *sipFactory.LastEvent)
			}
			if packet.Protocol == "DNS" {
				packet.DNSData = parseDNSFromRawData(packet.RawData, packet.LinkType)
			}
			if packet.Protocol == "HTTP" {
				packet.HTTPData = parseHTTPFromRawData(packet.RawData, packet.LinkType)
			}
			packet.TLSData = tlsParser.Parse(info.Packet)
			if tcp, ok := info.Packet.TransportLayer().(*layers.TCP); session.TLSDecryptor != nil && ok {
				if packet.TLSData != nil {
					session.TLSDecryptor.processTLSHandshakePayload(packet.SrcIP, packet.DstIP, packet.SrcPort, packet.DstPort, tcp.LayerPayload(), !packet.TLSData.IsServer)
				} else {
					session.TLSDecryptor.processApplicationPayload(packet.SrcIP, packet.DstIP, packet.SrcPort, packet.DstPort, tcp.LayerPayload())
				}
				if err := session.TLSDecryptor.sessionManager.Err(); err != nil {
					return fmt.Errorf("offline TLS analysis: %w", err)
				}
			}
			if sipFactory == nil || sipFactory.LastEvent == nil {
				agg.ProcessPacket(&packet)
			}
			meta := info.Packet.Metadata()
			detail := offline.Detail{Source: offline.SourcePosition{ArgumentIndex: info.SourceIndex, Path: info.SourcePath, InterfaceID: info.SourceInterfaceID, Sequence: info.SourceSequence}, CapturedLength: uint32(meta.CaptureLength), OriginalLength: uint32(meta.Length), Packet: packet}
			if err := builder.Append(readCtx, detail); err != nil {
				return err
			}
			indexedPackets++
			progress.LogicalPackets++
			progress.ScannedBytes += uint64(meta.CaptureLength)
			publish(false)
		}
		return nil
	}
	if prepared != nil {
		err = prepared.Replay(ctx, consume)
		if closeErr := prepared.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		} else {
			session.sortCleanup = nil
		}
	} else {
		var readErr error
		mark("scan")
		openErr := capture.StartOfflineSnifferOrdered(cfg.Inputs, cfg.BPFFilter, func(devices []pcaptypes.PcapInterface, filter string) {
			session.sortCleanup, readErr = capture.RunOfflineSortedStream(ctx, devices, filter, storage, sortProgress, consume)
		})
		err = errors.Join(openErr, readErr)
	}
	if err != nil {
		return nil, err
	}
	mark("finalization")
	if assembler != nil {
		sipFactory.Flushing = true
		if err = assembler.Close(); err != nil {
			return nil, err
		}
		handler.Close()
	}
	progress.State = offline.Finalizing
	publish(true)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	runtime.EOF()
	runtime.Close()
	if err = dispatcher.Close(ctx); err != nil {
		return nil, err
	}
	calls := agg.GetCalls()
	session.Calls = make([]types.CallInfo, 0, len(calls))
	for _, call := range calls {
		session.Calls = append(session.Calls, agg.convertToTUICall(call))
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if session.TLSDecryptor != nil {
		session.TLSDecryptor.Stop()
	}
	session.Dataset, err = builder.Finish(ctx)
	if err != nil {
		return nil, err
	}
	session.builder = nil
	progress.State = offline.Ready
	publish(true)
	return session, nil
}

func offlinePacketSupportsEventAnalysis(info capture.PacketInfo) bool {
	switch info.Packet.NetworkLayer().(type) {
	case *layers.IPv4, *layers.IPv6:
	default:
		return false
	}
	switch info.Packet.TransportLayer().(type) {
	case *layers.TCP, *layers.UDP:
		return true
	default:
		return false
	}
}

// Completed message metadata is immutable once applied, whether completion was
// observed in the packet loop or released from a bounded TCP gap at EOF.
func applyOfflineSIPEvent(packet *types.PacketDisplay, event sharedsip.Event) {
	packet.Protocol = "SIP"
	packet.Info = event.StartLine
	packet.VoIPData = &types.VoIPMetadata{CallID: event.CallID, Method: event.Method, Status: event.ResponseCode, From: event.From, To: event.To, FromTag: event.FromTag, ToTag: event.ToTag, User: event.FromUser, Headers: cloneStringMap(event.Headers)}
}
