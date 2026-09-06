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
	"github.com/endorses/lippycat/internal/pkg/dns"
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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// OfflineAnalysisConfig is captured by the model before starting a worker.
// Workers never read UI settings or mutate the active capture's global state.
type OfflineAnalysisConfig struct {
	BackingPolicy offline.BackingPolicy
	Inputs        []string
	BPFFilter     string
	VoIP          bool
	TLSKeylog     string
	EventCapacity int
	MaxCalls      int
	ESP           capture.OfflineESPConfig
	Analysis      LocalEventAnalysisOptions
	SIPConfig     voip.Config
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
	return indexOfflineDatasetBackend(ctx, storage, generation, cfg, report, nil, true, true)
}

// indexOfflineDatasetBackend retains the legacy storage builder as a differential
// test oracle. Production callers select one fixed backend in indexOfflineDataset;
// backend selection is never part of the frozen configuration or user settings.
func indexOfflineDatasetBackend(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration), locatorOrdering, compactStorage bool) (*offlineIndexedSession, error) {
	return indexOfflineDatasetBackendWithWorkers(ctx, storage, generation, cfg, report, observe, locatorOrdering, compactStorage, true, true)
}

func indexOfflineDatasetBackendWithAsync(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration), locatorOrdering, compactStorage, asynchronous bool) (result *offlineIndexedSession, err error) {
	return indexOfflineDatasetBackendWithWorkers(ctx, storage, generation, cfg, report, observe, locatorOrdering, compactStorage, asynchronous, false)
}

func indexOfflineDatasetBackendWithWorkers(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), observe func(string, time.Duration), locatorOrdering, compactStorage, asynchronous, asynchronousAnalysis bool) (result *offlineIndexedSession, err error) {
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
	var builder *offline.Builder
	if !compactStorage {
		builder, err = storage.NewBuilder(generation, sources)
		if err != nil {
			return nil, err
		}
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
	if locatorOrdering || compactStorage {
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
	if compactStorage {
		builder, err = storage.NewCompactBuilder(generation, sources, prepared.Backings(), materializeOfflinePacket)
		if err != nil {
			return nil, err
		}
		session.builder = builder
		if err = prepared.TransferBackings(); err != nil {
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
	var analysisWorker *offlineAnalysisWorker
	workerContext := ctx
	if compactStorage && asynchronousAnalysis {
		analysisWorker, err = newOfflineAnalysisWorker(ctx, storage, runtime.ObservePacket)
		if err != nil {
			return nil, err
		}
		if analysisWorker != nil {
			defer func() { err = errors.Join(err, analysisWorker.Close()) }()
			workerContext = analysisWorker.Context()
		}
	}
	var asyncWriter *offline.AsyncCompactWriter
	if compactStorage && asynchronous {
		asyncWriter, err = offline.NewAsyncCompactWriter(workerContext, storage, builder)
		if err != nil {
			return nil, err
		}
		if asyncWriter != nil {
			defer func() { err = errors.Join(err, asyncWriter.Close()) }()
		}
	}
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
				if compactStorage {
					if asyncWriter != nil {
						if err := asyncWriter.Drain(); err != nil {
							return err
						}
					}
					var packet types.PacketDisplay
					applyOfflineSIPEvent(&packet, event)
					return builder.AmendVoIP(ctx, id, packet.Protocol, packet.Info, packet.VoIPData)
				}
				return builder.UpdateDetail(ctx, id, func(detail *offline.Detail) error { applyOfflineSIPEvent(&detail.Packet, event); return nil })
			}
			return nil
		}
		assembler = pipeline.NewReassemblyEngine(sipFactory, reassemblyConfig)
		defer func() { err = errors.Join(err, assembler.Close()); handler.Close() }()
	}
	var replayEnvelope pipeline.PacketEnvelope
	consumeOne := func(readCtx context.Context, info capture.PacketInfo) error {
		if err := readCtx.Err(); err != nil {
			return err
		}
		env := &replayEnvelope
		captureadapter.ResetFromPacketInfo(env, info, pipeline.SourcePCAPReplay)
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
			observePacket := runtime.ObservePacket
			if analysisWorker != nil {
				observePacket = analysisWorker.Submit
			}
			if err := observePacket(source, info); err != nil {
				return err
			}
		}
		// LosslessDelivery waits only when bounded event queues fill.
		// Close drains all admitted events and EOF output before the
		// completed session can be published.
		// Compact append validates bytes synchronously and stores provenance;
		// neither it nor call aggregation retains this raw packet buffer.
		packet := convertEnvelopeWithRawOwnership(env, session.Tracker, protocols, flows, !compactStorage)
		if sipFactory != nil && sipFactory.LastEvent != nil {
			applyOfflineSIPEvent(&packet, *sipFactory.LastEvent)
		}
		if packet.Protocol == "DNS" {
			packet.DNSData = parseOfflineDNSPacket(info.Packet, packet.LinkType)
		}
		if packet.Protocol == "HTTP" {
			packet.HTTPData = parseHTTPFromPacket(info.Packet)
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
		var appendErr error
		if compactStorage {
			if info.Provenance == nil {
				return errors.New("compact offline packet has no effective-byte provenance")
			}
			if asyncWriter != nil {
				appendErr = asyncWriter.Append(detail, *info.Provenance)
			} else {
				appendErr = builder.AppendCompact(readCtx, detail, *info.Provenance)
			}
		} else {
			appendErr = builder.Append(readCtx, detail)
		}
		if appendErr != nil {
			return appendErr
		}
		indexedPackets++
		progress.LogicalPackets++
		progress.ScannedBytes += uint64(meta.CaptureLength)
		publish(false)
		return nil
	}
	consume := func(readCtx context.Context, ch <-chan capture.PacketInfo) error {
		for info := range ch {
			if err := consumeOne(readCtx, info); err != nil {
				return err
			}
		}
		return nil
	}
	if prepared != nil {
		if compactStorage {
			replayCtx := workerContext
			if asyncWriter != nil {
				replayCtx = asyncWriter.Context()
			}
			err = prepared.ReplayPackets(replayCtx, consumeOne)
		} else {
			err = prepared.Replay(ctx, consume)
		}
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
	if asyncWriter != nil {
		if err = asyncWriter.Close(); err != nil {
			return nil, err
		}
	}
	if analysisWorker != nil {
		if err = analysisWorker.Close(); err != nil {
			return nil, err
		}
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

// TCP replay enables datagram dissection for other protocols. Its automatically
// decoded DNS layer can include the two-byte TCP length prefix, so preserve the
// original transport-aware DNS parsing for TCP while reusing UDP dissection.
func parseOfflineDNSPacket(packet gopacket.Packet, linkType layers.LinkType) *types.DNSMetadata {
	if _, tcp := packet.TransportLayer().(*layers.TCP); tcp {
		return parseDNSFromRawData(packet.Data(), linkType)
	}
	return dns.NewParser().Parse(packet)
}
