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
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// offlineRevisionSnapshot is a published immutable view. Its packet and event
// datasets belong to the session, including when a completion message is lost.
// A completed revision never overwrites fields in an already published base.
type offlineRevisionSnapshot struct {
	Revision      offline.AnalysisRevision
	Dataset       offline.Dataset
	EventDataset  offline.EventDataset
	EventStore    *store.EventStore
	Calls         []types.CallInfo
	Tracker       *CallTracker
	TLSDecryptor  *TLSDecryptor
	AnalysisStats eventanalysis.Stats
}

type offlineViewCloser struct {
	closer io.Closer
	cancel func()
}

type offlineIndexedSession struct {
	closeMu           sync.Mutex
	eventMu           sync.Mutex
	eventClosed       bool
	eventClosers      []offlineViewCloser
	analysisMu        sync.Mutex
	analysisCancel    context.CancelCauseFunc
	analysisDone      chan struct{}
	analysisCandidate *offlineIndexedSession
	markRange         *offlineMarkRangeState
	export            *offlineExportState
	browser           *offlineBrowser
	filter            *offlineFilterOwner
	related           *offlineRelatedOwner
	Dataset           offline.Dataset
	EventDataset      offline.EventDataset
	sortCleanup       io.Closer
	builder           *offline.Builder
	eventBuilder      *offline.EventBuilder
	expectedPackets   uint64
	EventStore        *store.EventStore
	Calls             []types.CallInfo
	Tracker           *CallTracker
	TLSDecryptor      *TLSDecryptor
	AnalysisStats     eventanalysis.Stats
}

func snapshotOfflineRevision(s *offlineIndexedSession) *offlineRevisionSnapshot {
	return &offlineRevisionSnapshot{
		Revision: s.Dataset.Revision(), Dataset: s.Dataset, EventDataset: s.EventDataset,
		EventStore: s.EventStore, Calls: s.Calls, Tracker: s.Tracker,
		TLSDecryptor: s.TLSDecryptor, AnalysisStats: s.AnalysisStats,
	}
}

// Registration transfers ownership only on success. Every cancellation runs
// before any join, so an export pin cannot prevent its query owner from closing.
func (s *offlineIndexedSession) registerViewCloser(closer io.Closer, cancel func()) error {
	if closer == nil {
		return errors.New("offline view closer is nil")
	}
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.eventClosed {
		return errors.New("offline session is closing")
	}
	s.eventClosers = append(s.eventClosers, offlineViewCloser{closer, cancel})
	return nil
}

func (s *offlineIndexedSession) registerEventCloser(closer io.Closer) error {
	var cancel func()
	if c, ok := closer.(interface{ Cancel() }); ok {
		cancel = c.Cancel
	}
	return s.registerViewCloser(closer, cancel)
}

func (s *offlineIndexedSession) CancelAnalysis() {
	if s == nil {
		return
	}
	s.analysisMu.Lock()
	cancel := s.analysisCancel
	s.analysisMu.Unlock()
	if cancel != nil {
		cancel(context.Canceled)
	}
}

var offlineNoAnalysisDone = func() <-chan struct{} { c := make(chan struct{}); close(c); return c }()

func (s *offlineIndexedSession) AnalysisDone() <-chan struct{} {
	if s == nil {
		return offlineNoAnalysisDone
	}
	s.analysisMu.Lock()
	defer s.analysisMu.Unlock()
	if s.analysisDone == nil {
		return offlineNoAnalysisDone
	}
	return s.analysisDone
}

// discardAnalysisCandidate disposes a rejected completed result outside Update.
// The base and its readers/exports remain owned and usable. Failed candidate
// cleanup stays attached to this session so shutdown or a later retry can join it.
func (s *offlineIndexedSession) discardAnalysisCandidate() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	<-s.AnalysisDone()
	s.analysisMu.Lock()
	candidate := s.analysisCandidate
	s.analysisMu.Unlock()
	if candidate == nil {
		return nil
	}
	if err := candidate.Close(); err != nil {
		return err
	}
	s.analysisMu.Lock()
	s.analysisCandidate = nil
	s.analysisMu.Unlock()
	return nil
}

func (s *offlineIndexedSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.eventMu.Lock()
	s.eventClosed = true
	closers := s.eventClosers
	s.eventClosers = nil
	s.eventMu.Unlock()
	s.CancelAnalysis()
	for _, owner := range closers {
		if owner.cancel != nil {
			owner.cancel()
		}
	}
	// These legacy fields remain supported for synchronous callers and tests.
	// Progressive UI owners register above instead of replacing these fields.
	if s.markRange != nil {
		s.markRange.cancel()
	}
	if s.export != nil {
		s.export.cancel()
	}
	if s.filter != nil {
		s.filter.Cancel()
	}
	if s.browser != nil {
		s.browser.Cancel()
	}
	if s.related != nil {
		s.related.mu.Lock()
		if s.related.cancel != nil {
			s.related.cancel()
		}
		s.related.mu.Unlock()
	}
	<-s.AnalysisDone()
	if s.markRange != nil {
		<-s.markRange.done
	}
	if s.export != nil {
		<-s.export.done
	}
	var closeErr error
	failed := closers[:0]
	for _, owner := range closers {
		if err := owner.closer.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
			failed = append(failed, owner)
		}
	}
	clear(closers[len(failed):])
	s.eventMu.Lock()
	s.eventClosers = failed
	s.eventMu.Unlock()
	if s.filter != nil {
		closeErr = errors.Join(closeErr, s.filter.close())
	}
	if s.related != nil {
		s.related.close()
	}
	if s.browser != nil {
		closeErr = errors.Join(closeErr, s.browser.close())
	}
	if closeErr != nil {
		// Failed owners may retain pins; keep their datasets available for retry.
		return closeErr
	}
	s.analysisMu.Lock()
	candidate := s.analysisCandidate
	s.analysisMu.Unlock()
	if candidate != nil {
		if err := candidate.Close(); err != nil {
			return err
		}
		s.analysisMu.Lock()
		s.analysisCandidate = nil
		s.analysisMu.Unlock()
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
	if s.eventBuilder != nil {
		if err := s.eventBuilder.Abort(); err != nil {
			closeErr = errors.Join(closeErr, err)
		} else {
			s.eventBuilder = nil
		}
	}
	if s.EventDataset != nil {
		closeErr = errors.Join(closeErr, s.EventDataset.Close())
	}
	if s.Dataset != nil {
		closeErr = errors.Join(closeErr, s.Dataset.Close())
	}
	return closeErr
}

// indexOfflineProgressiveDataset publishes the complete B-only base before
// starting application analysis. Both passes use the same validated byte
// backings and locator ordering. The caller owns the returned session even on
// error; after onBase succeeds, cancellation or analysis failure preserves base.
func indexOfflineProgressiveDataset(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), onBase func(*offlineIndexedSession) error) (session *offlineIndexedSession, completed *offlineRevisionSnapshot, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	session = &offlineIndexedSession{analysisCancel: cancel, analysisDone: make(chan struct{}), EventStore: store.NewEventStore(cfg.EventCapacity), Tracker: NewCallTrackerWithCapacity(cfg.MaxCalls)}
	defer func() { cancel(nil); close(session.analysisDone) }()
	if err = ctx.Err(); err != nil {
		return session, nil, err
	}
	if _, err = resolveLocalEventOptions(cfg.Analysis); err != nil {
		return session, nil, fmt.Errorf("offline event policy: %w", err)
	}
	if cfg.BackingPolicy, err = offline.ParseBackingPolicy(string(cfg.BackingPolicy)); err != nil {
		return session, nil, err
	}
	ctx = capture.WithOfflineESPConfig(ctx, cfg.ESP)
	ctx = capture.WithOfflineBackingPolicy(ctx, cfg.BackingPolicy)
	sources := make([]offline.SourcePosition, len(cfg.Inputs))
	for i, path := range cfg.Inputs {
		sources[i] = offline.SourcePosition{ArgumentIndex: uint32(i), Path: path}
	}
	started, last := time.Now(), time.Time{}
	progress := offline.Progress{Token: offline.Token{Dataset: generation, Revision: offline.BaseRevision}, State: offline.Reading, Sources: uint32(len(sources))}
	publish := func(force bool) {
		if report != nil && (force || time.Since(last) >= 100*time.Millisecond) {
			progress.Elapsed, progress.DiskBytes = time.Since(started), storage.Resources().DiskBytes
			report(progress)
			last = time.Now()
		}
	}
	publish(true)
	var prepared *capture.OfflineLocatorStream
	basePass := true
	var prepareErr error
	openErr := capture.StartOfflineSnifferOrdered(cfg.Inputs, cfg.BPFFilter, func(devices []pcaptypes.PcapInterface, filter string) {
		prepared, prepareErr = capture.PrepareOfflineLocatorStream(ctx, devices, filter, storage, func(p capture.OfflineSortProgress) {
			if !basePass {
				return
			}
			switch p.Phase {
			case "Reading":
				progress.State = offline.Reading
			case "Sorting":
				progress.State = offline.Sorting
			case "Replaying":
				progress.State = offline.Indexing
			}
			progress.LogicalPackets, progress.ScannedBytes = p.LogicalPackets, p.BytesScanned
			if progress.State == offline.Indexing {
				progress.TotalPackets = p.LogicalPackets
				progress.LogicalPackets, progress.ScannedBytes = 0, 0
			}
			publish(true)
		})
		if prepared != nil {
			session.sortCleanup = prepared
		}
	})
	if err = errors.Join(openErr, prepareErr); err != nil {
		return session, nil, err
	}
	session.builder, err = storage.NewCompactBaseBuilder(generation, sources, prepared.Backings())
	if err != nil {
		return session, nil, err
	}
	if err = prepared.TransferBackings(); err != nil {
		return session, nil, err
	}
	var env pipeline.PacketEnvelope
	err = prepared.ReplayPackets(ctx, func(readCtx context.Context, info capture.PacketInfo) error {
		captureadapter.ResetFromPacketInfo(&env, info, pipeline.SourcePCAPReplay)
		fields := capture.ExtractPacketFields(info.Packet)
		meta := info.Packet.Metadata()
		packet := types.PacketDisplay{ObservationDomain: env.Source.ObservationDomain, ObservationDomainKnown: env.Source.ObservationDomainKnown, Timestamp: meta.Timestamp, SrcIP: fields.SrcIP, DstIP: fields.DstIP, SrcPort: fields.SrcPort, DstPort: fields.DstPort, Transport: fields.Transport, Length: meta.Length, RawData: info.Packet.Data(), Interface: env.Source.InterfaceName, LinkType: env.LinkType}
		if info.Provenance == nil {
			return errors.New("base offline packet has no effective-byte provenance")
		}
		detail := offline.Detail{Source: offline.SourcePosition{ArgumentIndex: info.SourceIndex, Path: info.SourcePath, InterfaceID: info.SourceInterfaceID, Sequence: info.SourceSequence}, CapturedLength: uint32(meta.CaptureLength), OriginalLength: uint32(meta.Length), Packet: packet}
		if err := session.builder.AppendCompact(readCtx, detail, *info.Provenance); err != nil {
			return err
		}
		progress.LogicalPackets++
		progress.ScannedBytes += uint64(meta.CaptureLength)
		publish(false)
		return nil
	})
	basePass = false
	if err != nil {
		return session, nil, err
	}
	progress.State = offline.Finalizing
	publish(true)
	// Finish seals the backing registry and must run after replay released its
	// borrowed raw lease, never from inside a ReplayPackets visitor.
	session.Dataset, err = session.builder.Finish(ctx)
	if err != nil {
		return session, nil, err
	}
	session.builder = nil
	progress.State = offline.Ready
	publish(true)
	if onBase != nil {
		if err = onBase(session); err != nil {
			return session, nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return session, nil, err
	}
	candidate := &offlineIndexedSession{EventStore: store.NewEventStore(cfg.EventCapacity), Tracker: NewCallTrackerWithCapacity(cfg.MaxCalls), expectedPackets: session.Dataset.Count()}
	candidate.builder, err = storage.NewCompactRevisionBuilder(session.Dataset, offline.CompletedRevision, materializeOfflinePacket)
	if err != nil {
		session.analysisMu.Lock()
		session.analysisCandidate = candidate
		session.analysisMu.Unlock()
		return session, nil, err
	}
	candidate, err = indexOfflineDatasetPrepared(ctx, storage, generation, cfg, report, nil, true, true, true, true, &offlinePreparedAnalysis{
		stream: prepared, session: candidate,
		releaseReplay: func() error {
			if closeErr := prepared.Close(); closeErr != nil {
				return closeErr
			}
			session.sortCleanup = nil
			return nil
		},
	})
	session.analysisMu.Lock()
	session.analysisCandidate = candidate
	session.analysisMu.Unlock()
	if err != nil {
		return session, nil, err
	}
	return session, snapshotOfflineRevision(candidate), nil
}
