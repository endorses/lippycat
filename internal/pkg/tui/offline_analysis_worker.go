//go:build tui || all

package tui

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
)

// offlineAnalysisWorker preserves event-analysis order in one independent
// consumer. Three fixed batches bound producer, queued and active snapshots.
// Submit, Drain and Close belong to the serial indexing goroutine.
type offlineAnalysisWorker struct {
	storage   *offline.Storage
	observe   func(eventanalysis.Source, capture.PacketInfo) error
	decoder   *capture.OfflinePacketDecoder
	ctx       context.Context
	cancel    context.CancelCauseFunc
	jobs      chan *offlineAnalysisBatch
	free      chan *offlineAnalysisBatch
	pending   *offlineAnalysisBatch
	done      chan struct{}
	once      sync.Once
	err       error
	held      io.Closer
	slabBytes uint64
}

type offlineAnalysisJob struct {
	source   eventanalysis.Source
	info     capture.PacketInfo
	metadata gopacket.PacketMetadata
	raw      []byte
	held     io.Closer
}

type offlineAnalysisBatch struct {
	jobs    [32]offlineAnalysisJob
	n       int
	bytes   uint64
	raw     []byte
	barrier chan struct{}
}

func newOfflineAnalysisWorker(ctx context.Context, storage *offline.Storage, observe func(eventanalysis.Source, capture.PacketInfo) error) (*offlineAnalysisWorker, error) {
	if storage.MemoryLimit() < 16<<20 {
		return nil, nil
	}
	slabBytes := min(uint64(64<<10), storage.MemoryLimit()/1024)
	held, err := storage.ReserveTransient(ctx, (uint64(reflect.TypeOf(offlineAnalysisBatch{}).Size())+slabBytes)*3+uint64(reflect.TypeOf(capture.OfflinePacketDecoder{}).Size())+1024)
	if err != nil {
		return nil, err
	}
	decoder := capture.NewOfflinePacketDecoder()
	workerCtx, cancel := context.WithCancelCause(ctx)
	w := &offlineAnalysisWorker{storage: storage, observe: observe, decoder: decoder, ctx: workerCtx, cancel: cancel, jobs: make(chan *offlineAnalysisBatch, 1), free: make(chan *offlineAnalysisBatch, 3), done: make(chan struct{}), held: held, slabBytes: slabBytes}
	for range 3 {
		w.free <- &offlineAnalysisBatch{raw: make([]byte, slabBytes)}
	}
	go w.run()
	return w, nil
}

func (w *offlineAnalysisWorker) Context() context.Context { return w.ctx }

func (w *offlineAnalysisWorker) run() {
	defer close(w.done)
	for batch := range w.jobs {
		for i := 0; i < batch.n; i++ {
			job := &batch.jobs[i]
			if w.err == nil {
				w.err = context.Cause(w.ctx)
			}
			if w.err == nil {
				job.info.Packet = w.decoder.Decode(job.raw, job.info.LinkType)
				*job.info.Packet.Metadata() = job.metadata
				w.err = w.observe(job.source, job.info)
			}
			if job.held != nil {
				w.err = errors.Join(w.err, job.held.Close())
			}
			*job = offlineAnalysisJob{}
			if w.err != nil {
				w.cancel(w.err)
			}
		}
		if batch.barrier != nil {
			close(batch.barrier)
		}
		batch.n, batch.bytes, batch.barrier = 0, 0, nil
		w.free <- batch
	}
	// Release every fixed slab reference before releasing its reservation.
	w.decoder, w.free = nil, nil
	w.err = errors.Join(w.err, context.Cause(w.ctx), w.held.Close())
}

func (w *offlineAnalysisWorker) flush() error {
	if w.pending == nil {
		return nil
	}
	select {
	case w.jobs <- w.pending:
		w.pending = nil
		return nil
	case <-w.ctx.Done():
		return context.Cause(w.ctx)
	}
}

func (w *offlineAnalysisWorker) acquire() error {
	if w.pending != nil {
		return nil
	}
	select {
	case w.pending = <-w.free:
		return nil
	case <-w.ctx.Done():
		return context.Cause(w.ctx)
	}
}

func (w *offlineAnalysisWorker) Submit(source eventanalysis.Source, info capture.PacketInfo) error {
	if err := context.Cause(w.ctx); err != nil {
		return err
	}
	if info.Packet == nil {
		return errors.New("offline analysis requires a packet")
	}
	raw := info.Packet.Data()
	n := uint64(len(source.ProcessorNodeIDs)) * uint64(reflect.TypeOf("").Size())
	if uint64(len(raw)) > w.slabBytes || n > w.storage.MemoryLimit()/1024 {
		if err := w.Drain(); err != nil {
			return err
		}
		return w.observeSynchronously(source, info)
	}
	if w.pending != nil && (w.pending.n == len(w.pending.jobs) || w.pending.bytes+uint64(len(raw)) > w.slabBytes) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	var held io.Closer
	if n != 0 {
		var err error
		held, err = w.storage.ReserveTransient(w.ctx, n)
		if err != nil {
			if drainErr := w.Drain(); drainErr != nil {
				return drainErr
			}
			return w.observeSynchronously(source, info)
		}
	}
	if err := w.acquire(); err != nil {
		if held != nil {
			err = errors.Join(err, held.Close())
		}
		return err
	}
	metadata := *info.Packet.Metadata()
	// Capture ancillary objects are not read by Runtime.ObservePacket. Avoid
	// retaining arbitrary caller-owned objects beyond this synchronous call.
	metadata.AncillaryData = nil
	info.Packet, info.Provenance = nil, nil
	if source.ProcessorNodeIDs != nil {
		nodes := make([]string, len(source.ProcessorNodeIDs))
		copy(nodes, source.ProcessorNodeIDs)
		source.ProcessorNodeIDs = nodes
	}
	start, end := w.pending.bytes, w.pending.bytes+uint64(len(raw))
	owned := w.pending.raw[start:end:end]
	copy(owned, raw)
	w.pending.jobs[w.pending.n] = offlineAnalysisJob{source: source, info: info, metadata: metadata, raw: owned, held: held}
	w.pending.n++
	w.pending.bytes = end
	return nil
}

func (w *offlineAnalysisWorker) observeSynchronously(source eventanalysis.Source, info capture.PacketInfo) error {
	err := w.observe(source, info)
	if err != nil {
		w.cancel(err)
	}
	return err
}

func (w *offlineAnalysisWorker) Drain() error {
	if err := context.Cause(w.ctx); err != nil {
		return err
	}
	if err := w.flush(); err != nil {
		return err
	}
	if err := w.acquire(); err != nil {
		return err
	}
	barrier := make(chan struct{})
	w.pending.barrier = barrier
	if err := w.flush(); err != nil {
		return err
	}
	select {
	case <-barrier:
		return context.Cause(w.ctx)
	case <-w.ctx.Done():
		return context.Cause(w.ctx)
	}
}

func (w *offlineAnalysisWorker) Close() error {
	w.once.Do(func() {
		flushErr := w.flush()
		if w.pending != nil {
			for i := 0; i < w.pending.n; i++ {
				if w.pending.jobs[i].held != nil {
					flushErr = errors.Join(flushErr, w.pending.jobs[i].held.Close())
				}
				w.pending.jobs[i] = offlineAnalysisJob{}
			}
			w.pending = nil
		}
		close(w.jobs)
		<-w.done
		w.err = errors.Join(w.err, flushErr)
		w.cancel(context.Canceled)
	})
	return w.err
}
