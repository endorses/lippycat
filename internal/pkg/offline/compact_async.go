package offline

import (
	"context"
	"errors"
	"io"
	"maps"
	"reflect"
	"sync"
)

// AsyncCompactWriter overlaps ordered analysis with a single serialized writer.
// Three bounded batches cover producer, queued and active work; every snapshot
// owns all mutable metadata and raw bytes. Small caches stay synchronous.
type AsyncCompactWriter struct {
	storage     *Storage
	builder     *Builder
	ctx         context.Context
	cancel      context.CancelCauseFunc
	jobs        chan *compactAppendBatch
	free        chan *compactAppendBatch
	pending     *compactAppendBatch
	done        chan struct{}
	once        sync.Once
	err         error
	held        io.Closer
	rawCapacity int
}
type compactAppendJob struct {
	detail     Detail
	provenance PacketProvenance
	held       io.Closer
}
type compactAppendBatch struct {
	jobs    [32]compactAppendJob
	n       int
	bytes   uint64
	barrier chan struct{}
	raw     []byte
}

func NewAsyncCompactWriter(ctx context.Context, storage *Storage, builder *Builder) (*AsyncCompactWriter, error) {
	if storage.limits.CacheBytes < 16<<20 || storage.limits.MaxRecordBytes > storage.limits.CacheBytes/8 {
		return nil, nil
	}
	rawCapacity := int(min(uint64(64<<10), storage.limits.CacheBytes/1024))
	held, err := storage.ReserveTransient(ctx, uint64(reflect.TypeOf(compactAppendBatch{}).Size())*3+uint64(rawCapacity)*3+1024)
	if err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancelCause(ctx)
	w := &AsyncCompactWriter{storage: storage, builder: builder, ctx: workerCtx, cancel: cancel, jobs: make(chan *compactAppendBatch, 1), free: make(chan *compactAppendBatch, 3), done: make(chan struct{}), held: held, rawCapacity: rawCapacity}
	for i := 0; i < 3; i++ {
		w.free <- &compactAppendBatch{raw: make([]byte, 0, rawCapacity)}
	}
	go w.run()
	return w, nil
}
func (w *AsyncCompactWriter) Context() context.Context { return w.ctx }
func (w *AsyncCompactWriter) run() {
	defer close(w.done)
	for batch := range w.jobs {
		for i := 0; i < batch.n; i++ {
			job := &batch.jobs[i]
			if w.err == nil {
				w.err = w.builder.AppendCompact(w.ctx, job.detail, job.provenance)
			}
			w.err = errors.Join(w.err, job.held.Close())
			*job = compactAppendJob{}
			if w.err != nil {
				w.cancel(w.err)
			}
		}
		if batch.barrier != nil {
			close(batch.barrier)
		}
		batch.n, batch.bytes, batch.barrier = 0, 0, nil
		batch.raw = batch.raw[:0]
		w.free <- batch
	}
}
func (w *AsyncCompactWriter) flush() error {
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
func (w *AsyncCompactWriter) acquire() error {
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
func (w *AsyncCompactWriter) Append(detail Detail, provenance PacketProvenance) error {
	if err := context.Cause(w.ctx); err != nil {
		return err
	}
	n, err := compactDetailMemory(&detail, w.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	// Bound snapshot overlap independently of the maximum legal record size.
	if n > w.storage.limits.MaxRecordBytes/16 || len(detail.Packet.RawData) > w.rawCapacity {
		if err := w.Drain(); err != nil {
			return err
		}
		return w.builder.AppendCompact(w.ctx, detail, provenance)
	}
	if w.pending != nil && (w.pending.n == len(w.pending.jobs) || w.pending.bytes+n > w.storage.limits.CacheBytes/64 || len(w.pending.raw)+len(detail.Packet.RawData) > w.rawCapacity) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	held, err := w.storage.ReserveTransient(w.ctx, n-uint64(len(detail.Packet.RawData)))
	if err != nil {
		if drainErr := w.Drain(); drainErr != nil {
			return drainErr
		}
		return w.builder.AppendCompact(w.ctx, detail, provenance)
	}
	if err := w.acquire(); err != nil {
		return errors.Join(err, held.Close())
	}
	// Raw storage belongs to this batch until every job has finished. Limit
	// each packet's capacity so no consumer can append into the next packet.
	start := len(w.pending.raw)
	end := start + len(detail.Packet.RawData)
	w.pending.raw = w.pending.raw[:end]
	raw := w.pending.raw[start:end:end]
	if detail.Packet.RawData == nil {
		raw = nil
	}
	copy(raw, detail.Packet.RawData)
	w.pending.jobs[w.pending.n] = compactAppendJob{detail: cloneCompactDetail(detail, raw), provenance: provenance, held: held}
	w.pending.n++
	w.pending.bytes += n
	return nil
}

// Drain is the barrier before synchronous row amendments. Calls from the
// analyzer to Append, Drain and Close must remain serialized.
func (w *AsyncCompactWriter) Drain() error {
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
func (w *AsyncCompactWriter) Close() error {
	w.once.Do(func() {
		flushErr := w.flush()
		if w.pending != nil {
			for i := 0; i < w.pending.n; i++ {
				flushErr = errors.Join(flushErr, w.pending.jobs[i].held.Close())
				w.pending.jobs[i] = compactAppendJob{}
			}
			w.pending = nil
		}
		close(w.jobs)
		<-w.done
		// The worker has returned all active/queued batches. Drop slab and
		// descriptor references before releasing their retained reservation.
		for len(w.free) > 0 {
			batch := <-w.free
			batch.raw = nil
		}
		w.free, w.jobs = nil, nil
		w.err = errors.Join(w.err, flushErr, w.held.Close())
		w.cancel(context.Canceled)
	})
	return w.err
}

func cloneCompactDetail(d Detail, raw []byte) Detail {
	p := &d.Packet
	p.RawData = raw
	if p.VoIPData != nil {
		m := *p.VoIPData
		m.Headers = maps.Clone(m.Headers)
		m.RawSIP = cloneCompactSlice(m.RawSIP)
		if m.AccessNetworkInfo != nil {
			a := *m.AccessNetworkInfo
			a.Parameters = maps.Clone(a.Parameters)
			m.AccessNetworkInfo = &a
		}
		p.VoIPData = &m
	}
	if p.DNSData != nil {
		m := *p.DNSData
		m.Answers = cloneCompactSlice(m.Answers)
		p.DNSData = &m
	}
	if p.EmailData != nil {
		m := *p.EmailData
		m.RcptTo = cloneCompactSlice(m.RcptTo)
		m.IMAPFlags = cloneCompactSlice(m.IMAPFlags)
		p.EmailData = &m
	}
	if p.RADIUSData != nil {
		m := *p.RADIUSData
		m.Attributes = cloneCompactSlice(m.Attributes)
		p.RADIUSData = &m
	}
	if p.HTTPData != nil {
		m := *p.HTTPData
		m.Headers = maps.Clone(m.Headers)
		p.HTTPData = &m
	}
	if p.TLSData != nil {
		m := *p.TLSData
		m.CipherSuites = cloneCompactSlice(m.CipherSuites)
		m.Extensions = cloneCompactSlice(m.Extensions)
		m.SupportedVersions = cloneCompactSlice(m.SupportedVersions)
		m.SupportedGroups = cloneCompactSlice(m.SupportedGroups)
		m.SignatureAlgos = cloneCompactSlice(m.SignatureAlgos)
		m.ECPointFormats = cloneCompactSlice(m.ECPointFormats)
		m.ALPNProtocols = cloneCompactSlice(m.ALPNProtocols)
		p.TLSData = &m
	}
	return d
}

func cloneCompactSlice[T any](value []T) []T {
	if value == nil {
		return nil
	}
	result := make([]T, len(value))
	copy(result, value)
	return result
}
