package offline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
)

// One worker owns one borrowed block and one bounded directory segment. The
// coordinator does all row decoding and predicate work in packet-ID order.
type compactQueryJob struct {
	first     PacketID
	count     uint64
	off, size uint64
}

type compactQueryResult struct {
	job   compactQueryJob
	block []byte
	err   error
}

type compactQueryWorker struct {
	reader   *compactScanReader
	decoder  *compactQueryDecoder
	entries  []byte
	jobs     chan compactQueryJob
	results  chan compactQueryResult
	ack      chan struct{}
	closeErr error
}

func (d *diskDataset) compactQueryJob(ctx context.Context, directory *bufio.Reader, first PacketID, entries []byte, pending *[compactIndexBytes]byte, hasPending *bool) (compactQueryJob, error) {
	var entry [compactIndexBytes]byte
	if *hasPending {
		entry = *pending
		*hasPending = false
	} else if _, err := io.ReadFull(directory, entry[:]); err != nil {
		return compactQueryJob{}, err
	}
	copy(entries, entry[:])
	job := compactQueryJob{first: first, count: 1, off: binary.LittleEndian.Uint64(entry[:8]), size: binary.LittleEndian.Uint64(entry[8:16])}
	for job.count < uint64(len(entries)/compactIndexBytes) && uint64(first)+job.count < d.count {
		if err := ctx.Err(); err != nil {
			return compactQueryJob{}, err
		}
		if _, err := io.ReadFull(directory, entry[:]); err != nil {
			return compactQueryJob{}, err
		}
		if binary.LittleEndian.Uint64(entry[:8]) != job.off || binary.LittleEndian.Uint64(entry[8:16]) != job.size {
			*pending = entry
			*hasPending = true
			break
		}
		copy(entries[job.count*compactIndexBytes:], entry[:])
		job.count++
	}
	return job, nil
}

func (w *compactQueryWorker) run(ctx context.Context, d *diskDataset, done *sync.WaitGroup) {
	defer done.Done()
	defer func() { w.closeErr = w.reader.Close(); d.storage.releaseMemory(uint64(len(w.entries))) }()
	for {
		var job compactQueryJob
		select {
		case job = <-w.jobs:
		case <-ctx.Done():
			return
		}
		result := compactQueryResult{job: job}
		for i := uint64(0); i < job.count; i++ {
			if err := ctx.Err(); err != nil {
				result.err = err
				break
			}
			entry := w.entries[i*compactIndexBytes : (i+1)*compactIndexBytes]
			id := job.first + PacketID(i)
			checksum, err := w.reader.IndexChecksum(entry[:32], id)
			if err != nil {
				result.err = err
				break
			}
			if !bytes.Equal(checksum[:], entry[32:]) {
				result.err = errors.New("compact row directory checksum mismatch")
				break
			}
			if binary.LittleEndian.Uint64(entry[:8]) != job.off || binary.LittleEndian.Uint64(entry[8:16]) != job.size {
				result.err = errors.New("compact directory reference changed during scan")
				break
			}
		}
		if result.err == nil {
			result.block, result.err = w.reader.Read(ctx, d.summaries, job.off, job.size, 1, job.first)
		}
		select {
		case w.results <- result:
		case <-ctx.Done():
			return
		}
		if result.err != nil {
			return
		}
		// The result borrows reader buffers. Wait until the coordinator finishes
		// decoding before reusing or releasing them.
		select {
		case <-w.ack:
		case <-ctx.Done():
			return
		}
	}
}

// scanCompactSummariesParallel returns used=false when the shared memory budget
// cannot hold at least two independent scan readers plus decoder headroom.
func (d *diskDataset) scanCompactSummariesParallel(ctx context.Context, expression *Expression, related bool, visit func(Summary) error) (used bool, err error) {
	workerCount := min(runtime.GOMAXPROCS(0), 4)
	if workerCount < 2 {
		return false, nil
	}
	bufferBytes := min(uint64(32<<10), d.storage.limits.MaxRecordBytes)
	projectionBytes := compactQueryProjectionCredit()
	coordinatorBytes := bufferBytes + projectionBytes
	if err := d.storage.reserveMemory(ctx, coordinatorBytes); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	defer d.storage.releaseMemory(coordinatorBytes)
	directory := bufio.NewReaderSize(io.NewSectionReader(d.offsets, compactHeaderBytes, int64(d.count)*compactIndexBytes), int(bufferBytes))
	maxRows := min(uint64(4096), max(uint64(1), d.storage.limits.MaxRecordBytes/compactIndexBytes))
	entryBytes := maxRows * compactIndexBytes
	workers := make([]*compactQueryWorker, 0, workerCount)
	var setupErr error
	for len(workers) < workerCount {
		usage := d.storage.Resources()
		occupied := usage.CachedBytes + usage.PinnedBytes + usage.PrefetchBytes + usage.InFlightBytes
		// Admit each reader's inflater before launching any worker.
		// A reader's third MaxRecordBytes allowance covers the coordinator's
		// decoded row scratch while its worker uses the two block buffers. The
		// coordinator's directory buffer and fixed projection are already held.
		need := entryBytes + 3*d.storage.limits.MaxRecordBytes + 4096 + compactInflaterMemory
		if occupied > d.storage.limits.CacheBytes || need > d.storage.limits.CacheBytes-occupied {
			break
		}
		reader, readerErr := newCompactScanReader(ctx, d)
		if readerErr != nil {
			if probeErr := d.storage.reserveMemory(ctx, 0); probeErr != nil {
				setupErr = readerErr
			}
			break
		}
		if !reader.inflaterHeld {
			if reserveErr := d.storage.reserveMemory(ctx, compactInflaterMemory); reserveErr != nil {
				closeErr := reader.Close()
				if probeErr := d.storage.reserveMemory(ctx, 0); probeErr == nil {
					setupErr = closeErr // A competing allocation exhausted the budget.
				} else {
					setupErr = errors.Join(reserveErr, closeErr)
				}
				break
			}
			reader.held += compactInflaterMemory
			reader.inflaterHeld = true
		}
		if reserveErr := d.storage.reserveMemory(ctx, entryBytes); reserveErr != nil {
			closeErr := reader.Close()
			if probeErr := d.storage.reserveMemory(ctx, 0); probeErr == nil {
				setupErr = closeErr // A competing allocation exhausted the budget.
			} else {
				setupErr = errors.Join(reserveErr, closeErr)
			}
			break
		}
		decoder := newCompactQueryDecoder(expression, related)
		decoder.projectionCredit = true
		workers = append(workers, &compactQueryWorker{
			reader: reader, decoder: decoder, entries: make([]byte, int(entryBytes)),
			jobs: make(chan compactQueryJob), results: make(chan compactQueryResult, 1), ack: make(chan struct{}),
		})
	}
	if setupErr != nil || len(workers) < 2 {
		for _, w := range workers {
			err = errors.Join(err, w.reader.Close())
			d.storage.releaseMemory(uint64(len(w.entries)))
		}
		return false, errors.Join(setupErr, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	var done sync.WaitGroup
	for _, w := range workers {
		done.Add(1)
		go w.run(ctx, d, &done)
	}
	defer func() {
		cancel()
		done.Wait()
		for _, w := range workers {
			err = errors.Join(err, w.closeErr)
		}
	}()
	var next PacketID
	active := 0
	issued := 0
	var pending [compactIndexBytes]byte
	var hasPending bool
	for active < len(workers) && uint64(next) < d.count {
		job, jobErr := d.compactQueryJob(ctx, directory, next, workers[active].entries, &pending, &hasPending)
		if jobErr != nil {
			return true, jobErr
		}
		select {
		case workers[active].jobs <- job:
		case <-ctx.Done():
			return true, ctx.Err()
		}
		next += PacketID(job.count)
		active++
		issued++
	}
	for sequence := 0; sequence < issued; sequence++ {
		w := workers[sequence%active]
		var result compactQueryResult
		select {
		case result = <-w.results:
		case <-ctx.Done():
			return true, ctx.Err()
		}
		if result.err != nil {
			return true, result.err
		}
		for i := uint64(0); i < result.job.count; i++ {
			if err := ctx.Err(); err != nil {
				return true, err
			}
			entry := w.entries[i*compactIndexBytes : (i+1)*compactIndexBytes]
			if err := w.decoder.visit(ctx, d, result.block, entry, result.job.first+PacketID(i), visit); err != nil {
				return true, err
			}
		}
		select {
		case w.ack <- struct{}{}:
		case <-ctx.Done():
			return true, ctx.Err()
		}
		if uint64(next) < d.count {
			job, jobErr := d.compactQueryJob(ctx, directory, next, w.entries, &pending, &hasPending)
			if jobErr != nil {
				return true, jobErr
			}
			select {
			case w.jobs <- job:
			case <-ctx.Done():
				return true, ctx.Err()
			}
			next += PacketID(job.count)
			issued++
		}
	}
	return true, ctx.Err()
}
