package offline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/protobuf/proto"
)

const eventDatasetMemory = 1024

// EventBuilder admits immutable metadata snapshots in arrival order. Append
// errors poison the builder: Finish never publishes an incomplete prefix.
// The owner must Abort after any failure; failed removal remains retryable.
type EventBuilder struct {
	mu        sync.Mutex
	d         *diskEventDataset
	failure   error
	finished  bool
	published bool
}

type diskEventDataset struct {
	mu                      sync.RWMutex
	queryMu                 sync.Mutex
	storage                 *Storage
	generation              DatasetGeneration
	count                   uint64
	dir                     string
	data, offsets, manifest *os.File
	dataBytes, offsetBytes  uint64
	ownedBytes, memoryBytes uint64
	completion              [eventManifestBytes]byte
	queryHead               *diskEventQuery
	queryCount              uint64
	closed, cleaned         bool
}

// NewEventBuilder uses the packet storage owner's shared disk/cache budgets.
// A non-nil builder returned with an error owns cleanup that failed and must be
// retained for Abort retries, just like a failed offline session.
func (s *Storage) NewEventBuilder(generation DatasetGeneration) (builder *EventBuilder, err error) {
	if err = s.reserveMemory(context.Background(), eventDatasetMemory); err != nil {
		return nil, err
	}
	d := &diskEventDataset{storage: s, generation: generation, memoryBytes: eventDatasetMemory}
	b := &EventBuilder{d: d}
	defer func() {
		if err != nil {
			b.failure = err
			if cleanupErr := b.Abort(); cleanupErr != nil {
				builder, err = b, errors.Join(err, cleanupErr)
			}
		}
	}()
	if d.dir, err = os.MkdirTemp(s.limits.Directory, "lippycat-events-*"); err != nil {
		return nil, fmt.Errorf("create offline event directory: %w", err)
	}
	if d.data, err = os.OpenFile(filepath.Join(d.dir, "events.data"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600); err != nil {
		return nil, err
	}
	if d.offsets, err = os.OpenFile(filepath.Join(d.dir, "events.offsets"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600); err != nil {
		return nil, err
	}
	for _, stream := range []struct {
		file  *os.File
		magic [8]byte
	}{{d.data, eventDataMagic}, {d.offsets, eventOffsetMagic}} {
		h := eventStreamHeader(stream.magic, generation, 0)
		if err = d.write(stream.file, h[:]); err != nil {
			return nil, err
		}
	}
	d.dataBytes, d.offsetBytes = eventStreamHeaderBytes, eventStreamHeaderBytes
	return b, nil
}

func (d *diskEventDataset) write(file *os.File, payload []byte) error {
	if err := d.storage.reserveDisk(uint64(len(payload))); err != nil {
		return err
	}
	n, err := file.Write(payload)
	d.ownedBytes += uint64(n)
	d.storage.releaseDisk(uint64(len(payload) - n))
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write offline event storage: %w", err)
	}
	return nil
}

func (b *EventBuilder) Append(ctx context.Context, ev events.Event) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() {
		if err != nil && b.failure == nil {
			b.failure = err
		}
	}()
	if b.finished {
		return errors.New("offline event builder closed")
	}
	if b.failure != nil {
		return b.failure
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	d := b.d
	memory, err := eventObjectMemory(ev, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	if ev.Kind() == events.KindFileContent {
		return protoadapter.ErrFileContentDisallowed
	}
	reservation := uint64(4096)
	if err = addProduct(&reservation, memory, 4, d.storage.limits.CacheBytes); err != nil {
		return fmt.Errorf("offline event encode allocation: %w", err)
	}
	if err = d.storage.reserveMemory(ctx, reservation); err != nil {
		return err
	}
	defer d.storage.releaseMemory(reservation)
	wire, err := protoadapter.ToProto(ev)
	if err != nil {
		return fmt.Errorf("encode offline event: %w", err)
	}
	size := proto.Size(wire)
	if uint64(size)+eventFrameBytes > d.storage.limits.MaxRecordBytes || uint64(size) > math.MaxUint32 {
		return errors.New("offline event exceeds encoded record limit")
	}
	if uint64(size) > reservation {
		return errors.New("offline event encoder exceeded allocation reservation")
	}
	if d.count >= uint64((math.MaxInt64-eventStreamHeaderBytes)/eventOffsetBytes) || d.dataBytes > math.MaxInt64-uint64(size)-eventFrameBytes {
		return errors.New("offline event stream exceeds addressable file offsets")
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(wire)
	if err != nil {
		return fmt.Errorf("marshal offline event: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	id := EventRowID(d.count + 1)
	header := eventFrame(id, payload)
	if err = d.write(d.data, header[:]); err != nil {
		return err
	}
	if err = d.write(d.data, payload); err != nil {
		return err
	}
	var offset [eventOffsetBytes]byte
	binary.LittleEndian.PutUint64(offset[:8], d.dataBytes)
	binary.LittleEndian.PutUint64(offset[8:], eventFrameBytes+uint64(len(payload)))
	if err = d.write(d.offsets, offset[:]); err != nil {
		return err
	}
	d.dataBytes += eventFrameBytes + uint64(len(payload))
	d.offsetBytes += eventOffsetBytes
	d.count++
	return nil
}

func (b *EventBuilder) Finish(ctx context.Context) (result EventDataset, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer func() {
		if err != nil && b.failure == nil {
			b.failure = err
		}
	}()
	if b.finished {
		return nil, errors.New("offline event builder closed")
	}
	if b.failure != nil {
		return nil, b.failure
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	d := b.d
	for _, stream := range []struct {
		target **os.File
		magic  [8]byte
	}{{&d.data, eventDataMagic}, {&d.offsets, eventOffsetMagic}} {
		h := eventStreamHeader(stream.magic, d.generation, d.count)
		if _, err = (*stream.target).WriteAt(h[:], 0); err != nil {
			return nil, fmt.Errorf("finalize offline event header: %w", err)
		}
		if err = (*stream.target).Sync(); err != nil {
			return nil, fmt.Errorf("flush offline event stream: %w", err)
		}
		name := (*stream.target).Name()
		err = (*stream.target).Close()
		*stream.target = nil
		if err != nil {
			return nil, fmt.Errorf("close offline event writer: %w", err)
		}
		if *stream.target, err = os.Open(name); err != nil {
			return nil, fmt.Errorf("open completed offline event stream: %w", err)
		}
	}
	copy(d.completion[:8], eventManifestMagic[:])
	binary.LittleEndian.PutUint16(d.completion[8:10], EventSchemaVersion)
	binary.LittleEndian.PutUint16(d.completion[10:12], 1) // complete
	binary.LittleEndian.PutUint64(d.completion[16:24], uint64(d.generation))
	binary.LittleEndian.PutUint64(d.completion[24:32], d.count)
	binary.LittleEndian.PutUint64(d.completion[32:40], d.dataBytes)
	binary.LittleEndian.PutUint64(d.completion[40:48], d.offsetBytes)
	binary.LittleEndian.PutUint32(d.completion[48:52], eventChecksum(d.completion[:48], nil))
	temp := filepath.Join(d.dir, "events.manifest.tmp")
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	err = d.write(f, d.completion[:])
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, fmt.Errorf("publish offline event manifest: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	name := filepath.Join(d.dir, "events.manifest")
	if err = os.Rename(temp, name); err != nil {
		return nil, err
	}
	if d.manifest, err = os.Open(name); err != nil {
		return nil, err
	}
	if err = d.validate(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	b.finished, b.published = true, true
	return d, nil
}

// Abort joins readers and retries removal. After successful Finish ownership has
// transferred to EventDataset, so closing the builder does not close readers.
func (b *EventBuilder) Abort() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.published {
		return nil
	}
	b.finished = true
	return b.d.Close()
}

func (b *EventBuilder) Close() error { return b.Abort() }

func (d *diskEventDataset) Generation() DatasetGeneration { return d.generation }
func (d *diskEventDataset) Count() uint64                 { return d.count }
func (d *diskEventDataset) Resources() ResourceUsage      { return d.storage.Resources() }

func (d *diskEventDataset) validate() error {
	if d.closed {
		return errors.New("offline event dataset closed")
	}
	for _, stream := range []struct {
		file *os.File
		size uint64
		want []byte
	}{{d.data, d.dataBytes, nil}, {d.offsets, d.offsetBytes, nil}, {d.manifest, eventManifestBytes, d.completion[:]}} {
		if stream.file == nil {
			return errors.New("offline event storage is not complete")
		}
		info, err := stream.file.Stat()
		if err != nil {
			return fmt.Errorf("stat offline event stream: %w", err)
		}
		if uint64(info.Size()) != stream.size {
			return errors.New("corrupt offline event stream length")
		}
		if stream.want != nil {
			var header [eventManifestBytes]byte
			if _, err := stream.file.ReadAt(header[:], 0); err != nil {
				return err
			}
			if !bytes.Equal(header[:], stream.want) {
				return errors.New("corrupt offline event manifest")
			}
		}
	}
	for _, stream := range []struct {
		file  *os.File
		magic [8]byte
	}{{d.data, eventDataMagic}, {d.offsets, eventOffsetMagic}} {
		var header [eventStreamHeaderBytes]byte
		if _, err := stream.file.ReadAt(header[:], 0); err != nil {
			return err
		}
		want := eventStreamHeader(stream.magic, d.generation, d.count)
		if header != want {
			return errors.New("corrupt offline event stream header")
		}
	}
	return nil
}

func (d *diskEventDataset) Detail(ctx context.Context, token Token, id EventRowID) (*EventDetail, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if token.Dataset != d.generation {
		return nil, errors.New("offline event detail dataset generation mismatch")
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	if err := d.storage.reserveMemory(ctx, eventLeaseMemory+EventPresentationBytesPerRow); err != nil {
		return nil, err
	}
	record, held, err := d.readRecord(ctx, id)
	if err != nil {
		d.storage.releaseMemory(eventLeaseMemory + EventPresentationBytesPerRow)
		return nil, err
	}
	return &EventDetail{Record: record, lease: &eventLease{storage: d.storage, bytes: held + eventLeaseMemory + EventPresentationBytesPerRow}}, nil
}

func (d *diskEventDataset) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cleaned {
		return nil
	}
	d.closed = true
	var result error
	// Dataset's exclusive lock joins query scans, readers, and explicit pins.
	// Query cleanup retains its accounting/ownership until removal succeeds.
	// Query ownership is intrusive: each query's own reservation covers its
	// links, without retaining high-water map buckets after queries close.
	for q := d.queryHead; q != nil; {
		next := q.next
		result = errors.Join(result, q.closeLocked())
		q = next
	}
	for _, target := range []**os.File{&d.data, &d.offsets, &d.manifest} {
		if *target != nil {
			result = errors.Join(result, (*target).Close())
			*target = nil
		}
	}
	if d.dir != "" {
		if err := os.RemoveAll(d.dir); err != nil {
			return errors.Join(result, fmt.Errorf("remove private offline event session: %w", err))
		}
	}
	// RemoveAll also settles files whose individual query cleanup failed.
	d.queryMu.Lock()
	for q := d.queryHead; q != nil; {
		next := q.next
		q.finishCleanup()
		q.previous, q.next, q.registered = nil, nil, false
		q = next
	}
	d.queryHead, d.queryCount = nil, 0
	d.queryMu.Unlock()
	d.storage.releaseDisk(d.ownedBytes)
	d.storage.releaseMemory(d.memoryBytes)
	d.ownedBytes, d.memoryBytes = 0, 0
	d.cleaned = true
	return result
}
