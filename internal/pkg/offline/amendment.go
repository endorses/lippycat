package offline

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// UpdateDetail finalizes deferred analyzer metadata before Finish. It reads one
// packet, invokes mutate, appends replacement frames, and updates its on-disk
// offset entry. Superseded frames remain charged until the session is removed.
// The callback must keep allocations within MaxRecordBytes and must not retain
// the detail. Packet identity is preserved. Any error poisons the builder.
func (b *Builder) UpdateDetail(ctx context.Context, id PacketID, mutate func(*Detail) error) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return errors.New("offline builder closed")
	}
	if b.failure != nil {
		return b.failure
	}
	defer func() {
		if err != nil {
			b.failure = err
		}
	}()
	if mutate == nil {
		return errors.New("offline detail update callback is required")
	}
	d := b.d
	detail, held, err := d.readDetail(ctx, id)
	if err != nil {
		return err
	}
	defer func() { d.storage.releaseMemory(held) }()
	// Cover the decoded detail, callback growth, summary and both serializers.
	reservation := 4*d.storage.limits.MaxRecordBytes + 2*frameHeaderBytes
	if err = d.storage.reserveMemory(ctx, reservation-held); err != nil {
		return err
	}
	held = reservation
	if err = mutate(&detail); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	detail.ID, detail.Token = id, Token{}
	if detail.Packet.Length < 0 {
		return errors.New("offline packet length must be nonnegative")
	}
	summary := NewSummary(id, detail.Packet)
	if _, err = recordMemory(summary, d.storage.limits.MaxRecordBytes); err != nil {
		return err
	}
	if _, err = recordMemory(detail, d.storage.limits.MaxRecordBytes); err != nil {
		return err
	}
	so, do := b.summaryEnd, b.detailEnd
	sn, err := writeRecord(&builderWriter{b: b, f: d.summaries}, 1, id, summary, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	dn, err := writeRecord(&builderWriter{b: b, f: d.details}, 2, id, detail, d.storage.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	var offset [32]byte
	for i, value := range [...]uint64{uint64(so), sn, uint64(do), dn} {
		binary.LittleEndian.PutUint64(offset[i*8:], value)
	}
	n, err := d.offsets.WriteAt(offset[:], 16+int64(id)*32)
	if err != nil {
		return fmt.Errorf("update offline packet offsets: %w", err)
	}
	if n != len(offset) {
		return io.ErrShortWrite
	}
	d.storage.mu.Lock()
	for _, kind := range [...]uint16{1, 2} {
		if entry := d.storage.cache[cacheKey{dataset: d, id: id, kind: kind}]; entry != nil {
			d.storage.removeCacheLocked(entry)
		}
	}
	d.storage.mu.Unlock()
	b.summaryEnd += sn
	b.detailEnd += dn
	b.amended = true
	return nil
}

// An amended packet may change any statistics field, including bounded key
// membership and min/max. Rebuild once from the final disk summaries so totals
// never include both old and replacement frames, without retaining an ID slice.
func (b *Builder) rebuildStatistics(ctx context.Context) error {
	accumulator := newStatisticsAccumulator()
	for id := PacketID(0); uint64(id) < b.d.count; id++ {
		summary, held, err := b.d.readSummary(ctx, id)
		if err != nil {
			return err
		}
		if uint64(summary.packet.Length) > ^uint64(0)-accumulator.stats.Bytes {
			b.d.storage.releaseMemory(held)
			return errors.New("offline packet byte total exceeds uint64 range")
		}
		accumulator.Add(summary)
		b.d.storage.releaseMemory(held)
	}
	b.accumulator = accumulator
	return nil
}
