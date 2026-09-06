package offline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
)

// ReadBatch returns packet slices sharing one owned, byte-bounded lease. Nearby
// ascending locators on one backing are read together, including small headers
// between packet payloads. Callers must release the lease after using every slice.
func (r *BackingRegistry) ReadBatch(ctx context.Context, locs []Locator, maxBytes uint64) (*BackingLease, [][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, nil, errors.New("offline backings closed")
	}
	if r.failure != nil {
		return nil, nil, r.failure
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	type span struct {
		first, last int
		id          uint32
		start, end  int64
	}
	// At most 64 references keeps descriptor and returned-slice overhead bounded.
	if len(locs) > 64 {
		return nil, nil, errors.New("offline read batch locator limit exceeded")
	}
	var spans [64]span
	count := 0
	var total uint64
	var payloadBytes uint64
	for _, loc := range locs {
		if uint64(loc.Length) > maxBytes-payloadBytes {
			return nil, nil, errors.New("offline read batch byte limit exceeded")
		}
		payloadBytes += uint64(loc.Length)
	}
	gapBudget := maxBytes - payloadBytes
	for i, loc := range locs {
		if loc.BackingID == 0 || uint64(loc.BackingID) > uint64(len(r.entries)) || loc.Offset < 0 || uint64(loc.Length) > r.storage.limits.MaxRecordBytes {
			return nil, nil, ErrInvalidLocator
		}
		b := r.entries[loc.BackingID-1]
		if loc.Offset > b.size || int64(loc.Length) > b.size-loc.Offset {
			return nil, nil, ErrInvalidLocator
		}
		n := uint64(loc.Length)
		if total > maxBytes || n > maxBytes-total {
			return nil, nil, errors.New("offline read batch byte limit exceeded")
		}
		end := loc.Offset + int64(loc.Length)
		merged := false
		if count > 0 {
			prev := &spans[count-1]
			gap := loc.Offset - prev.end
			if prev.id == loc.BackingID && gap >= 0 && gap <= 4096 && uint64(gap) <= gapBudget {
				prev.last = i
				prev.end = end
				total += n + uint64(gap)
				gapBudget -= uint64(gap)
				merged = true
			}
		}
		if !merged {
			spans[count] = span{i, i, loc.BackingID, loc.Offset, end}
			count++
			total += n
		}
	}
	if total > uint64(math.MaxInt) {
		return nil, nil, ErrInvalidLocator
	}
	charge := total + 128 + uint64(len(locs))*24 + 64*40
	if err := r.storage.reserveMemory(ctx, charge); err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*BackingLease, [][]byte, error) {
		r.storage.releaseMemory(charge)
		return nil, nil, err
	}
	data := make([]byte, int(total))
	packets := make([][]byte, len(locs))
	offset := 0
	for _, span := range spans[:count] {
		b := r.entries[span.id-1]
		if err := r.check(b, span.id, "read"); err != nil {
			return fail(err)
		}
		length := int(span.end - span.start)
		if _, err := b.file.ReadAt(data[offset:offset+length], span.start); err != nil {
			if b.scratch == nil {
				return fail(r.changed(b, span.id, "read", "short_read", err))
			}
			return fail(fmt.Errorf("%w: %v", ErrInvalidLocator, err))
		}
		for i := span.first; i <= span.last; i++ {
			loc := locs[i]
			start := offset + int(loc.Offset-span.start)
			packet := data[start : start+int(loc.Length) : start+int(loc.Length)]
			if sha256.Sum256(packet) != loc.Digest {
				if b.scratch == nil {
					return fail(r.changed(b, span.id, "read", "digest", nil))
				}
				return fail(fmt.Errorf("%w: digest mismatch", ErrInvalidLocator))
			}
			packets[i] = packet
		}
		if err := r.check(b, span.id, "read"); err != nil {
			return fail(err)
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		offset += length
	}
	r.leases++
	return &BackingLease{Bytes: data, registry: r, size: charge}, packets, nil
}
