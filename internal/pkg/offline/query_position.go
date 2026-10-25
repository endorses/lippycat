package offline

import "context"

// Position locates a stable packet ID in this immutable ordered snapshot.
// Identity projections are arithmetic; filtered vectors use bounded ReadAt
// binary search, without loading matches or scanning them into the frontend.
func (q *diskQuery) Position(ctx context.Context, id PacketID) (uint64, bool, error) {
	d := q.dataset
	d.mu.RLock()
	defer d.mu.RUnlock()
	q.mu.RLock()
	defer q.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	if err := q.validate(); err != nil {
		return 0, false, err
	}
	if q.identity {
		if uint64(id) < q.count {
			return uint64(id), true, nil
		}
		return 0, false, nil
	}
	lo, hi := uint64(0), q.count
	for lo < hi {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		mid := lo + (hi-lo)/2
		candidate, err := q.idAt(mid)
		if err != nil {
			return 0, false, err
		}
		if candidate == id {
			return mid, true, nil
		}
		if candidate < id {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return 0, false, ctx.Err()
}
