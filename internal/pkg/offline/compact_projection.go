package offline

import (
	"context"
	"reflect"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// materializeCompactSummary admits the fixed projection objects before creating
// them. Projection strings borrow the already charged compact row; no text is
// copied. The caller keeps both reservations until transferring the final value.
func (d *diskDataset) materializeCompactSummary(ctx context.Context, row compactRow, id PacketID) (Summary, uint64, error) {
	n := uint64(reflect.TypeOf(Summary{}).Size())
	p := row.Projection
	if p.Presence&1 != 0 {
		n += uint64(reflect.TypeOf(types.VoIPMetadata{}).Size())
	}
	if p.Presence&2 != 0 {
		n += uint64(reflect.TypeOf(types.DNSMetadata{}).Size())
		if p.AnswerPresent {
			n += uint64(reflect.TypeOf(types.DNSAnswer{}).Size())
		}
	}
	if p.Presence&4 != 0 {
		n += uint64(reflect.TypeOf(types.EmailMetadata{}).Size())
	}
	if p.Presence&8 != 0 {
		n += uint64(reflect.TypeOf(types.TLSMetadata{}).Size())
	}
	if p.Presence&16 != 0 {
		n += uint64(reflect.TypeOf(types.HTTPMetadata{}).Size())
	}
	if err := d.storage.reserveMemory(ctx, n); err != nil {
		return Summary{}, 0, err
	}
	return row.summary(id), n, nil
}
