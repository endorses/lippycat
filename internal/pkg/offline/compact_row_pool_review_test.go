package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactRowPoolKeepsFirstRowAdmissionHeadroom(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 16 << 20
	ctx := context.Background()
	require.NoError(t, b.AppendCompact(ctx, detail, provenance))
	require.NoError(t, b.flushCompact())
	// Reproduce a builder with initialized registries and no optional buffers,
	// as after earlier pooling admission failed beside another retained session.
	b.d.releaseCompactBuffers()
	const poolBytes = compactRows * compactRowSlotBytes
	rowScratch := s.limits.MaxRecordBytes*5 + 4096
	held := s.limits.CacheBytes - s.Resources().InFlightBytes - rowScratch - poolBytes - 31
	require.NoError(t, s.reserveMemory(ctx, held))
	defer s.releaseMemory(held)
	// The ordinary exact-sized row easily fits. An optional pool must not
	// consume the space its first descriptor needs and turn this into failure.
	require.NoError(t, b.AppendCompact(ctx, detail, provenance))
}
