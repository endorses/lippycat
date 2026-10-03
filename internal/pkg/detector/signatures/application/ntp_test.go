package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func TestNTPDetectorUsesTypedTimeDecoder(t *testing.T) {
	p := make([]byte, 48)
	p[0], p[1], p[2], p[3] = 4<<3|3, 16, 255, 127
	ctx := &signatures.DetectionContext{Transport: "UDP", DstPort: 123, Payload: p}
	r := NewNTPSignature().Detect(ctx)
	require.NotNil(t, r)
	require.Equal(t, int8(-1), r.Metadata["poll"])
	require.Equal(t, int8(127), r.Metadata["precision"])
	for _, mode := range []byte{0, 6, 7} {
		p[0] = 4<<3 | mode
		require.Nil(t, NewNTPSignature().Detect(ctx))
	}
	p[0] = 4<<3 | 3
	ctx.Payload = append(p, 1)
	require.Nil(t, NewNTPSignature().Detect(ctx))
	ctx.Payload, ctx.Transport = p, "TCP"
	require.Nil(t, NewNTPSignature().Detect(ctx))
}
