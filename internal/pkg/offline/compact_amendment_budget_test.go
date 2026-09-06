package offline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactAmendedCombinedDetailBudget(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		name := "within-budget"
		if oversized {
			name = "oversized"
		}
		t.Run(name, func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			ctx := context.Background()
			detail.Packet.Info = strings.Repeat("i", 30000)
			for range 3 {
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
			}
			body := strings.Repeat("b", 10000)
			if oversized {
				body = strings.Repeat("b", 40000)
			}
			// Amend in reverse order to exercise both ends of the validation range.
			require.NoError(t, b.AmendVoIP(ctx, 2, "SIP", detail.Packet.Info, &types.VoIPMetadata{Body: body}))
			require.NoError(t, b.AmendVoIP(ctx, 0, "SIP", detail.Packet.Info, &types.VoIPMetadata{}))
			d, err := b.Finish(ctx)
			if oversized {
				require.ErrorContains(t, err, "validate amended compact detail 2")
				require.ErrorContains(t, err, "allocation limit")
				require.Nil(t, d)
				_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
				require.ErrorIs(t, err, os.ErrNotExist)
				_, err = b.Finish(ctx)
				require.Error(t, err, "failed finalization must poison the builder")
				require.NoError(t, b.Close())
			} else {
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, d.Close()) })
				got, err := d.Detail(ctx, Token{Dataset: 17}, 2)
				require.NoError(t, err)
				require.Equal(t, body, got.Packet.VoIPData.Body)
				require.NoError(t, d.Close())
			}
			require.Zero(t, s.Resources().InFlightBytes)
			require.Zero(t, s.Resources().DiskBytes)
		})
	}
}
