package offline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactAuditRejectInvalidContextBeforePublication(t *testing.T) {
	for _, mode := range []string{"format", "byte-order", "link-type"} {
		t.Run(mode, func(t *testing.T) {
			_, b, detail, provenance := compactReviewBuilder(t)
			switch mode {
			case "format":
				provenance.Context.Format = CaptureFormatPCAPNG + 1
			case "byte-order":
				provenance.Context.ByteOrder = CaptureBigEndian + 1
			case "link-type":
				provenance.Context.LinkType = 256
			}
			require.Error(t, b.AppendCompact(context.Background(), detail, provenance))
			require.Error(t, b.AppendCompact(context.Background(), detail, provenance))
			_, err := b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
		})
	}
}

func TestCompactAuditRejectInvalidAmendments(t *testing.T) {
	for _, mode := range []string{"length", "captured-length", "source-argument", "source-path", "raw-bytes", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			_, b, detail, provenance := compactReviewBuilder(t)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := b.UpdateDetail(ctx, 0, func(d *Detail) error {
				switch mode {
				case "length":
					d.Packet.Length = -1
				case "captured-length":
					d.CapturedLength++
				case "source-argument":
					d.Source.ArgumentIndex++
				case "source-path":
					d.Source.Path += ".other"
				case "raw-bytes":
					d.Packet.RawData[0] ^= 0xff
				case "cancelled":
					cancel()
				}
				return nil
			})
			require.Error(t, err)
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
		})
	}
}

func TestCompactAuditAmendmentReservesCallbackScratch(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.NoError(t, b.flushCompact())
	// Warm the exact read path so cached blocks do not change the ledger when
	// UpdateDetail subsequently loads the same detail and source row.
	_, detailHeld, err := b.d.readDetail(context.Background(), 0)
	require.NoError(t, err)
	_, _, rowHeld, err := b.d.readCompactRow(context.Background(), 0, false)
	require.NoError(t, err)
	s.releaseMemory(detailHeld + rowHeld)
	baseline := s.Resources().InFlightBytes
	require.NoError(t, b.UpdateDetail(context.Background(), 0, func(d *Detail) error {
		require.GreaterOrEqual(t, s.Resources().InFlightBytes, baseline+detailHeld+rowHeld+s.limits.MaxRecordBytes,
			"the callback's allowed growth must be admitted before invocation")
		d.Packet.Info = "amended"
		return nil
	}))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataset.Close()) })
	got, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	require.Equal(t, "amended", got.Packet.Info)
}
