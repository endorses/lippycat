//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineExportRejectsUnrepresentableTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stamp time.Time
	}{
		{"missing", time.Time{}},
		{"before_epoch", time.Unix(-1, 999999999)},
		{"after_pcap_range", time.Unix(1<<32, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "existing.pcap")
			require.NoError(t, os.WriteFile(path, []byte("existing"), 0600))
			_, err := exportOfflinePCAP(context.Background(), path, func(_ context.Context, visit func(offline.RawRecord) error) error {
				if err := visit(exportTestRaw(0)); err != nil {
					return err
				}
				d := exportTestRaw(1)
				d.Timestamp = tc.stamp
				return visit(d)
			})
			require.ErrorContains(t, err, "timestamp")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "existing", string(raw))
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestOfflineExportTimestampRangeBoundaries(t *testing.T) {
	for _, stamp := range []time.Time{time.Unix(0, 0), time.Unix(1<<32-1, 999999999)} {
		t.Run(stamp.UTC().Format(time.RFC3339Nano), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "boundary.pcap")
			count, err := exportOfflinePCAP(context.Background(), path, func(_ context.Context, visit func(offline.RawRecord) error) error {
				d := exportTestRaw(0)
				d.Timestamp = stamp
				return visit(d)
			})
			require.NoError(t, err)
			require.Equal(t, uint64(1), count)
			f, err := os.Open(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, f.Close()) }()
			r, err := pcapgo.NewReader(f)
			require.NoError(t, err)
			_, ci, err := r.ReadPacketData()
			require.NoError(t, err)
			require.True(t, stamp.Equal(ci.Timestamp), "expected %s, got %s", stamp, ci.Timestamp)
		})
	}
}
