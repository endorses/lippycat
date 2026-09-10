package records

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	"github.com/stretchr/testify/require"
)

func TestRADIUSLogsBothFormatsAndDrains(t *testing.T) {
	for _, format := range []logstream.Format{logstream.FormatTSV, logstream.FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			dir := t.TempDir()
			var offset atomic.Int64
			rotated := make(chan string, 1)
			base := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
			sink, err := logstream.New(logstream.Config{Directory: dir, Format: format, QueueSize: 8,
				RotateInterval: 20 * time.Millisecond, Now: func() time.Time { return base.Add(time.Duration(offset.Load())) },
				PostRotate: func(_ context.Context, path string) error {
					select {
					case rotated <- path:
					default:
					}
					return nil
				},
			})
			require.NoError(t, err)
			require.NoError(t, sink.Register(events.KindRADIUS, "radius", RADIUS))
			require.NoError(t, sink.Start(context.Background()))
			event := events.NewRADIUSEvent(events.Envelope{Timestamp: time.Unix(1, 0)})
			event.Code, event.Identifier, event.Association = 2, 255, "unique"
			event.RequestInstanceID = "opaque-request"
			event.Attributes = []string{}
			require.NoError(t, sink.HandleEvent(context.Background(), event))
			require.NoError(t, sink.Flush(context.Background()))
			offset.Store(int64(time.Second))
			select {
			case path := <-rotated:
				archived, readErr := os.ReadFile(path)
				require.NoError(t, readErr)
				require.Contains(t, string(archived), "opaque-request")
			case <-time.After(time.Second):
				t.Fatal("radius log did not rotate")
			}
			require.NoError(t, sink.HandleEvent(context.Background(), event))
			require.NoError(t, sink.Close(context.Background()))
			output, err := os.ReadFile(filepath.Join(dir, "radius.log"))
			require.NoError(t, err)
			require.Contains(t, string(output), "opaque-request")
			if format == logstream.FormatJSON {
				var record map[string]any
				require.NoError(t, json.Unmarshal(output, &record))
				require.Equal(t, float64(2), record["code"])
				require.Equal(t, "unique", record["association"])
				require.Empty(t, record["attributes"])
			} else {
				require.Contains(t, string(output), "#path\tradius\n")
				require.Contains(t, string(output), "#close\t")
			}
			_, err = os.Stat(filepath.Join(dir, "dns.log"))
			require.True(t, os.IsNotExist(err))
		})
	}
}
