//go:build li && linux

package delivery

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestX3ShortenedCutoffRejectsReorderedPermit(t *testing.T) {
	for _, journal := range []bool{false, true} {
		name := "memory"
		if journal {
			name = "journal"
		}
		t.Run(name, func(t *testing.T) {
			cfg, manager, did, xid, metadata, data := x3ClientFixture(t)
			cfg.AuthoritativeTaskAuthorization = true
			if !journal {
				cfg.X3SpoolDir, cfg.X3SpoolKeyFile, cfg.X3SpoolKeyID = "", "", ""
				cfg.X3SpoolMaxBytes = 0
			}
			c := NewClient(manager, cfg)
			require.NoError(t, c.Err())
			defer c.Stop()
			c.PublishX3TaskAuthorization(authorizationTask(xid, metadata.TaskGeneration, time.Now().Add(time.Hour)))
			permit, err := c.PrepareX3(xid, did, data, metadata)
			require.NoError(t, err)
			var emitted error
			buffer := NewCallAwareReorderBuffer(func(entry ReorderEntry) {
				if entry.Accepted != nil {
					emitted = c.SendAcceptedX3(entry.Accepted)
				}
			}, time.Hour)
			t.Cleanup(func() { buffer.Discard(); buffer.Wait() })
			// Establish the stream, then hold an admitted product behind a gap.
			buffer.DeliverEntryX3AfterCommit(ReorderEntry{}, 42, 1, nil)
			buffer.DeliverEntryX3AfterCommit(ReorderEntry{Accepted: permit}, 42, 3, nil)
			count, _ := buffer.Buffered()
			require.Equal(t, 1, count)
			c.SetX3TaskAuthorization(xid, metadata.TaskGeneration, time.Now().Add(-time.Second))
			buffer.Stop()
			buffer.Wait()
			require.Error(t, emitted, "a delayed reorder callback cannot deliver after the shortened cutoff")
			require.Zero(t, c.QueueDepth())
			require.Zero(t, c.Stats().X3Queued)
			if journal {
				require.Zero(t, c.X3JournalStats().Persisted)
			}
		})
	}
}
