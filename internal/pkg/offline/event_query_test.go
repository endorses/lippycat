package offline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestEventQueryCancellationFailureAndPageMemoryBounds(t *testing.T) {
	s, d := eventStorageDataset(t, 600)
	base := s.Resources()
	ctx, cancel := context.WithCancel(context.Background())
	predicate, err := eventquery.Compile("kind:dns")
	require.NoError(t, err)
	_, err = d.Query(ctx, EventQuerySpec{Token: Token{Revision: CompletedRevision, Dataset: 7, Query: 2}, Match: predicate, Progress: func(p QueryProgress) {
		if p.Scanned >= 256 {
			cancel()
		}
	}})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, base, s.Resources())
	require.Zero(t, d.queryCount)
	q, err := AllEvents(context.Background(), d, Token{Revision: CompletedRevision, Dataset: 7, Query: 1})
	require.NoError(t, err)
	installed := s.Resources()
	callbackErr := errors.New("consumer failed")
	require.ErrorIs(t, q.Iterate(context.Background(), func(EventRecord) error { return callbackErr }), callbackErr)
	require.Equal(t, installed, s.Resources())
	ctx, cancel = context.WithCancel(context.Background())
	visited := 0
	err = q.Iterate(ctx, func(EventRecord) error { visited++; cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, visited)
	require.Equal(t, installed, s.Resources())
	_, err = q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 1, MaxBytes: 100})
	require.Error(t, err)
	require.Equal(t, installed, s.Resources())
	// A large requested row count cannot consume the entire small byte cap in
	// empty row slots. Return a bounded nonempty prefix when one record fits.
	page, err := q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 1000, MaxBytes: 2048})
	require.NoError(t, err)
	require.NotEmpty(t, page.Rows)
	require.LessOrEqual(t, s.Resources().InFlightBytes-installed.InFlightBytes, uint64(2048))
	require.NoError(t, page.Close())
	require.Equal(t, installed, s.Resources())
	reservation, err := s.ReserveTransient(context.Background(), s.MemoryLimit()-s.Resources().InFlightBytes-100)
	require.NoError(t, err)
	_, err = d.Detail(context.Background(), Token{Revision: CompletedRevision, Dataset: 7}, 1)
	require.Error(t, err)
	require.NoError(t, reservation.Close())
	require.Equal(t, installed, s.Resources())
	require.NoError(t, q.Close())
	require.Equal(t, base, s.Resources())
}

func TestEventQueryQuotaFailureAndCleanupRemainOwned(t *testing.T) {
	s, d := eventStorageDataset(t, 20)
	base := s.Resources()
	s.limits.DiskBytes = base.DiskBytes + eventQueryHeaderBytes + eventQueryEntryBytes
	predicate, err := eventquery.Compile("kind:dns")
	require.NoError(t, err)
	_, err = d.Query(context.Background(), EventQuerySpec{Token: Token{Revision: CompletedRevision, Dataset: 7, Query: 2}, Match: predicate})
	require.Error(t, err)
	require.Equal(t, base, s.Resources())
	require.Zero(t, d.queryCount)
	s.limits.DiskBytes = 8 << 20
	value, err := d.Query(context.Background(), EventQuerySpec{Token: Token{Revision: CompletedRevision, Dataset: 7, Query: 3}, Match: predicate})
	require.NoError(t, err)
	q := value.(*diskEventQuery)
	withQuery := s.Resources()
	// A nonempty directory at the owned query pathname makes Remove fail on
	// every platform, including tests run as root, without production hooks.
	saved := q.path + ".saved"
	require.NoError(t, os.Rename(q.path, saved))
	require.NoError(t, os.Mkdir(q.path, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(q.path, "block"), []byte("x"), 0600))
	require.Error(t, q.Close())
	require.True(t, q.registered)
	require.Equal(t, withQuery, s.Resources(), "failed removal retains both disk and query ownership")
	require.NoError(t, os.RemoveAll(q.path))
	require.NoError(t, os.Rename(saved, q.path))
	require.NoError(t, q.Close())
	require.NoError(t, q.Close())
	require.Equal(t, base, s.Resources())
}

func TestEventQueryCorruptionRejectsHeaderAndMatchRows(t *testing.T) {
	for _, corruption := range []string{"header", "length", "id", "order"} {
		t.Run(corruption, func(t *testing.T) {
			s, d := eventStorageDataset(t, 6)
			predicate, err := eventquery.Compile("kind:dns")
			require.NoError(t, err)
			value, err := d.Query(context.Background(), EventQuerySpec{Token: Token{Revision: CompletedRevision, Dataset: 7, Query: 2}, Match: predicate})
			require.NoError(t, err)
			q := value.(*diskEventQuery)
			f := eventStorageWritable(t, q.file)
			switch corruption {
			case "header":
				_, err = f.WriteAt([]byte{255}, 8)
			case "length":
				err = f.Truncate(int64(q.bytes - 1))
			case "id":
				_, err = f.WriteAt([]byte{5}, eventQueryHeaderBytes)
			case "order":
				entry := eventQueryEntry(1, 1)
				_, err = f.WriteAt(entry[:], eventQueryHeaderBytes+eventQueryEntryBytes)
			}
			require.NoError(t, err)
			before := s.Resources()
			_, err = q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 6, MaxBytes: 16 << 10})
			require.Error(t, err)
			require.Equal(t, before, s.Resources())
			require.NoError(t, q.Close())
		})
	}
}

func TestEventQueryPinJoinsCloseAndReadsBehindPendingClose(t *testing.T) {
	for _, target := range []string{"query", "dataset"} {
		t.Run(target, func(t *testing.T) {
			_, d := eventStorageDataset(t, 10)
			q, err := AllEvents(context.Background(), d, Token{Revision: CompletedRevision, Dataset: 7, Query: 1})
			require.NoError(t, err)
			pin, err := PinEventQuery(q)
			require.NoError(t, err)
			defer func() { require.NoError(t, pin.Close()) }()
			started, closed := make(chan struct{}), make(chan error, 1)
			go func() {
				close(started)
				if target == "query" {
					closed <- q.Close()
				} else {
					closed <- d.Close()
				}
			}()
			<-started
			select {
			case err := <-closed:
				t.Fatalf("pin failed to retain %s: %v", target, err)
			case <-time.After(20 * time.Millisecond):
			}
			read := make(chan error, 1)
			go func() {
				page, err := pin.Page(context.Background(), PageRequest{Token: pin.Token(), Row: 8, Limit: 2, MaxBytes: 16 << 10})
				if err == nil {
					if len(page.Rows) != 2 || page.Rows[0].ID != 9 || page.Rows[1].ID != 10 {
						err = errors.New("pin returned incorrect final rows")
					}
					err = errors.Join(err, page.Close())
				}
				if err == nil {
					var rows int
					err = pin.Iterate(context.Background(), func(EventRecord) error { rows++; return nil })
					if err == nil && rows != 10 {
						err = errors.New("pin returned incomplete iteration")
					}
				}
				read <- err
			}()
			select {
			case err := <-read:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("pin read deadlocked behind pending close")
			}
			require.NoError(t, pin.Close())
			require.NoError(t, pin.Close())
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("close did not join released pin")
			}
			require.Error(t, pin.Iterate(context.Background(), func(EventRecord) error { return nil }))
			_, err = PinEventQuery(q)
			require.Error(t, err)
		})
	}
}

func TestEventDatasetCloseRetriesFailedRemovalAccounting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	s, d := eventStorageDataset(t, 3)
	base := s.Resources()
	require.NoError(t, os.Chmod(s.limits.Directory, 0500))
	t.Cleanup(func() { require.NoError(t, os.Chmod(s.limits.Directory, 0700)) })
	require.Error(t, d.Close())
	require.Equal(t, base, s.Resources())
	require.Error(t, s.Close())
	require.NoError(t, os.Chmod(s.limits.Directory, 0700))
	require.NoError(t, d.Close())
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
	_, err := d.Detail(context.Background(), Token{Revision: CompletedRevision, Dataset: 7}, 1)
	require.Error(t, err)
}

func TestEventBuilderCancellationNeverPublishesPrefix(t *testing.T) {
	for _, stage := range []string{"append", "finish"} {
		t.Run(stage, func(t *testing.T) {
			s := newTestStorage(t)
			b, err := s.NewEventBuilder(1)
			require.NoError(t, err)
			require.NoError(t, b.Append(context.Background(), eventStorageDNS(1)))
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if stage == "append" {
				require.ErrorIs(t, b.Append(ctx, eventStorageDNS(2)), context.Canceled)
			}
			_, err = b.Finish(ctx)
			require.ErrorIs(t, err, context.Canceled)
			_, err = b.Finish(context.Background())
			require.ErrorIs(t, err, context.Canceled)
			require.NoError(t, b.Abort())
			require.NoError(t, s.Close())
		})
	}
}

func TestEventDetailMutationDoesNotChangeDiskSnapshot(t *testing.T) {
	s := newTestStorage(t)
	b, err := s.NewEventBuilder(1)
	require.NoError(t, err)
	e := events.NewHTTPEvent(eventStorageEnvelope(1))
	e.Headers = map[string][]string{"x": {"original"}}
	require.NoError(t, b.Append(context.Background(), e))
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	a, err := d.Detail(context.Background(), Token{Revision: CompletedRevision, Dataset: 1}, 1)
	require.NoError(t, err)
	a.Record.Event.(events.HTTPEvent).Headers["x"][0] = "changed"
	c, err := d.Detail(context.Background(), Token{Revision: CompletedRevision, Dataset: 1}, 1)
	require.NoError(t, err)
	require.Equal(t, "original", c.Record.Event.(events.HTTPEvent).Headers["x"][0])
	require.NoError(t, a.Close())
	require.NoError(t, c.Close())
	require.NoError(t, d.Close())
	require.NoError(t, s.Close())
}
