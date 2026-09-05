package offline

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func queryDataset(t *testing.T, count int) *diskDataset {
	t.Helper()
	s, err := NewStorage(ResourceLimits{Directory: t.TempDir(), DiskBytes: 16 << 20, CacheBytes: 1 << 20, MaxRecordBytes: 16 << 10, MaxSources: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.NewBuilder(7, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		if err := b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: i + 1, Protocol: "UDP", Transport: 17, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "1", DstPort: "2", Timestamp: time.Unix(int64(i), 0)}}); err != nil {
			t.Fatal(err)
		}
	}
	dataset, err := b.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := dataset.(*diskDataset)
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return d
}

func TestQueryCancellationFailureAndCleanup(t *testing.T) {
	d := queryDataset(t, 50)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 1}
	first, err := d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	baseline := d.Resources().DiskBytes
	cctx, cancel := context.WithCancel(ctx)
	_, err = d.Query(cctx, QuerySpec{Token: Token{Dataset: 7, Query: 2}, Match: func(s Summary) bool {
		if s.ID == 15 {
			cancel()
		}
		return true
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if d.Resources().DiskBytes != baseline {
		t.Fatal("cancel leaked disk")
	}
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("unfinished query: %s", e.Name())
		}
	}
	d.storage.mu.Lock()
	d.storage.limits.DiskBytes = baseline + 30
	d.storage.mu.Unlock()
	_, err = d.Query(ctx, QuerySpec{Token: Token{Dataset: 7, Query: 3}})
	if err == nil {
		t.Fatal("expected budget failure")
	}
	if first.Count() != 50 || first.Statistics().Packets != 50 {
		t.Fatal("failed replacement affected previous query")
	}
	page, err := first.Page(ctx, PageRequest{Token: token, Limit: 1, MaxBytes: 16 << 10})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("previous query unreadable: %v", err)
	}
	if err := page.Close(); err != nil {
		t.Fatal(err)
	}
	if d.Resources().DiskBytes != baseline {
		t.Fatal("failure leaked disk")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQueryEmptyCorruptionAndReaderJoin(t *testing.T) {
	d := queryDataset(t, 3)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 1}
	empty, err := d.Query(ctx, QuerySpec{Token: token, Match: func(Summary) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if empty.Count() != 0 || empty.Statistics().Packets != 0 {
		t.Fatal("nonempty query")
	}
	if err := empty.Iterate(ctx, func(Detail) error { return errors.New("should not visit") }); err != nil {
		t.Fatal(err)
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	q, err := d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	entered, release, iterDone, closeDone := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan error, 1)
	go func() {
		iterDone <- q.Iterate(ctx, func(Detail) error {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
			return nil
		})
	}()
	<-entered
	go func() { closeDone <- q.Close() }()
	select {
	case <-closeDone:
		t.Fatal("closed during active read")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-iterDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	q, err = d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(q.(*diskQuery).path, queryHeaderBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Page(ctx, PageRequest{Token: token, Limit: 1, MaxBytes: 16 << 10}); err == nil {
		t.Fatal("accepted corrupt query")
	}
}

func TestRelatedFlowParity(t *testing.T) {
	f := Flow{Source: netip.MustParseAddrPort("192.0.2.1:1"), Destination: netip.MustParseAddrPort("192.0.2.2:2"), Transport: 17, Node: "Local"}
	base := types.PacketDisplay{SrcIP: "::ffff:192.0.2.2", DstIP: "192.0.2.1", SrcPort: "2", DstPort: "1", Protocol: "UDP"}
	for _, tc := range []struct {
		name string
		edit func(*types.PacketDisplay)
		want bool
	}{
		{"reverse mapped wildcard node", func(*types.PacketDisplay) {}, true},
		{"unknown transport", func(p *types.PacketDisplay) { p.Protocol = "DNS" }, true},
		{"other transport", func(p *types.PacketDisplay) { p.Transport = 6 }, false},
		{"invalid transport", func(p *types.PacketDisplay) { p.Transport = 1 }, false},
		{"wrong node", func(p *types.PacketDisplay) { p.NodeID = "remote" }, false},
		{"zero port", func(p *types.PacketDisplay) { p.SrcPort = "0" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.edit(&p)
			if got := matchesFlow(NewSummary(0, p), f); got != tc.want {
				t.Fatalf("match %v", got)
			}
		})
	}
	d := queryDataset(t, 80)
	q, err := d.Related(context.Background(), Token{Dataset: 7, Query: 9}, f)
	if err != nil {
		t.Fatal(err)
	}
	if q.Count() != 80 {
		t.Fatalf("related count %d", q.Count())
	}
}

func TestStatisticsBoundsAndSnapshot(t *testing.T) {
	a := newStatisticsAccumulator()
	for i := 0; i < 11000; i++ {
		a.Add(NewSummary(PacketID(i), types.PacketDisplay{Length: 10, SrcIP: fmt.Sprint(i), DstIP: fmt.Sprint(i), Protocol: fmt.Sprint(i), Timestamp: time.Unix(int64(i), 0)}))
	}
	s := a.Snapshot()
	if s.Packets != 11000 || s.Bytes != 110000 || len(s.Protocols) != 1000 || s.Sources != 10000 || s.Destinations != 10000 || len(s.TruncatedCardinality) != 3 {
		t.Fatalf("bad stats %+v", s)
	}
	s.Protocols["0"] = 999
	if a.Snapshot().Protocols["0"] != 1 {
		t.Fatal("mutable snapshot")
	}
	b := newStatisticsAccumulator()
	b.Add(NewSummary(0, types.PacketDisplay{SrcIP: strings.Repeat("x", (1<<20)+1)}))
	if len(b.Snapshot().SourceCounts) != 0 {
		t.Fatal("unbounded key retained")
	}
}

func TestQueryManifestAndCorruptOrdering(t *testing.T) {
	d := queryDataset(t, 4)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 2, Request: 8}
	qInterface, err := d.Query(ctx, QuerySpec{Token: token, Description: []string{"udp", "length > 0"}})
	if err != nil {
		t.Fatal(err)
	}
	q := qInterface.(*diskQuery)
	data, err := os.ReadFile(q.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "udp") || !strings.Contains(string(data), "length > 0") || !strings.Contains(string(data), "192.0.2.1") {
		t.Fatal("manifest omits frozen description or statistics")
	}
	// Duplicate IDs must fail even when a random page starts at the duplicate.
	var duplicate [8]byte
	mutator, err := os.OpenFile(q.path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := mutator.WriteAt(duplicate[:], queryHeaderBytes+queryEntryBytes)
	closeErr := mutator.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Page(ctx, PageRequest{Token: token, Row: 1, Limit: 1, MaxBytes: 16 << 10}); err == nil {
		t.Fatal("accepted duplicate IDs")
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	qInterface, err = d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	q = qInterface.(*diskQuery)
	if err := os.Truncate(q.manifest, 1); err != nil {
		t.Fatal(err)
	}
	if err := q.Iterate(ctx, func(Detail) error { return nil }); err == nil {
		t.Fatal("accepted corrupt manifest")
	}
	before := d.Resources().DiskBytes
	if _, err := d.Query(ctx, QuerySpec{Token: token, Description: []string{strings.Repeat("x", 16<<10)}}); err == nil {
		t.Fatal("accepted oversized description")
	}
	if d.Resources().DiskBytes != before {
		t.Fatal("invalid description allocated query files")
	}
}

func TestQueryCleanupFailureRemainsDatasetOwned(t *testing.T) {
	d := queryDataset(t, 3)
	qi, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 7, Query: 1}})
	if err != nil {
		t.Fatal(err)
	}
	q := qi.(*diskQuery)
	if err := os.Remove(q.manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(q.manifest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(q.manifest+"/block", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err == nil {
		t.Fatal("expected cleanup failure")
	}
	if d.Resources().DiskBytes != d.ownedBytes {
		t.Fatal("failed cleanup accounting stranded")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if d.Resources().DiskBytes != 0 {
		t.Fatal("dataset cleanup did not release query files")
	}
}

func TestQueryManifestFailurePreservesCompletedQuery(t *testing.T) {
	d := queryDataset(t, 3)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 1}
	old, err := d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	before := d.Resources().DiskBytes
	// Enough budget for every match ID and header, then fail during manifest.
	d.storage.mu.Lock()
	d.storage.limits.DiskBytes = before + queryHeaderBytes + 3*8 + 10
	d.storage.mu.Unlock()
	if _, err := d.Query(ctx, QuerySpec{Token: Token{Dataset: 7, Query: 2}}); err == nil {
		t.Fatal("expected manifest write failure")
	}
	if d.Resources().DiskBytes != before {
		t.Fatal("manifest failure leaked files")
	}
	if err := old.Iterate(ctx, func(Detail) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPageLeaseAccountsRetainedRowsAndCopies(t *testing.T) {
	d := queryDataset(t, 4)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 1}
	q, err := d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	page, err := q.Page(ctx, PageRequest{Token: token, Limit: 4, MaxBytes: 16 << 10})
	if err != nil {
		t.Fatal(err)
	}
	copyOfPage := page
	usage := d.Resources()
	if usage.PinnedBytes == 0 || usage.InFlightBytes != 0 || usage.PinnedBytes > 16<<10 {
		t.Fatalf("page not charged after return: %+v", usage)
	}
	if err := d.storage.reserveMemory(ctx, d.storage.limits.CacheBytes-usage.PinnedBytes+1); err == nil {
		t.Fatal("retained page failed to constrain allocation budget")
	}
	// Rows are owned values. Closing the disk dataset can proceed, but storage
	// must retain their budget until the model releases the page.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.storage.Close(); err == nil {
		t.Fatal("closed storage with retained page")
	}
	if len(page.Rows) != 4 || page.Rows[3].ID != 3 {
		t.Fatal("dataset close invalidated page")
	}
	if err := copyOfPage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := page.Close(); err != nil {
		t.Fatal(err)
	}
	if d.Resources().PinnedBytes != 0 {
		t.Fatal("copied page double release leaked or underflowed budget")
	}
}

func TestPageFailureDoesNotReturnUnaccountedRows(t *testing.T) {
	d := queryDataset(t, 4)
	ctx := context.Background()
	token := Token{Dataset: 7, Query: 1}
	qi, err := d.Query(ctx, QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	q := qi.(*diskQuery)
	// Corrupt the second entry so a successfully decoded first row must be
	// discarded and its reservation released when pagination fails.
	f, err := os.OpenFile(q.path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var zero [8]byte
	_, writeErr := f.WriteAt(zero[:], queryHeaderBytes+queryEntryBytes)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		t.Fatal(err)
	}
	page, err := q.Page(ctx, PageRequest{Token: token, Limit: 4, MaxBytes: 16 << 10})
	if err == nil || len(page.Rows) != 0 {
		t.Fatalf("partial page escaped on failure: %d, %v", len(page.Rows), err)
	}
	if usage := d.Resources(); usage.PinnedBytes != 0 || usage.InFlightBytes != 0 {
		t.Fatalf("failed page leaked memory: %+v", usage)
	}
}

func TestQueryCloseDoesNotWaitForUnrelatedDetailPin(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	token := Token{Dataset: 1, Query: 1}
	q, err := d.Query(context.Background(), QuerySpec{Token: token})
	require.NoError(t, err)
	pin, err := d.PinDetail(context.Background(), token, 0)
	require.NoError(t, err)
	closed := make(chan error, 1)
	go func() { closed <- q.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.NoError(t, pin.Close())
		require.NoError(t, <-closed)
		require.NoError(t, d.Close())
		require.NoError(t, s.Close())
		t.Fatal("closing a query blocked on a dataset detail pin unrelated to that query")
	}
	require.NoError(t, pin.Close())
	require.NoError(t, d.Close())
	require.NoError(t, s.Close())
}
