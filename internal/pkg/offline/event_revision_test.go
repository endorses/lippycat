package offline

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/stretchr/testify/require"
)

func TestEventCompletedRevisionRejectsBaseTokensIncludingPins(t *testing.T) {
	_, d := eventStorageDataset(t, 3)
	require.Equal(t, CompletedRevision, d.Revision())
	token := Token{Dataset: d.Generation(), Revision: CompletedRevision, Query: 9, Request: 3}
	match, err := eventquery.Compile("query:query-2.example.test")
	require.NoError(t, err)
	q, err := d.Query(context.Background(), EventQuerySpec{Token: token, Match: match})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	pin, err := PinEventQuery(q)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pin.Close()) })
	require.Equal(t, token, pin.Token())
	base := token
	base.Revision = BaseRevision
	_, err = AllEvents(context.Background(), d, base)
	require.Error(t, err)
	_, err = d.Detail(context.Background(), base, 2)
	require.Error(t, err)
	for _, page := range []func(context.Context, PageRequest) (EventPage, error){q.Page, pin.Page} {
		got, err := page(context.Background(), PageRequest{Token: base, Limit: 1, MaxBytes: 32 << 10})
		require.Error(t, err)
		require.Equal(t, base, got.Token)
		require.Empty(t, got.Rows)
	}
	detail, err := d.Detail(context.Background(), token, 2)
	require.NoError(t, err)
	require.Equal(t, token, detail.Token)
	require.EqualValues(t, 2, detail.Record.ID)
	require.NoError(t, detail.Close())
	page, err := pin.Page(context.Background(), PageRequest{Token: token, Limit: 1, MaxBytes: 32 << 10})
	require.NoError(t, err)
	require.EqualValues(t, 2, page.Rows[0].ID)
	require.NoError(t, page.Close())
	require.NoError(t, pin.Close())
	page, err = pin.Page(context.Background(), PageRequest{Token: token, Row: 2, Limit: 1, MaxBytes: 32 << 10})
	require.Error(t, err)
	require.Equal(t, token, page.Token)
	require.EqualValues(t, 2, page.Row)
}

func TestEventRevisionIsBoundIntoStreamManifestAndQueryHeaders(t *testing.T) {
	for _, target := range []string{"data", "manifest", "query"} {
		t.Run(target, func(t *testing.T) {
			_, d := eventStorageDataset(t, 3)
			token := Token{Dataset: d.Generation(), Revision: CompletedRevision, Query: 1}
			match, err := eventquery.Compile("query:query-2.example.test")
			require.NoError(t, err)
			q, err := d.Query(context.Background(), EventQuerySpec{Token: token, Match: match})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, q.Close()) })
			path, offset := d.data.Name(), int64(32)
			switch target {
			case "manifest":
				path, offset = d.manifest.Name(), 56
			case "query":
				path, offset = q.(*diskEventQuery).path, 40
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			require.NoError(t, err)
			var revision [8]byte
			binary.LittleEndian.PutUint64(revision[:], uint64(BaseRevision))
			_, err = file.WriteAt(revision[:], offset)
			require.NoError(t, err)
			require.NoError(t, file.Close())
			page, err := q.Page(context.Background(), PageRequest{Token: token, Limit: 1, MaxBytes: 32 << 10})
			require.Error(t, err)
			require.Equal(t, token, page.Token)
			require.Empty(t, page.Rows)
			_, err = PinEventQuery(q)
			require.Error(t, err)
		})
	}
}
