package offline

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryPositionUsesImmutableOrderedRowsWithoutRetainedAllocation(t *testing.T) {
	d := compactQueryFixture(t, 2051)
	for _, identity := range []bool{true, false} {
		spec := QuerySpec{Token: Token{Dataset: d.Generation(), Revision: d.Revision(), Query: 8}}
		if !identity {
			spec.Match = func(s Summary) bool { return s.ID%7 == 0 }
		}
		query, err := d.Query(context.Background(), spec)
		require.NoError(t, err)
		q := query.(*diskQuery)
		before := d.Resources()
		for _, id := range []PacketID{0, 1, 7, 14, 700, 1024, 2044, 2050, 2051} {
			position, found, err := q.Position(context.Background(), id)
			require.NoError(t, err)
			want := uint64(id) < d.Count() && (identity || id%7 == 0)
			require.Equal(t, want, found)
			if found {
				wantPosition := uint64(id)
				if !identity {
					wantPosition /= 7
				}
				require.Equal(t, wantPosition, position)
			}
		}
		require.Equal(t, before, d.Resources(), "position reads no decoded records or retained ID collection")
		require.NoError(t, q.Close())
	}
}

func TestQueryPositionRejectsCorruptOrderingAndRevisionHeader(t *testing.T) {
	for _, target := range []string{"ordering", "revision", "manifest"} {
		t.Run(target, func(t *testing.T) {
			d := compactQueryFixture(t, 130)
			query, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: d.Generation(), Revision: d.Revision(), Query: 3}, Match: func(s Summary) bool { return s.ID%2 == 0 }})
			require.NoError(t, err)
			q := query.(*diskQuery)
			t.Cleanup(func() { require.NoError(t, q.Close()) })
			path, offset := q.path, int64(queryHeaderBytes+(q.count/2)*queryEntryBytes)
			if target == "revision" {
				offset = 24
			}
			if target == "manifest" {
				path, offset = q.manifest, 40
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			require.NoError(t, err)
			var invalid [8]byte
			binary.LittleEndian.PutUint64(invalid[:], 0)
			_, err = file.WriteAt(invalid[:], offset)
			require.NoError(t, err)
			require.NoError(t, file.Close())
			_, _, err = q.Position(context.Background(), PacketID((q.count/2)*2))
			require.Error(t, err)
		})
	}
}
