package offline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRawQueryPinSurvivesPendingDatasetAndQueryClose(t *testing.T) {
	for _, closeDataset := range []bool{false, true} {
		name := "query"
		if closeDataset {
			name = "dataset"
		}
		t.Run(name, func(t *testing.T) {
			d := queryDataset(t, 5)
			q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 7, Query: 1}, Match: func(s Summary) bool { return s.ID%2 == 0 }})
			require.NoError(t, err)
			pin, err := PinQuery(q)
			require.NoError(t, err)
			defer func() { require.NoError(t, pin.Close()) }()
			closed := make(chan error, 1)
			go func() {
				if closeDataset {
					closed <- d.Close()
				} else {
					closed <- q.Close()
				}
			}()
			select {
			case err := <-closed:
				t.Fatalf("snapshot failed to pin %s: %v", name, err)
			case <-time.After(20 * time.Millisecond):
			}
			finished := make(chan error, 1)
			var ids []PacketID
			go func() {
				finished <- pin.IterateRaw(context.Background(), func(detail RawRecord) error { ids = append(ids, detail.ID); return nil })
			}()
			select {
			case err := <-finished:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("snapshot iteration deadlocked behind pending close")
			}
			require.Equal(t, []PacketID{0, 2, 4}, ids)
			require.EqualValues(t, 3, pin.Count())
			require.NoError(t, pin.Close())
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("close did not finish after snapshot release")
			}
			require.Error(t, pin.IterateRaw(context.Background(), func(RawRecord) error { return nil }))
			_, err = PinQuery(q)
			require.Error(t, err)
		})
	}
}

func TestRawQueryPinCancellationAndCallbackFailure(t *testing.T) {
	d := queryDataset(t, 5)
	q, err := AllPackets(context.Background(), d, Token{Dataset: 7, Query: 1})
	require.NoError(t, err)
	pin, err := PinQuery(q)
	require.NoError(t, err)
	require.Error(t, pin.IterateRaw(context.Background(), nil))
	callbackErr := errors.New("export writer failed")
	require.ErrorIs(t, pin.IterateRaw(context.Background(), func(RawRecord) error { return callbackErr }), callbackErr)
	ctx, cancel := context.WithCancel(context.Background())
	visited := 0
	err = pin.IterateRaw(ctx, func(RawRecord) error { visited++; cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, visited)
	require.NoError(t, pin.Close())
	require.NoError(t, pin.Close())
	require.NoError(t, q.Close())
	require.Zero(t, d.Resources().InFlightBytes)
}

func TestRawIteratorIdentityFilteredAndCompatibility(t *testing.T) {
	d := queryDataset(t, 7)
	for _, filtered := range []bool{false, true} {
		var q Query
		var err error
		token := Token{Dataset: 7, Query: 1}
		if filtered {
			q, err = d.Query(context.Background(), QuerySpec{Token: token, Match: func(s Summary) bool { return s.ID%2 == 0 }})
		} else {
			q, err = AllPackets(context.Background(), d, token)
		}
		require.NoError(t, err)
		expected := make([]RawRecord, 0, q.Count())
		require.NoError(t, q.Iterate(context.Background(), func(detail Detail) error {
			expected = append(expected, rawRecord(detail))
			return nil
		}))
		// Wrapping the public interface exercises external query compatibility.
		for _, input := range []Query{q, struct{ Query }{q}} {
			var got []RawRecord
			require.NoError(t, IterateRaw(context.Background(), input, func(r RawRecord) error {
				r.RawData = append([]byte(nil), r.RawData...)
				got = append(got, r)
				return nil
			}))
			require.Equal(t, expected, got)
			require.Zero(t, d.Resources().InFlightBytes)
		}
		require.NoError(t, q.Close())
	}
}
