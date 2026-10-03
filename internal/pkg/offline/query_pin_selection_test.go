package offline

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPinnedSelectionRangesFollowFilteredOrder(t *testing.T) {
	d := queryDataset(t, 12)
	q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 7, Query: 1}, Match: func(s Summary) bool { return s.ID%2 == 0 }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	pin, err := PinQuery(q)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	for _, tc := range []struct {
		anchor PacketID
		cursor uint64
	}{{2, 4}, {8, 1}} {
		ids, err := pin.RangeIDs(context.Background(), tc.anchor, tc.cursor, 4)
		require.NoError(t, err)
		require.Equal(t, []PacketID{2, 4, 6, 8}, ids)
	}
	_, err = pin.RangeIDs(context.Background(), 3, 4, 12)
	require.ErrorContains(t, err, "anchor is hidden")
	_, err = pin.RangeIDs(context.Background(), 2, 4, 3)
	require.ErrorContains(t, err, "limit")
	_, err = pin.RangeIDs(context.Background(), 2, 6, 12)
	require.ErrorContains(t, err, "unavailable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = pin.RangeIDs(ctx, 2, 4, 12)
	require.ErrorIs(t, err, context.Canceled)
}

func TestPinnedSelectedRawIncludesFilteredOutRecordsWithoutDecoding(t *testing.T) {
	storage := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	var decodes atomic.Int64
	d := compactRawDataset(t, storage, 1, &decodes)
	q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 1, Query: 1}, Match: func(s Summary) bool { return s.ID == 1 }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	pin, err := PinQuery(q)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	decodes.Store(0)
	inFlight := d.Resources().InFlightBytes
	var got []byte
	err = pin.IterateSelectedRaw(context.Background(), []PacketID{0, 2}, func(r RawRecord) error {
		got = append(got, r.RawData...)
		require.EqualValues(t, 2, r.CapturedLength)
		require.EqualValues(t, 9, r.OriginalLength)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []byte{0, 1, 4, 5}, got)
	require.Zero(t, decodes.Load())
	require.Equal(t, inFlight, d.Resources().InFlightBytes)
	want := errors.New("callback failed")
	require.ErrorIs(t, pin.IterateSelectedRaw(context.Background(), []PacketID{0}, func(RawRecord) error { return want }), want)
	require.Equal(t, inFlight, d.Resources().InFlightBytes)
	for _, ids := range [][]PacketID{{3}, {2, 0}, {1, 1}} {
		require.Error(t, pin.IterateSelectedRaw(context.Background(), ids, func(RawRecord) error { return nil }))
	}
}

func TestPinnedSelectionSurvivesPendingDatasetClose(t *testing.T) {
	d := queryDataset(t, 8)
	q, err := AllPackets(context.Background(), d, Token{Dataset: 7, Query: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	pin, err := PinQuery(q)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("dataset close passed selection pin: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	finished := make(chan error, 1)
	go func() {
		ids, err := pin.RangeIDs(context.Background(), 3, 5, 3)
		if err == nil {
			err = pin.IterateSelectedRaw(context.Background(), ids, func(RawRecord) error { return nil })
		}
		finished <- err
	}()
	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("selection recursively acquired dataset lock behind pending close")
	}
	require.NoError(t, pin.Close())
	require.NoError(t, <-closed)
}
