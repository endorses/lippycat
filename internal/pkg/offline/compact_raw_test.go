package offline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func compactRawDataset(t *testing.T, storage *Storage, generation DatasetGeneration, decodes *atomic.Int64) Dataset {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "source")
	bytes := []byte{0, 1, 2, 3, 4, 5}
	require.NoError(t, os.WriteFile(path, bytes, 0600))
	backings := storage.NewBackingRegistry()
	input, err := backings.Open(ctx, path, 0, BackingSource, false)
	require.NoError(t, err)
	require.NoError(t, input.Close())
	builder, err := storage.NewCompactBuilder(generation, []SourcePosition{{Path: path}}, backings, func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		decodes.Add(1)
		packet := summary.DisplayFields()
		packet.RawData = raw
		return packet, ctx.Err()
	})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		raw := bytes[i*2 : i*2+2]
		locator, err := backings.Locator(input.ID, int64(i*2), raw)
		require.NoError(t, err)
		detail := Detail{Source: SourcePosition{Path: path, Sequence: uint64(i)}, CapturedLength: 2, OriginalLength: 9, Packet: types.PacketDisplay{Timestamp: time.Unix(int64(i), 123), RawData: raw, Length: 2, LinkType: layers.LinkTypeEthernet, Protocol: "UDP"}}
		require.NoError(t, builder.AppendCompact(ctx, detail, PacketProvenance{Locator: locator}))
	}
	dataset, err := builder.Finish(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataset.Close()) })
	return dataset
}

func TestCompactRawPinSurvivesReplacementWithoutDecoding(t *testing.T) {
	storage := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	var decodes atomic.Int64
	old := compactRawDataset(t, storage, 1, &decodes)
	query, err := old.Query(context.Background(), QuerySpec{Token: Token{Dataset: 1, Query: 1}, Match: func(s Summary) bool { return s.ID != 1 }})
	require.NoError(t, err)
	pin, err := PinQuery(query)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	replacement := compactRawDataset(t, storage, 2, &decodes)
	decodes.Store(0)
	closed := make(chan error, 1)
	go func() { closed <- old.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("compact dataset closed despite export pin: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	var ids []PacketID
	require.NoError(t, pin.IterateRaw(context.Background(), func(record RawRecord) error {
		ids = append(ids, record.ID)
		require.Equal(t, []byte{byte(record.ID * 2), byte(record.ID*2 + 1)}, record.RawData)
		require.EqualValues(t, 2, record.CapturedLength)
		require.EqualValues(t, 9, record.OriginalLength)
		require.Equal(t, layers.LinkTypeEthernet, record.LinkType)
		require.True(t, time.Unix(int64(record.ID), 123).Equal(record.Timestamp))
		return nil
	}))
	require.Equal(t, []PacketID{0, 2}, ids)
	require.Zero(t, decodes.Load(), "raw export must not call stateless decoder")
	require.NoError(t, pin.Close())
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("compact close did not join raw pin")
	}
	require.NoError(t, replacement.Close())
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestCompactRawCancellationAndCallbackRelease(t *testing.T) {
	storage := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	var decodes atomic.Int64
	dataset := compactRawDataset(t, storage, 1, &decodes)
	query, err := AllPackets(context.Background(), dataset, Token{Dataset: 1, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	baseline := storage.Resources().InFlightBytes
	sentinel := errors.New("export output failed")
	require.ErrorIs(t, IterateRaw(context.Background(), query, func(RawRecord) error { return sentinel }), sentinel)
	require.Equal(t, baseline, storage.Resources().InFlightBytes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visits := 0
	require.ErrorIs(t, IterateRaw(ctx, query, func(RawRecord) error { visits++; cancel(); return nil }), context.Canceled)
	require.Equal(t, 1, visits)
	require.Equal(t, baseline, storage.Resources().InFlightBytes)
}

func TestCompactRawBatchCallbackOwnershipAndFailure(t *testing.T) {
	d := compactQueryFixture(t, 130)
	query, err := AllPackets(context.Background(), d, Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	detail, err := d.Detail(context.Background(), query.Token(), 0)
	require.NoError(t, err)
	baseline := d.Resources().InFlightBytes
	visits := 0
	require.NoError(t, IterateRaw(context.Background(), query, func(record RawRecord) error {
		require.Equal(t, detail.Packet.RawData, record.RawData)
		require.Equal(t, len(record.RawData), cap(record.RawData), "callback append must not access another record")
		record.RawData[0] ^= 0xff
		visits++
		return nil
	}))
	require.Equal(t, 130, visits)
	require.Equal(t, baseline, d.Resources().InFlightBytes)
	callbackError := errors.New("stop export")
	visits = 0
	err = IterateRaw(context.Background(), query, func(RawRecord) error { visits++; return callbackError })
	require.ErrorIs(t, err, callbackError)
	require.Equal(t, 1, visits)
	require.Equal(t, baseline, d.Resources().InFlightBytes)
	for _, stopAt := range []int{1, 130} {
		ctx, cancel := context.WithCancel(context.Background())
		visits = 0
		err = IterateRaw(ctx, query, func(RawRecord) error {
			visits++
			if visits == stopAt {
				cancel()
			}
			return nil
		})
		cancel()
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, stopAt, visits)
		require.Equal(t, baseline, d.Resources().InFlightBytes)
	}
}
