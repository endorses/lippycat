package capture

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func drainReplay(_ context.Context, packets <-chan PacketInfo) error {
	for range packets {
	}
	return nil
}

func TestOfflineRepeatedCountAndOrderedPasses(t *testing.T) {
	stamp := time.Unix(100, 0)
	first := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{stamp, "a"}, {stamp.Add(2 * time.Second), "c"}})
	second := writeTimestampedTestPCAPWithPayload(t, []timestampedPayload{{stamp, "b"}, {stamp.Add(time.Second), "d"}})
	var payloads []string
	var before, after []uint64
	options := OfflineReplayOptions{
		Count: 3,
		BeforePass: func(pass uint64) error {
			before = append(before, pass)
			return nil
		},
		AfterPass: func(pass uint64) error {
			after = append(after, pass)
			return nil
		},
	}
	err := RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, first, second), "", options,
		func(_ context.Context, packets <-chan PacketInfo) error {
			for packet := range packets {
				payloads = append(payloads, string(packet.Packet.Layer(layers.LayerTypeUDP).LayerPayload()))
			}
			return nil
		})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "d", "c", "a", "b", "d", "c", "a", "b", "d", "c"}, payloads)
	require.Equal(t, []uint64{1, 2, 3}, before)
	require.Equal(t, before, after)
}

func TestOfflineRepeatedReopensSourceAndStopsOnFailure(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 0)})
	var completed []uint64
	options := OfflineReplayOptions{Count: 3, AfterPass: func(pass uint64) error {
		completed = append(completed, pass)
		return os.Remove(path)
	}}
	err := RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, path), "", options, drainReplay)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.ErrorContains(t, err, "pass 2")
	require.Equal(t, []uint64{1}, completed)
}

func TestOfflineRepeatedContinuousCancellation(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 0)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var completed []uint64
	options := OfflineReplayOptions{Count: 0, AfterPass: func(pass uint64) error {
		completed = append(completed, pass)
		if pass == 3 {
			cancel()
		}
		return nil
	}}
	err := RunOfflineOrderedRepeated(ctx, offlineTestDevices(t, path), "", options, drainReplay)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []uint64{1, 2, 3}, completed)
}

func TestOfflineRepeatedEmptyOrFilteredContinuousInput(t *testing.T) {
	for _, scenario := range []string{"empty", "filtered"} {
		t.Run(scenario, func(t *testing.T) {
			var stamps []time.Time
			filter := ""
			if scenario == "filtered" {
				stamps = []time.Time{time.Unix(100, 0)}
				filter = "tcp" // The fixture contains UDP.
			}
			path := writeTimestampedTestPCAP(t, stamps)
			passes := 0
			err := RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, path), filter,
				OfflineReplayOptions{Count: 0, BeforePass: func(uint64) error { passes++; return nil }}, drainReplay)
			require.ErrorIs(t, err, ErrOfflineReplayEmpty)
			require.Equal(t, 1, passes)
			err = RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, path), filter,
				OfflineReplayOptions{Count: 2}, drainReplay)
			require.NoError(t, err)
		})
	}
}

func TestOfflineRepeatedDelayOnlyBetweenPassesAndCancels(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 0)})
	for _, count := range []int{1, 2} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			var passes []uint64
			err := RunOfflineOrderedRepeated(ctx, offlineTestDevices(t, path), "",
				OfflineReplayOptions{Count: count, Delay: time.Hour, BeforePass: func(pass uint64) error {
					passes = append(passes, pass)
					return nil
				}}, drainReplay)
			if count == 1 {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			require.Equal(t, []uint64{1}, passes)
		})
	}
}

func TestOfflineRepeatedRejectsSettingsAndPropagatesHookErrors(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 0)})
	sentinel := errors.New("hook failure")
	for _, tc := range []struct {
		name    string
		options OfflineReplayOptions
		want    error
	}{
		{"negative count", OfflineReplayOptions{Count: -1}, nil},
		{"negative delay", OfflineReplayOptions{Count: 1, Delay: -time.Second}, nil},
		{"before hook", OfflineReplayOptions{Count: 2, BeforePass: func(uint64) error { return sentinel }}, sentinel},
		{"after hook", OfflineReplayOptions{Count: 2, AfterPass: func(uint64) error { return sentinel }}, sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, path), "", tc.options, drainReplay)
			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}
}

func TestOfflineRepeatedConsumerFailureStopsReplay(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 0), time.Unix(101, 0)})
	want := errors.New("output failed")
	completed := 0
	err := RunOfflineOrderedRepeated(context.Background(), offlineTestDevices(t, path), "",
		OfflineReplayOptions{Count: 2, AfterPass: func(uint64) error { completed++; return nil }},
		func(context.Context, <-chan PacketInfo) error { return want })
	require.ErrorIs(t, err, want)
	require.Zero(t, completed)
}
