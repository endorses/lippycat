package vinterface

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimingReplayCancellation(t *testing.T) {
	replayer := NewTimingReplayer(true)
	stamp := time.Unix(100, 0)
	require.NoError(t, replayer.WaitForPacketTimeContext(context.Background(), stamp))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, replayer.WaitForPacketTimeContext(ctx, stamp.Add(5*time.Second)), context.DeadlineExceeded)
}

func TestTimingReplayResetStartsANewPass(t *testing.T) {
	replayer := NewTimingReplayer(true)
	stamp := time.Unix(100, 0)
	require.NoError(t, replayer.WaitForPacketTimeContext(context.Background(), stamp))
	replayer.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// With fresh timing this is the new first packet, so no wait is needed.
	require.NoError(t, replayer.WaitForPacketTimeContext(ctx, stamp.Add(5*time.Second)))
}

func TestTimingReplayChecksCancelledContextWhenDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, NewTimingReplayer(false).WaitForPacketTimeContext(ctx, time.Now()), context.Canceled)
}

func TestTimingReplayRetainsTimestampSanityGuard(t *testing.T) {
	replayer := NewTimingReplayer(true)
	stamp := time.Unix(100, 0)
	require.NoError(t, replayer.WaitForPacketTimeContext(context.Background(), stamp))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	require.NoError(t, replayer.WaitForPacketTimeContext(ctx, stamp.Add(time.Hour)))
}
