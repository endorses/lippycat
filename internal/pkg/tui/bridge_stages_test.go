//go:build tui || all

package tui

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestSamplingRatioUsesPacketCountTimeDeltaAndClamps(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1.0, samplingRatio(500, time.Second))
	require.Equal(t, 0.5, samplingRatio(2000, time.Second))
	require.Equal(t, 0.01, samplingRatio(200000, time.Second))
	require.Equal(t, 1.0, samplingRatio(0, time.Second))
}

func TestDisplaySamplingPolicyDeterministicSelection(t *testing.T) {
	t.Parallel()
	start := time.Unix(100, 0)
	policy := newDisplaySamplingPolicy(false, start)
	env := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("detail"))

	// The first checkpoint represents 2,000 pps, giving a 50% detail budget.
	require.False(t, policy.shouldDisplay(env, 2000, start.Add(time.Second)))
	require.True(t, policy.shouldDisplay(env, 2001, start.Add(time.Second)))
	require.False(t, policy.shouldDisplay(env, 2002, start.Add(time.Second)))
	require.True(t, policy.shouldDisplay(env, 2003, start.Add(time.Second)))
}

func TestDisplaySamplingPolicyPreservesReplayAndSIPPreference(t *testing.T) {
	t.Parallel()
	start := time.Unix(200, 0)
	replay := telemetryUDPEnvelope(t, pipeline.SourcePCAPReplay, []byte("replay"))
	liveSIP := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("OPTIONS sip:test@example.invalid SIP/2.0\r\n\r\n"))

	policy := newDisplaySamplingPolicy(false, start)
	require.True(t, policy.shouldDisplay(replay, 100000, start.Add(time.Second)))
	require.True(t, policy.shouldDisplay(liveSIP, 100000, start.Add(time.Second)))
}

func BenchmarkDisplaySamplingPolicy(b *testing.B) {
	start := time.Unix(300, 0)
	env := telemetryUDPEnvelope(b, pipeline.SourceLiveCapture, []byte("detail"))
	policy := newDisplaySamplingPolicy(false, start)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.shouldDisplay(env, int64(i+1), start.Add(time.Duration(i)*time.Microsecond))
	}
}
