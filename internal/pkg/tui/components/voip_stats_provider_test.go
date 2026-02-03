//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
)

func TestNewVoIPStatsProvider(t *testing.T) {
	provider := NewVoIPStatsProvider()
	assert.NotNil(t, provider)
	assert.NotNil(t, provider.codecCounts)
	assert.Equal(t, "VoIP (SIP/RTP)", provider.ProtocolName())
}

func TestVoIPStatsProvider_IsActive(t *testing.T) {
	provider := NewVoIPStatsProvider()

	// Initially inactive
	assert.False(t, provider.IsActive())

	// Add some calls
	calls := []Call{
		{CallID: "call-1", State: CallStateActive},
	}
	provider.UpdateCalls(calls)

	// Now active
	assert.True(t, provider.IsActive())
}

func TestVoIPStatsProvider_UpdateCalls(t *testing.T) {
	provider := NewVoIPStatsProvider()

	calls := []Call{
		{CallID: "call-1", State: CallStateActive, Codec: "G.711u"},
		{CallID: "call-2", State: CallStateRinging, Codec: "G.729"},
		{CallID: "call-3", State: CallStateEnded, Codec: "G.711u", MOS: 4.2, Jitter: 15, PacketLoss: 0.5, Duration: 120 * time.Second},
		{CallID: "call-4", State: CallStateFailed},
		{CallID: "call-5", State: CallStateRTPOnly, Codec: "Opus"},
	}
	provider.UpdateCalls(calls)

	assert.Equal(t, 5, provider.totalCalls)
	assert.Equal(t, 1, provider.activeCalls)
	assert.Equal(t, 1, provider.ringingCalls)
	assert.Equal(t, 1, provider.completedCalls)
	assert.Equal(t, 1, provider.failedCalls)
	assert.Equal(t, 1, provider.rtpOnlyCalls)
}

func TestVoIPStatsProvider_CodecDistribution(t *testing.T) {
	provider := NewVoIPStatsProvider()

	calls := []Call{
		// Calls with RTP (Active, Ended, RTPOnly) - should be counted
		{CallID: "call-1", State: CallStateActive, Codec: "PCMU"},  // Should normalize to G.711u
		{CallID: "call-2", State: CallStateEnded, Codec: "G711U"},  // Should normalize to G.711u
		{CallID: "call-3", State: CallStateRTPOnly, Codec: "G729"}, // Should normalize to G.729
		{CallID: "call-4", State: CallStateActive, Codec: "opus"},  // Should normalize to Opus
		{CallID: "call-5", State: CallStateEnded, Codec: "PCMA"},   // Should normalize to G.711a
		// Early dialog calls (Trying, Ringing, Progress) - should NOT be counted
		{CallID: "call-6", State: CallStateTrying, Codec: "Unknown"},
		{CallID: "call-7", State: CallStateRinging, Codec: "Unknown"},
		{CallID: "call-8", State: CallStateProgress, Codec: "Unknown"},
	}
	provider.UpdateCalls(calls)

	// Only Active, Ended, RTPOnly calls should contribute to codec stats
	assert.Equal(t, int64(2), provider.codecCounts["G.711u"])
	assert.Equal(t, int64(1), provider.codecCounts["G.729"])
	assert.Equal(t, int64(1), provider.codecCounts["Opus"])
	assert.Equal(t, int64(1), provider.codecCounts["G.711a"])
	// Early dialog calls should NOT contribute to Unknown count
	assert.Equal(t, int64(0), provider.codecCounts["Unknown"])
}

func TestVoIPStatsProvider_QualityMetrics(t *testing.T) {
	provider := NewVoIPStatsProvider()

	calls := []Call{
		{CallID: "call-1", MOS: 4.5, Jitter: 10, PacketLoss: 0.1, Duration: 60 * time.Second},
		{CallID: "call-2", MOS: 4.0, Jitter: 20, PacketLoss: 0.5, Duration: 120 * time.Second},
		{CallID: "call-3", MOS: 3.0, Jitter: 50, PacketLoss: 2.0, Duration: 180 * time.Second},
	}
	provider.UpdateCalls(calls)

	// Check averages
	assert.InDelta(t, 3.83, provider.avgMOS, 0.1)
	assert.InDelta(t, 26.67, provider.avgJitter, 0.1)
	assert.InDelta(t, 0.87, provider.avgPacketLoss, 0.1)
	assert.InDelta(t, 120.0, provider.avgDuration, 0.1)
}

func TestVoIPStatsProvider_QualityDistribution(t *testing.T) {
	provider := NewVoIPStatsProvider()

	calls := []Call{
		{CallID: "call-1", MOS: 4.5}, // Excellent
		{CallID: "call-2", MOS: 4.0}, // Excellent
		{CallID: "call-3", MOS: 3.7}, // Good
		{CallID: "call-4", MOS: 3.2}, // Fair
		{CallID: "call-5", MOS: 2.5}, // Poor
	}
	provider.UpdateCalls(calls)

	assert.Equal(t, 2, provider.excellentCalls)
	assert.Equal(t, 1, provider.goodCalls)
	assert.Equal(t, 1, provider.fairCalls)
	assert.Equal(t, 1, provider.poorCalls)
}

func TestVoIPStatsProvider_GetMetrics(t *testing.T) {
	provider := NewVoIPStatsProvider()

	calls := []Call{
		{CallID: "call-1", State: CallStateEnded, Codec: "G.711u", MOS: 4.2, Duration: 60 * time.Second},
		{CallID: "call-2", State: CallStateFailed},
		{CallID: "call-3", State: CallStateActive},
	}
	provider.UpdateCalls(calls)

	metrics := provider.GetMetrics()

	assert.Equal(t, int64(3), metrics.TotalItems)
	assert.Equal(t, int64(1), metrics.ActiveItems)
	assert.Equal(t, int64(1), metrics.CompletedItems)
	assert.Equal(t, int64(1), metrics.FailedItems)
	assert.Equal(t, 50.0, metrics.SuccessRate) // 1 completed / 2 (completed + failed)
	assert.InDelta(t, 4.2, metrics.AvgQuality, 0.01)
	assert.Equal(t, "MOS", metrics.QualityMetric)
	assert.Equal(t, int64(1), metrics.Distribution["G.711u"])
}

func TestVoIPStatsProvider_Render(t *testing.T) {
	provider := NewVoIPStatsProvider()
	theme := themes.Solarized()

	// Empty render
	result := provider.Render(80, theme)
	assert.Contains(t, result, "No VoIP calls detected")

	// With calls
	calls := []Call{
		{CallID: "call-1", State: CallStateActive, Codec: "G.711u"},
		{CallID: "call-2", State: CallStateEnded, Codec: "G.729", MOS: 4.2, Jitter: 15, PacketLoss: 0.5, Duration: 120 * time.Second},
	}
	provider.UpdateCalls(calls)

	result = provider.Render(80, theme)

	// Check sections are present
	assert.Contains(t, result, "Call Overview")
	assert.Contains(t, result, "Total Calls")
	assert.Contains(t, result, "Active")
	assert.Contains(t, result, "Completed")
	assert.Contains(t, result, "Quality Metrics")
	assert.Contains(t, result, "MOS")
	assert.Contains(t, result, "Codecs")
}

func TestVoIPStatsProvider_SetTheme(t *testing.T) {
	provider := NewVoIPStatsProvider()
	newTheme := themes.Solarized()

	provider.SetTheme(newTheme)

	assert.Equal(t, newTheme, provider.theme)
}

func TestNormalizeCodecName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"PCMU", "G.711u"},
		{"pcmu", "G.711u"},
		{"G711U", "G.711u"},
		{"PCMA", "G.711a"},
		{"G711A", "G.711a"},
		{"G729", "G.729"},
		{"g729", "G.729"},
		{"G722", "G.722"},
		{"OPUS", "Opus"},
		{"opus", "Opus"},
		{"AMR-WB", "AMR-WB"},
		{"AMR", "AMR"},
		{"SILK", "SILK"},
		{"SPEEX", "Speex"},
		{"ILBC", "iLBC"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCodecName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatCallDuration(t *testing.T) {
	tests := []struct {
		seconds  float64
		expected string
	}{
		{30, "30s"},
		{90, "1m 30s"},
		{3600, "1h 0m"},
		{3660, "1h 1m"},
		{7200, "2h 0m"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatCallDuration(tt.seconds)
			assert.Equal(t, tt.expected, result)
		})
	}
}
