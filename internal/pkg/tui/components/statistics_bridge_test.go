//go:build tui || all

package components

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBridgeStatisticsRetentionRatio(t *testing.T) {
	tests := []struct {
		name  string
		stats *BridgeStatistics
		want  float64
	}{
		{name: "empty is fully retained", stats: &BridgeStatistics{}, want: 1},
		{name: "partial", stats: &BridgeStatistics{PacketsReceived: 1000, PacketsDelivered: 625}, want: 0.625},
		{name: "invalid excluded", stats: &BridgeStatistics{PacketsReceived: 100, InvalidEnvelopes: 20, PacketsDelivered: 40}, want: 0.5},
		{name: "compatibility displayed", stats: &BridgeStatistics{PacketsReceived: 10, PacketsDisplayed: 8}, want: 0.8},
		{name: "clamped", stats: &BridgeStatistics{PacketsReceived: 10, PacketsDelivered: 12}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.stats.RetentionRatio())
		})
	}
}

func TestHealthRenderingShowsPacketLevelDisplayLoss(t *testing.T) {
	view := NewStatisticsView()
	view.SetBridgeStats(&BridgeStatistics{
		PacketsReceived:        1000,
		PacketsDelivered:       700,
		PacketsSampledOut:      200,
		BatchQueuePacketDrops:  75,
		PendingPacketEvictions: 25,
		SamplingRatio:          700,
	})

	rendered := view.renderHealthSubView()
	for _, expected := range []string{
		"Packets Delivered:", "700 (70.0% retained)",
		"Sampled Out:", "200", "Batch Queue Drops:", "75", "Pending Evictions:", "25",
	} {
		assert.Truef(t, strings.Contains(rendered, expected), "rendered health missing %q", expected)
	}
}

func TestLiveIngressLabelsExactProtocolClassification(t *testing.T) {
	view := NewStatisticsView()
	assert.Equal(t, "🔌 Protocol Distribution", view.protocolDistributionTitle())

	view.SetL3L4ProtocolClassification(true)
	assert.Equal(t, "🔌 L3/L4 Protocol Distribution", view.protocolDistributionTitle())
}
