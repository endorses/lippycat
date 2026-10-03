//go:build tui || all

package components

import (
	"math"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeResourceThresholdConfiguration(t *testing.T) {
	for name, test := range map[string]struct {
		values map[string]any
		want   nodesview.ResourceThresholds
	}{
		"default":      {nil, nodesview.DefaultResourceThresholds()},
		"custom":       {map[string]any{"elevated": 40, "high": 60}, nodesview.ResourceThresholds{Elevated: 40, High: 60}},
		"one override": {map[string]any{"high": 95}, nodesview.ResourceThresholds{Elevated: 70, High: 95}},
		"bad text":     {map[string]any{"elevated": "no"}, nodesview.DefaultResourceThresholds()},
		"reverse":      {map[string]any{"elevated": 95}, nodesview.DefaultResourceThresholds()},
		"nan":          {map[string]any{"high": math.NaN()}, nodesview.DefaultResourceThresholds()},
		"infinite":     {map[string]any{"elevated": math.Inf(1)}, nodesview.DefaultResourceThresholds()},
	} {
		t.Run(name, func(t *testing.T) {
			config := viper.New()
			for key, value := range test.values {
				config.Set("watch.nodes_resources."+key, value)
			}
			assert.Equal(t, test.want, nodeResourceThresholds(config))
		})
	}
}

func TestNodeResourceLevelsSurviveQuietResizeAndViewChanges(t *testing.T) {
	n, p, now := changeViewFixture()
	n.selectedIndex, n.selectedProcessorAddr = 0, ""
	h := &p[0].Hunters[0]
	h.CPUPercent, h.CPUCapacityCores = 360, 4
	h.MemoryRSSBytes, h.MemoryLimitBytes = 950, 1000
	h.MetricsSampleTimeNS = 1
	n.SetProcessors(p)
	key := nodesview.NodeKey{ProcessorAddr: p[0].Address, HunterID: h.ID}
	for i := 0; i < 5; i++ {
		n.SetSize(140+i, 20)
		n.SetProcessors(p)
		h.LastHeartbeat++
	}
	assert.Equal(t, nodesview.NodeChanges{}, n.changeState[key], "rerendering and packet timestamps do not fabricate resource samples")
	for sample := int64(2); sample <= 3; sample++ {
		h.MetricsSampleTimeNS = sample
		n.SetProcessors(p)
	}
	want := nodesview.NodeChanges{CPU: nodesview.ResourceHigh, Memory: nodesview.ResourceHigh}
	require.Equal(t, want, n.changeState[key])
	before := n.View()
	n.SetHighlightMode("quiet")
	assert.Equal(t, before, n.View(), "quiet does not suppress persistent foregrounds")
	assert.NotContains(t, ansi.Strip(n.View()), "↑")
	assert.NotContains(t, ansi.Strip(n.View()), "↓")
	assert.Contains(t, ansi.Strip(n.View()), "360%", "CPU remains expressed per core")
	*now = now.Add(time.Hour)
	assert.False(t, n.AdvanceChanges(*now))
	n.SetSize(100, 20)
	require.True(t, n.ToggleView())
	assert.Equal(t, want, n.changeState[key])
	assert.Contains(t, ansi.Strip(n.View()), "360%")
	n.ResetChanges()
	assert.Equal(t, nodesview.NodeChanges{}, n.changeState[key])
}
