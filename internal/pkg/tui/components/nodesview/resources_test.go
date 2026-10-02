//go:build tui || all

package nodesview

import (
	"math"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceThresholdTransitions(t *testing.T) {
	var state resourceState
	thresholds := DefaultResourceThresholds()
	for _, sample := range []struct {
		value float64
		want  ResourceLevel
	}{
		{69.9, ResourceNormal},
		{70, ResourceNormal}, {89, ResourceNormal}, {70, ResourceElevated},
		{69, ResourceElevated}, {65, ResourceElevated}, {64.9, ResourceNormal},
		{90, ResourceNormal}, {95, ResourceNormal}, {90, ResourceHigh},
		{89, ResourceHigh}, {85, ResourceHigh}, {84.9, ResourceElevated},
		{90, ResourceElevated}, {89, ResourceElevated}, // Interrupted escalation.
		{90, ResourceElevated}, {90, ResourceElevated}, {90, ResourceHigh},
		{20, ResourceNormal},
	} {
		state.observe(sample.value, thresholds)
		assert.Equal(t, sample.want, state.level, "sample=%v", sample.value)
	}
}

func TestResourcesRequireDistinctSamplesAndRemainPersistent(t *testing.T) {
	p, key := trackerFixture()
	h := &p[0].Hunters[0]
	h.CPUCapacityCores, h.CPUPercent = 4, 360 // 90% of four cores.
	h.MemoryLimitBytes, h.MemoryRSSBytes = 1000, 700
	var tracker ChangeTracker
	now := time.Unix(100, 0)
	for sample := int64(1); sample <= 3; sample++ {
		h.MetricsSampleTimeNS = sample
		tracker.Observe(p, now)
		if sample < 3 {
			assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
		}
		for duplicate := 0; duplicate < 5; duplicate++ {
			h.LastHeartbeat++ // Traffic and unrelated topology updates are not samples.
			tracker.Observe(p, now.Add(time.Duration(duplicate)*time.Second))
		}
		if sample < 3 {
			assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
		}
	}
	want := NodeChanges{CPU: ResourceHigh, Memory: ResourceElevated}
	assert.Equal(t, want, tracker.Snapshot()[key])
	assert.False(t, tracker.Advance(now.Add(time.Hour)), "resource levels do not expire")
	assert.Equal(t, want, tracker.Snapshot()[key])
	h.MetricsSampleTimeNS, h.CPUPercent, h.MemoryRSSBytes = 2, 10, 10
	tracker.Observe(p, now)
	assert.Equal(t, want, tracker.Snapshot()[key], "out-of-order sample cannot change resource state")
	h.MetricsSampleTimeNS = 4
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
}

func TestResourcesUnknownOrInvalidResetIndependently(t *testing.T) {
	for name, change := range map[string]struct {
		mutate   func(*types.HunterInfo)
		cpu, ram ResourceLevel
	}{
		"old peer":             {func(h *types.HunterInfo) { h.CPUCapacityCores, h.MetricsSampleTimeNS = 0, 0 }, ResourceNormal, ResourceNormal},
		"missing timestamp":    {func(h *types.HunterInfo) { h.MetricsSampleTimeNS = 0 }, ResourceNormal, ResourceNormal},
		"missing capacity":     {func(h *types.HunterInfo) { h.CPUCapacityCores = 0 }, ResourceNormal, ResourceHigh},
		"negative capacity":    {func(h *types.HunterInfo) { h.CPUCapacityCores = -1 }, ResourceNormal, ResourceHigh},
		"nan capacity":         {func(h *types.HunterInfo) { h.CPUCapacityCores = math.NaN() }, ResourceNormal, ResourceHigh},
		"infinite capacity":    {func(h *types.HunterInfo) { h.CPUCapacityCores = math.Inf(1) }, ResourceNormal, ResourceHigh},
		"missing CPU":          {func(h *types.HunterInfo) { h.CPUPercent = -1 }, ResourceNormal, ResourceHigh},
		"nan CPU":              {func(h *types.HunterInfo) { h.CPUPercent = math.NaN() }, ResourceNormal, ResourceHigh},
		"infinite CPU":         {func(h *types.HunterInfo) { h.CPUPercent = math.Inf(1) }, ResourceNormal, ResourceHigh},
		"overflow utilization": {func(h *types.HunterInfo) { h.CPUCapacityCores = math.SmallestNonzeroFloat64 }, ResourceNormal, ResourceHigh},
		"missing memory limit": {func(h *types.HunterInfo) { h.MemoryLimitBytes = 0 }, ResourceHigh, ResourceNormal},
		"missing RSS":          {func(h *types.HunterInfo) { h.MemoryRSSBytes = 0 }, ResourceHigh, ResourceNormal},
		"new capacity":         {func(h *types.HunterInfo) { h.CPUCapacityCores = .5 }, ResourceNormal, ResourceHigh},
		"new memory limit":     {func(h *types.HunterInfo) { h.MemoryLimitBytes = 950 }, ResourceHigh, ResourceNormal},
	} {
		t.Run(name, func(t *testing.T) {
			var state resourceObservation
			h := types.HunterInfo{CPUCapacityCores: 1, CPUPercent: 95, MemoryRSSBytes: 950, MemoryLimitBytes: 1000}
			for h.MetricsSampleTimeNS = 1; h.MetricsSampleTimeNS <= 3; h.MetricsSampleTimeNS++ {
				state.observe(h, DefaultResourceThresholds())
			}
			require.Equal(t, ResourceHigh, state.cpu.level)
			require.Equal(t, ResourceHigh, state.memory.level)
			change.mutate(&h)
			state.observe(h, DefaultResourceThresholds())
			assert.Equal(t, change.cpu, state.cpu.level)
			assert.Equal(t, change.ram, state.memory.level)
		})
	}
}

func TestResourcesFractionalCapacityAndLegacyMemory(t *testing.T) {
	for _, test := range []struct {
		name     string
		h        types.HunterInfo
		cpu, ram ResourceLevel
	}{
		{"half core allocation", types.HunterInfo{CPUPercent: 45, CPUCapacityCores: .5}, ResourceHigh, ResourceNormal},
		{"multi core normal", types.HunterInfo{CPUPercent: 200, CPUCapacityCores: 4}, ResourceNormal, ResourceNormal},
		{"memory with old CPU telemetry", types.HunterInfo{CPUPercent: 95, MemoryRSSBytes: 950, MemoryLimitBytes: 1000}, ResourceNormal, ResourceHigh},
	} {
		t.Run(test.name, func(t *testing.T) {
			var state resourceObservation
			for test.h.MetricsSampleTimeNS = 1; test.h.MetricsSampleTimeNS <= 3; test.h.MetricsSampleTimeNS++ {
				state.observe(test.h, DefaultResourceThresholds())
			}
			assert.Equal(t, test.cpu, state.cpu.level)
			assert.Equal(t, test.ram, state.memory.level)
		})
	}
}

func TestResourcesResetOnLostVisibilityAndNeedFreshSamples(t *testing.T) {
	for _, reason := range []string{"stats", "parent", "ancestor"} {
		t.Run(reason, func(t *testing.T) {
			p, key := trackerFixture()
			p = append(p, ProcessorInfo{Address: "root", ConnectionState: ProcessorConnectionStateConnected})
			p[0].UpstreamAddr = "root"
			h := &p[0].Hunters[0]
			h.CPUCapacityCores, h.CPUPercent = 1, 95
			h.MemoryRSSBytes, h.MemoryLimitBytes = 950, 1000
			var tracker ChangeTracker
			now := time.Unix(100, 0)
			for sample := int64(1); sample <= 3; sample++ {
				h.MetricsSampleTimeNS = sample
				tracker.Observe(p, now)
			}
			require.Equal(t, ResourceHigh, tracker.Snapshot()[key].CPU)
			switch reason {
			case "stats":
				h.StatsUnavailable = true
			case "parent":
				p[0].ConnectionState = ProcessorConnectionStateDisconnected
			case "ancestor":
				p[1].ConnectionState = ProcessorConnectionStateDisconnected
			}
			tracker.Observe(p, now)
			assert.Equal(t, ResourceNormal, tracker.Snapshot()[key].CPU)
			assert.Equal(t, ResourceNormal, tracker.Snapshot()[key].Memory)
			h.StatsUnavailable = false
			p[0].ConnectionState, p[1].ConnectionState = ProcessorConnectionStateConnected, ProcessorConnectionStateConnected
			for i := 0; i < 5; i++ {
				tracker.Observe(p, now)
			}
			assert.Equal(t, ResourceNormal, tracker.Snapshot()[key].CPU, "cached reconnect stats do not count")
			for sample := int64(4); sample <= 6; sample++ {
				h.MetricsSampleTimeNS = sample
				tracker.Observe(p, now)
				if sample < 6 {
					assert.Equal(t, ResourceNormal, tracker.Snapshot()[key].CPU)
				}
			}
			assert.Equal(t, ResourceHigh, tracker.Snapshot()[key].CPU)
		})
	}
}

func TestCustomResourceThresholdsAndReset(t *testing.T) {
	thresholds := ResourceThresholds{Elevated: 40, High: 60}
	require.NoError(t, thresholds.Validate())
	var state resourceState
	for i := 0; i < 3; i++ {
		state.observe(60, thresholds)
	}
	assert.Equal(t, ResourceHigh, state.level)
	state.observe(54.9, thresholds)
	assert.Equal(t, ResourceElevated, state.level)
	state.observe(34.9, thresholds)
	assert.Equal(t, ResourceNormal, state.level)
	tracker := ChangeTracker{Thresholds: thresholds}
	tracker.Reset()
	assert.Equal(t, thresholds, tracker.resourceThresholds())
	for _, invalid := range []ResourceThresholds{{0, 90}, {70, 70}, {90, 70}, {70, 101}, {math.NaN(), 90}, {70, math.Inf(1)}} {
		assert.Error(t, invalid.Validate())
	}
	thresholds = ResourceThresholds{Elevated: 1, High: 2}
	require.NoError(t, thresholds.Validate())
	state = resourceState{}
	for i := 0; i < 3; i++ {
		state.observe(2, thresholds)
	}
	state.observe(1.4, thresholds)
	assert.Equal(t, ResourceElevated, state.level)
	state.observe(.4, thresholds)
	assert.Equal(t, ResourceNormal, state.level)
}
