//go:build tui || all

package nodesview

import (
	"fmt"
	"math"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// ResourceLevel is utilization, independent of the node's reported health.
// Unknown and normal resources both use the default foreground.
type ResourceLevel uint8

const (
	ResourceNormal ResourceLevel = iota
	ResourceElevated
	ResourceHigh
)

// ResourceThresholds are percentages of effective CPU capacity or memory limit.
type ResourceThresholds struct {
	Elevated float64
	High     float64
}

func DefaultResourceThresholds() ResourceThresholds {
	return ResourceThresholds{Elevated: 70, High: 90}
}

func (v ResourceThresholds) Validate() error {
	if !finite(v.Elevated) || !finite(v.High) || v.Elevated <= 0 || v.Elevated >= v.High || v.High > 100 {
		return fmt.Errorf("resource thresholds must satisfy 0 < elevated < high <= 100")
	}
	return nil
}

func (t *ChangeTracker) resourceThresholds() ResourceThresholds {
	if t.Thresholds == (ResourceThresholds{}) {
		return DefaultResourceThresholds()
	}
	return t.Thresholds
}

type resourceState struct {
	level                        ResourceLevel
	elevatedSamples, highSamples int
}

func (s *resourceState) observe(value float64, thresholds ResourceThresholds) {
	if value >= thresholds.Elevated {
		s.elevatedSamples = min(3, s.elevatedSamples+1)
	} else {
		s.elevatedSamples = 0
	}
	if value >= thresholds.High {
		s.highSamples = min(3, s.highSamples+1)
	} else {
		s.highSamples = 0
	}
	// Default exit boundaries are 65% and 85%. Keep a useful gap even with
	// configured thresholds close together or close to zero.
	gap := min(5.0, thresholds.Elevated/2, (thresholds.High-thresholds.Elevated)/2)
	if value < thresholds.Elevated-gap {
		s.level = ResourceNormal
	} else if s.level == ResourceHigh && value < thresholds.High-gap {
		s.level = ResourceElevated
	}
	if s.highSamples >= 3 {
		s.level = ResourceHigh
	} else if s.elevatedSamples >= 3 && s.level == ResourceNormal {
		s.level = ResourceElevated
	}
}

type resourceObservation struct {
	cpu, memory resourceState
	lastSample  int64
	capacity    float64
	memoryLimit uint64
}

// reset preserves the sample floor. A reconnect snapshot must not turn cached
// telemetry into a new observation after losing visibility.
func (r *resourceObservation) reset() {
	r.cpu, r.memory = resourceState{}, resourceState{}
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func (r *resourceObservation) observe(h types.HunterInfo, thresholds ResourceThresholds) {
	if h.MetricsSampleTimeNS <= 0 {
		// Legacy peers cannot establish distinct metric samples. LastHeartbeat
		// also advances on packet delivery, so it is not a safe substitute.
		r.reset()
		return
	}
	if h.MetricsSampleTimeNS < r.lastSample {
		return
	}
	cpu := h.CPUPercent / h.CPUCapacityCores
	cpuKnown := h.CPUPercent >= 0 && finite(h.CPUPercent) && h.CPUCapacityCores > 0 && finite(h.CPUCapacityCores) && finite(cpu)
	memoryKnown := h.MemoryRSSBytes > 0 && h.MemoryLimitBytes > 0
	if !cpuKnown || r.capacity != h.CPUCapacityCores {
		r.cpu = resourceState{}
	}
	if !memoryKnown || r.memoryLimit != h.MemoryLimitBytes {
		r.memory = resourceState{}
	}
	if h.MetricsSampleTimeNS <= r.lastSample {
		return
	}
	r.lastSample = h.MetricsSampleTimeNS
	r.capacity, r.memoryLimit = h.CPUCapacityCores, h.MemoryLimitBytes
	if cpuKnown {
		r.cpu.observe(cpu, thresholds)
	}
	if memoryKnown {
		r.memory.observe(100*float64(h.MemoryRSSBytes)/float64(h.MemoryLimitBytes), thresholds)
	}
}
