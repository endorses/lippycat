//go:build tui || all

package nodesview

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// NodeKey identifies a node independently of its position in a view.
type NodeKey struct {
	ProcessorAddr string
	HunterID      string
}

type MetricChange struct {
	Direction int
	Changed   bool
}

// NodeChanges is immutable presentation state shared by both renderers.
type NodeChanges struct {
	CPU, Memory                       MetricChange
	FilterDelta                       int64
	FiltersChanged                    bool
	Activity                          bool
	CapturedChanged, ForwardedChanged bool
	Label                             string
	StatusChanged                     bool
}

const (
	metricHighlightDuration = time.Second
	lifecycleDuration       = 5 * time.Second
	recentEventDuration     = 30 * time.Second
	recentEventCapacity     = 20
)

type observedNode struct {
	name                          string
	observed, metricsKnown        bool
	lifecycleKnown                bool
	failed                        bool
	health                        int32
	connection                    ProcessorConnectionState
	cpu                           float64
	memory, captured, sent        uint64
	filters                       uint32
	changes                       NodeChanges
	cpuUntil, memoryUntil         time.Time
	filtersUntil                  time.Time
	capturedUntil, forwardedUntil time.Time
	statusUntil                   time.Time
}

type recentNodeEvent struct {
	key  NodeKey
	text string
	at   time.Time
}

// ChangeTracker records observations, never inferring lifecycle events from a
// missing row. All times come from the caller; there are no timers or goroutines.
type ChangeTracker struct {
	nodes      map[NodeKey]*observedNode
	events     []recentNodeEvent
	recentText string
}

func (t *ChangeTracker) init() {
	if t.nodes == nil {
		t.nodes = make(map[NodeKey]*observedNode)
	}
}

// Observe reconciles a presentation snapshot. New identities establish a quiet
// baseline; only Joined records confirmed additions to an established topology.
func (t *ChangeTracker) Observe(processors []ProcessorInfo, now time.Time) {
	t.init()
	seen := make(map[NodeKey]bool)
	byAddress := make(map[string]ProcessorInfo, len(processors))
	for _, p := range processors {
		byAddress[p.Address] = p
		if p.ProcessorID != "" {
			byAddress[p.ProcessorID] = p
		}
	}
	for _, p := range processors {
		key := NodeKey{ProcessorAddr: p.Address}
		seen[key] = true
		n := t.node(key, p.Address)
		lost := p.ConnectionState == ProcessorConnectionStateDisconnected || p.ConnectionState == ProcessorConnectionStateFailed
		hidden := ancestorDisconnected(p, byAddress)
		if !hidden {
			oldLost := n.connection == ProcessorConnectionStateDisconnected || n.connection == ProcessorConnectionStateFailed
			available := !lost && p.ConnectionState != ProcessorConnectionStateConnecting
			if n.observed && lost && !oldLost {
				t.transition(key, n, "DISCONNECTED", "disconnected", now)
				n.failed = true
			} else if n.observed && available && n.failed && p.Status == 0 {
				t.transition(key, n, "RECOVERED", "recovered", now)
			} else if n.observed && available && int32(p.Status) != n.health && p.Status != 0 {
				t.transition(key, n, "", healthText(int32(p.Status)), now)
			}
			if available {
				n.failed = p.Status != 0
			}
			n.observed, n.health, n.connection = true, int32(p.Status), p.ConnectionState
		}
		for _, h := range p.Hunters {
			key := NodeKey{ProcessorAddr: p.Address, HunterID: h.ID}
			seen[key] = true
			name := h.Hostname
			if name == "" {
				name = h.ID
			}
			n := t.node(key, name)
			// Parent loss means visibility loss, not independent hunter failures.
			if !lost && !hidden {
				if n.observed && int32(h.Status) != n.health {
					if h.Status == 0 && n.failed {
						t.transition(key, n, "RECOVERED", "recovered", now)
					} else if h.Status != 0 {
						t.transition(key, n, "", healthText(int32(h.Status)), now)
					}
				}
				n.observed, n.health, n.failed = true, int32(h.Status), h.Status != 0
			}
			t.metrics(n, h, lost || hidden || h.StatsUnavailable, now)
		}
	}
	for key := range t.nodes {
		if !seen[key] {
			delete(t.nodes, key)
		}
	}
}

func ancestorDisconnected(p ProcessorInfo, processors map[string]ProcessorInfo) bool {
	visited := make(map[string]bool)
	for p.UpstreamAddr != "" && !visited[p.UpstreamAddr] {
		visited[p.UpstreamAddr] = true
		parent, ok := processors[p.UpstreamAddr]
		if !ok {
			return false
		}
		if parent.ConnectionState == ProcessorConnectionStateDisconnected || parent.ConnectionState == ProcessorConnectionStateFailed {
			return true
		}
		p = parent
	}
	return false
}

func (t *ChangeTracker) node(key NodeKey, name string) *observedNode {
	n := t.nodes[key]
	if n == nil {
		n = &observedNode{}
		t.nodes[key] = n
	}
	n.name = name
	return n
}

func healthText(status int32) string {
	switch status {
	case 1:
		return "warning"
	case 2:
		return "error"
	case 3:
		return "stopping"
	}
	return "status changed"
}

func (t *ChangeTracker) metrics(n *observedNode, h types.HunterInfo, unavailable bool, now time.Time) {
	if unavailable {
		n.metricsKnown = false
		n.changes.CPU, n.changes.Memory = MetricChange{}, MetricChange{}
		n.changes.FiltersChanged, n.changes.Activity, n.changes.FilterDelta = false, false, 0
		n.changes.CapturedChanged, n.changes.ForwardedChanged = false, false
		return
	}
	if n.metricsKnown {
		if h.CPUPercent >= 0 && n.cpu >= 0 && FormatCPU(h.CPUPercent) != FormatCPU(n.cpu) {
			n.changes.CPU = MetricChange{Direction: direction(h.CPUPercent, n.cpu), Changed: true}
			n.cpuUntil = now.Add(metricHighlightDuration)
		}
		if h.MemoryRSSBytes != 0 && n.memory != 0 && FormatMemory(h.MemoryRSSBytes) != FormatMemory(n.memory) {
			n.changes.Memory = MetricChange{Direction: direction(h.MemoryRSSBytes, n.memory), Changed: true}
			n.memoryUntil = now.Add(metricHighlightDuration)
		}
		if h.ActiveFilters != n.filters {
			n.changes.FiltersChanged, n.changes.FilterDelta = true, int64(h.ActiveFilters)-int64(n.filters)
			n.filtersUntil = now.Add(metricHighlightDuration)
		}
		if h.PacketsCaptured < n.captured || h.PacketsForwarded < n.sent {
			n.changes.CapturedChanged, n.changes.ForwardedChanged = false, false
		} else {
			if h.PacketsCaptured > n.captured {
				n.changes.CapturedChanged = true
				n.capturedUntil = now.Add(metricHighlightDuration)
			}
			if h.PacketsForwarded > n.sent {
				n.changes.ForwardedChanged = true
				n.forwardedUntil = now.Add(metricHighlightDuration)
			}
		}
		n.changes.Activity = n.changes.CapturedChanged || n.changes.ForwardedChanged
	}
	if h.CPUPercent < 0 {
		n.changes.CPU = MetricChange{}
	}
	if h.MemoryRSSBytes == 0 {
		n.changes.Memory = MetricChange{}
	}
	n.metricsKnown = true
	n.cpu, n.memory, n.filters, n.captured, n.sent = h.CPUPercent, h.MemoryRSSBytes, h.ActiveFilters, h.PacketsCaptured, h.PacketsForwarded
}

func direction[T ~uint64 | ~float64](new, old T) int {
	if new > old {
		return 1
	}
	return -1
}

func (t *ChangeTracker) transition(key NodeKey, n *observedNode, label, text string, now time.Time) {
	n.changes.Label, n.changes.StatusChanged = label, true
	n.statusUntil = now.Add(lifecycleDuration)
	t.addEvent(key, n.name+" "+text, now)
}

// Baseline identifies a node from an initial/reconnect topology snapshot. It
// suppresses a later duplicate join without discarding existing metric state.
func (t *ChangeTracker) Baseline(key NodeKey, name string) {
	t.init()
	t.node(key, name).lifecycleKnown = true
}

// Joined announces one confirmed arrival regardless of whether status polling
// observed its metrics first. Baseline and previous joins suppress duplicates.
func (t *ChangeTracker) Joined(key NodeKey, label string, now time.Time) {
	t.init()
	if n := t.nodes[key]; n != nil && n.lifecycleKnown {
		return
	}
	n := t.node(key, label)
	n.lifecycleKnown = true
	t.transition(key, n, "NEW", "joined", now)
}

// Removed records a confirmed disconnect before deleting its tracked state.
func (t *ChangeTracker) Removed(key NodeKey, label string, now time.Time) {
	n := t.nodes[key]
	if n == nil {
		return
	}
	if label == "" {
		label = n.name
	}
	if n.changes.Label != "DISCONNECTED" {
		t.addEvent(key, label+" disconnected", now)
	}
	delete(t.nodes, key)
}

func (t *ChangeTracker) addEvent(key NodeKey, text string, now time.Time) {
	t.events = append(t.events, recentNodeEvent{key: key, text: text, at: now})
	if len(t.events) > recentEventCapacity {
		t.events = append([]recentNodeEvent(nil), t.events[len(t.events)-recentEventCapacity:]...)
	}
	t.recentText = t.RecentText(now)
}

// Snapshot returns owned copies so renderers cannot mutate change history.
func (t *ChangeTracker) Snapshot() map[NodeKey]NodeChanges {
	result := make(map[NodeKey]NodeChanges, len(t.nodes))
	for key, n := range t.nodes {
		result[key] = n.changes
	}
	return result
}

// Advance expires transients and reports changes requiring a viewport refresh.
func (t *ChangeTracker) Advance(now time.Time) bool {
	dirty := false
	for _, n := range t.nodes {
		before := n.changes
		if !now.Before(n.cpuUntil) {
			n.changes.CPU = MetricChange{}
		}
		if !now.Before(n.memoryUntil) {
			n.changes.Memory = MetricChange{}
		}
		if !now.Before(n.filtersUntil) {
			n.changes.FiltersChanged, n.changes.FilterDelta = false, 0
		}
		if !now.Before(n.capturedUntil) {
			n.changes.CapturedChanged = false
		}
		if !now.Before(n.forwardedUntil) {
			n.changes.ForwardedChanged = false
		}
		n.changes.Activity = n.changes.CapturedChanged || n.changes.ForwardedChanged
		if !now.Before(n.statusUntil) {
			n.changes.Label, n.changes.StatusChanged = "", false
		}
		dirty = dirty || before != n.changes
	}
	for len(t.events) > 0 && !now.Before(t.events[0].at.Add(recentEventDuration)) {
		t.events = t.events[1:]
	}
	recent := t.RecentText(now)
	if recent != t.recentText {
		dirty = true
		t.recentText = recent
	}
	return dirty
}

func (t *ChangeTracker) RecentText(now time.Time) string {
	count := 0
	var latest recentNodeEvent
	for _, event := range t.events {
		if now.Before(event.at.Add(recentEventDuration)) {
			count++
			latest = event
		}
	}
	if count == 0 {
		return ""
	}
	age := int(now.Sub(latest.at).Seconds())
	if age < 0 {
		age = 0
	}
	text := fmt.Sprintf("%ds ago  %s", age, strings.ReplaceAll(latest.text, "\n", " "))
	if count > 1 {
		text += fmt.Sprintf(" (+%d more)", count-1)
	}
	return text
}

func (t *ChangeTracker) Reset() { *t = ChangeTracker{} }
