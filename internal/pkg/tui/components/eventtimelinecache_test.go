//go:build tui || all

package components

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestTimelineCacheBoundedAndReusesVisibleRows(t *testing.T) {
	v := NewEventsView()
	items := make([]EventItem, 1000)
	for i := range items {
		items[i] = EventItem{Event: dnsEvent(fmt.Sprint(i), fmt.Sprintf("query-%d.example", i))}
	}
	v.SetEvents(items)
	v.PrepareLayout(120, 12, 0, 0)
	require.Len(t, v.timelineCache.rows, 7)
	first := &v.timelineCache.rows[0]
	v.AppendEvents([]EventItem{{Event: dnsEvent("new", "new.example")}})
	v.PrepareLayout(120, 12, 0, 0)
	require.Same(t, first, &v.timelineCache.rows[0], "offscreen append must not rebuild visible rows")
	v.SetSelectedID("3")
	v.PrepareLayout(120, 12, 0, 0)
	require.Equal(t, first.normal, v.timelineCache.rows[0].normal)
	require.NotEmpty(t, v.timelineCache.rows[3].selected)
	v.SetSelectedID("999")
	v.PrepareLayout(120, 12, 0, 0)
	require.Len(t, v.timelineCache.rows, 7)
	require.NotContains(t, v.timelineCache.rows[0].plain, "query-0.example")
	v.PrepareLayout(120, 6, 0, 0)
	require.Len(t, v.timelineCache.rows, 1)
	require.Equal(t, 1, cap(v.timelineCache.rows), "shrinking viewport must release old rows")
}

func TestTimelineCacheSnapshotAndFallbackInvalidation(t *testing.T) {
	v := NewEventsView()
	v.SetEvents([]EventItem{{Event: dnsEvent("same", "first.example")}})
	v.PrepareLayout(120, 12, 0, 0)
	before := v.timelineCache
	_ = v.RenderTimeline(70, 9, false)
	require.Equal(t, before, v.timelineCache, "fallback render must not mutate cache")
	v.SetEvents([]EventItem{{Event: dnsEvent("same", "replacement.example")}})
	v.PrepareLayout(120, 12, 0, 0)
	require.Contains(t, v.timelineCache.rows[0].plain, "replacement.example")
	require.NotEqual(t, before.generation, v.timelineCache.generation)
	theme := v.theme
	theme.DNSColor = "1"
	v.SetTheme(theme)
	v.PrepareLayout(120, 12, 0, 0)
	require.Equal(t, theme, v.timelineCache.theme)
	require.Equal(t, theme, v.timelineCache.pane.theme)
}

// Kind is only queried while formatting rows; stable ID lookups use Envelope.
type timelineCountingEvent struct {
	events.Event
	calls *int
}

func (e timelineCountingEvent) Kind() events.Kind { *e.calls++; return e.Event.Kind() }

func TestTimelineCacheFormatsOnlyNewVisibleRows(t *testing.T) {
	v := NewEventsView()
	counts := make([]int, 1000)
	items := make([]EventItem, len(counts))
	for i := range items {
		items[i].Event = timelineCountingEvent{dnsEvent(fmt.Sprint(i), "example.org"), &counts[i]}
	}
	v.SetEvents(items)
	v.PrepareLayout(120, 12, 0, 0)
	for i, count := range counts {
		if i < 7 {
			require.Positive(t, count)
		} else {
			require.Zero(t, count)
		}
	}
	before := append([]int(nil), counts...)
	v.PrepareLayout(120, 12, 0, 0)
	_ = v.RenderTimeline(120, 12, true)
	_ = v.RenderTimeline(120, 12, false)
	v.SetSelectedID("3")
	v.PrepareLayout(120, 12, 0, 0)
	require.Equal(t, before, counts, "selection/focus/repeated update must reuse formatted rows")
	v.SetSelectedID("7")
	v.PrepareLayout(120, 12, 0, 0)
	require.Positive(t, counts[7])
	for i := range counts {
		if i != 7 {
			require.Equal(t, before[i], counts[i])
		}
	}
}
