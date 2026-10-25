//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestEventsViewOfflineClockMatchesPCAPPresentation(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("display-test", 5*3600+5*60)
	t.Cleanup(func() { time.Local = previous })
	event := noticefixture.Event()
	before := event.Envelope().Timestamp
	items := []EventItem{{Event: event, ArrivalSequence: 1}}
	v := NewEventsView()
	v.EnableVirtualEvents(1)
	v.SetVirtualWindow(1, 0, items)
	v.SetVirtualDetail(&items[0])
	v.PrepareLayout(140, 12, 80, 30)
	require.Contains(t, v.RenderTimeline(140, 12, false), before.Local().Format("15:04:05.000"))
	require.Contains(t, v.RenderDetails(80, 30, false), before.Local().Format("2006-01-02 15:04:05.000000"))
	require.Equal(t, before, event.Envelope().Timestamp, "display conversion leaves canonical evidence unchanged")
	v.SetEvents(items)
	v.PrepareLayout(140, 12, 80, 30)
	require.Contains(t, v.RenderTimeline(140, 12, false), before.Format("15:04:05.000"), "live/remote display behavior remains unchanged")
}
