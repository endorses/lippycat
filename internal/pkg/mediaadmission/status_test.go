package mediaadmission

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMissingMediaDiagnosticsRemainBoundedAndInformational(t *testing.T) {
	now := time.Now()
	d := NewDiagnostics(2, time.Second)
	a := OwnerID{Session: 1, Generation: 1, CallID: "a"}
	b := OwnerID{Session: 1, Generation: 2, CallID: "b"}
	c := OwnerID{Session: 1, Generation: 3, CallID: "c"}
	d.Selection(a, 0, true, true, now)
	d.Selection(b, 0, true, false, now)
	d.Selection(c, 0, true, true, now)
	early := d.Snapshot(now.Add(time.Millisecond))
	require.Zero(t, early.SelectedAnsweredWithoutMedia)
	require.Equal(t, uint64(1), early.TrackingRejected)
	late := d.Snapshot(now.Add(2 * time.Second))
	require.Equal(t, 1, late.SelectedAnsweredWithoutMedia)
	require.Equal(t, 2, late.Tracked)
	d.Attributed(a)
	require.Zero(t, d.Snapshot(now.Add(3*time.Second)).SelectedAnsweredWithoutMedia)
	d.Finalized(a)
	require.Equal(t, 1, d.Snapshot(now).Tracked)
}
