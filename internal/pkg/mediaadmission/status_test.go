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

func TestMissingMediaExpectationRevisionAndAlertPrivacy(t *testing.T) {
	now := time.Now()
	d := NewDiagnostics(2, time.Second)
	owner := OwnerID{Session: 9, Generation: 8, CallID: "synthetic-secret-identity"}
	d.Selection(owner, 0, true, true, now)
	d.Expectation(owner, 0, true, true, 1, now)
	d.Attributed(owner)
	require.Zero(t, d.Snapshot(now.Add(2*time.Second)).SelectedAnsweredWithoutMedia)
	d.Expectation(owner, 0, true, true, 2, now.Add(2*time.Second))
	require.Zero(t, d.Snapshot(now.Add(2*time.Second)).SelectedAnsweredWithoutMedia)
	alerts := d.MissingAlerts(now.Add(4 * time.Second))
	require.Len(t, alerts, 1)
	require.NotZero(t, alerts[0].Reference)
	require.Empty(t, d.MissingAlerts(now.Add(4500*time.Millisecond)), "rate limited per owner")
	require.Len(t, d.MissingAlerts(now.Add(6*time.Second)), 1)
	d.Expectation(owner, 0, false, true, 3, now.Add(7*time.Second))
	require.Equal(t, 1, d.Snapshot(now.Add(9*time.Second)).UnknownExpectation)
	require.Empty(t, d.MissingAlerts(now.Add(9*time.Second)))
	d.Expectation(owner, 0, true, false, 4, now.Add(10*time.Second))
	require.Equal(t, 1, d.Snapshot(now.Add(12*time.Second)).InactiveSelected)
	require.Empty(t, d.MissingAlerts(now.Add(12*time.Second)))
}

func TestMissingMediaPacketPressureCannotCreateFalseAlert(t *testing.T) {
	now := time.Now()
	owner := OwnerID{Session: 1, Generation: 1}
	d := NewDiagnostics(2, time.Second)
	d.Selection(owner, 0, true, true, now)
	d.mu.Lock()
	d.Attributed(owner)
	d.mu.Unlock()
	require.Equal(t, uint64(1), d.Snapshot(now.Add(2*time.Second)).AttributionDropped)
	require.Equal(t, 1, d.Snapshot(now.Add(2*time.Second)).ObservationUncertain)
	require.Empty(t, d.MissingAlerts(now.Add(2*time.Second)))
	d.Attributed(owner)
	require.Zero(t, d.Snapshot(now.Add(3*time.Second)).ObservationUncertain)
	require.Zero(t, d.Snapshot(now.Add(3*time.Second)).SelectedAnsweredWithoutMedia)
}
