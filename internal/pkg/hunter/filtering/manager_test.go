//go:build hunter || all

package filtering

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

type recordingRestarter struct {
	calls   int
	filters [][]*management.Filter
}

func (r *recordingRestarter) Restart(filters []*management.Filter) error {
	r.calls++
	r.filters = append(r.filters, append([]*management.Filter(nil), filters...))
	return nil
}

type noopDisconnectMarker struct{}

func (noopDisconnectMarker) MarkDisconnected() {}

type recordingApplicationUpdater struct {
	calls   int
	filters [][]*management.Filter
}

func (u *recordingApplicationUpdater) UpdateFilters(filters []*management.Filter) {
	u.calls++
	u.filters = append(u.filters, append([]*management.Filter(nil), filters...))
}

func TestModifyIsIdempotentUpsertForApplicationFilters(t *testing.T) {
	restarter := &recordingRestarter{}
	updater := &recordingApplicationUpdater{}
	manager := New("hunter-b", restarter, noopDisconnectMarker{})
	manager.SetApplicationFilterUpdater(updater)

	filter := &management.Filter{
		Id:      "retargeted-filter",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "alice@example.com",
	}
	modify := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_MODIFY,
		Filter:     filter,
	}

	// A hunter newly included in the target scope receives MODIFY despite not
	// having seen the original ADD. It must install the filter immediately.
	manager.handleUpdate(modify)
	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, filter, manager.GetFilters()[0])
	require.Equal(t, 1, updater.calls)
	require.Zero(t, restarter.calls)

	// Replaying the same update is a no-op: no duplicate and no rebuild.
	manager.handleUpdate(modify)
	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, 1, updater.calls)
	require.Zero(t, restarter.calls)

	changed := &management.Filter{
		Id:      filter.Id,
		Type:    filter.Type,
		Pattern: "bob@example.com",
	}
	manager.handleUpdate(&management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_MODIFY,
		Filter:     changed,
	})
	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, changed, manager.GetFilters()[0])
	require.Equal(t, 2, updater.calls)
	require.Zero(t, restarter.calls)
}

func TestModifyUpsertRebuildsBPFStateOncePerEffectiveChange(t *testing.T) {
	restarter := &recordingRestarter{}
	manager := New("hunter-b", restarter, noopDisconnectMarker{})
	filter := &management.Filter{
		Id:      "gpu-capable-filter",
		Type:    management.FilterType_FILTER_BPF,
		Pattern: "udp port 5060",
	}
	modify := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_MODIFY,
		Filter:     filter,
	}

	manager.handleUpdate(modify)
	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, 1, restarter.calls)

	manager.handleUpdate(modify)
	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, 1, restarter.calls)

	manager.handleUpdate(&management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_DELETE,
		Filter:     filter,
	})
	require.Empty(t, manager.GetFilters())
	require.Equal(t, 2, restarter.calls)

	// Replayed deletion is harmless and does not rebuild state again.
	manager.handleUpdate(&management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_DELETE,
		Filter:     filter,
	})
	require.Equal(t, 2, restarter.calls)
}

func TestModifyCollapsesDuplicateIDs(t *testing.T) {
	updater := &recordingApplicationUpdater{}
	manager := New("hunter", &recordingRestarter{}, noopDisconnectMarker{})
	manager.SetApplicationFilterUpdater(updater)
	manager.filters = []*management.Filter{
		{Id: "same", Type: management.FilterType_FILTER_SIP_USER, Pattern: "old-a"},
		{Id: "same", Type: management.FilterType_FILTER_SIP_USER, Pattern: "old-b"},
	}

	manager.handleUpdate(&management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_MODIFY,
		Filter: &management.Filter{
			Id: "same", Type: management.FilterType_FILTER_SIP_USER, Pattern: "new",
		},
	})

	require.Len(t, manager.GetFilters(), 1)
	require.Equal(t, "new", manager.GetFilters()[0].Pattern)
	require.Equal(t, 1, updater.calls)
}

func TestInvalidUpdateIsNoOp(t *testing.T) {
	restarter := &recordingRestarter{}
	manager := New("hunter", restarter, noopDisconnectMarker{})

	require.NotPanics(t, func() { manager.handleUpdate(nil) })
	require.NotPanics(t, func() { manager.handleUpdate(&management.FilterUpdate{}) })
	require.Empty(t, manager.GetFilters())
	require.Zero(t, restarter.calls)
}
