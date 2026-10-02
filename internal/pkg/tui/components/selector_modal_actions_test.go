//go:build tui || all

package components

import (
	"fmt"
	"image"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func selectorHit(t *testing.T, opts ModalRenderOptions, id string) image.Rectangle {
	t.Helper()
	for _, hit := range LayoutModal(opts).Hits {
		if hit.ID == id {
			return hit.Bounds
		}
	}
	t.Fatalf("missing target %q", id)
	return image.Rectangle{}
}

func selectorClick(rect image.Rectangle) tea.MouseMsg {
	return tea.MouseMsg{X: rect.Min.X, Y: rect.Min.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
}

func TestProtocolModalRowsStableAndMouseKeyboardParity(t *testing.T) {
	ps := NewProtocolSelector()
	ps.SetSize(100, 35)
	ps.Activate()
	before := selectorHit(t, ps.ModalOptions(), "protocol:2")
	require.Nil(t, ps.Update(selectorClick(before)))
	require.Equal(t, "DNS", ps.GetSelected().Name)
	require.Equal(t, before, selectorHit(t, ps.ModalOptions(), "protocol:2"))
	cmd := ps.Update(selectorClick(selectorHit(t, ps.ModalOptions(), "apply")))
	require.NotNil(t, cmd)
	mouse := cmd().(ProtocolSelectedMsg)
	require.False(t, ps.IsActive())
	ps.Activate()
	ps.selected = 2
	cmd = ps.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.Equal(t, mouse, cmd())
}

func TestProtocolModalClickIdentityResets(t *testing.T) {
	ps := NewProtocolSelector()
	ps.SetSize(100, 35)
	ps.Activate()
	now := time.Unix(100, 0)
	require.Nil(t, ps.selectProtocolAt(2, now))
	require.Nil(t, ps.selectProtocolAt(3, now.Add(10*time.Millisecond)))
	cmd := ps.selectProtocolAt(3, now.Add(20*time.Millisecond))
	require.NotNil(t, cmd)
	require.Equal(t, "HTTP", cmd().(ProtocolSelectedMsg).Protocol.Name)
	ps.Activate()
	require.Nil(t, ps.selectProtocolAt(2, now))
	ps.ScrollModal(1)
	require.Nil(t, ps.selectProtocolAt(2, now.Add(20*time.Millisecond)))
	ps.SetSize(80, 30)
	require.Nil(t, ps.selectProtocolAt(2, now.Add(30*time.Millisecond)))
	ps.Deactivate()
	ps.Activate()
	require.Nil(t, ps.selectProtocolAt(2, now.Add(40*time.Millisecond)))
}

func TestProtocolModalShortViewport(t *testing.T) {
	ps := NewProtocolSelector()
	ps.SetSize(60, 15)
	ps.Activate()
	require.Less(t, ps.visibleRows(), len(ps.protocols))
	for range len(ps.protocols) - 1 {
		ps.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	require.Equal(t, len(ps.protocols)-1, ps.selected)
	selectorHit(t, ps.ModalOptions(), "protocol:8")
	opts := ps.ModalOptions()
	require.Contains(t, ansi.Strip(opts.Content), ps.GetSelected().Description)
	selectorHit(t, opts, "apply")
}

func TestHunterModalLocalSelectionAndRefreshIdentity(t *testing.T) {
	hs := NewHunterSelector()
	hs.SetSize(100, 35)
	hs.Activate("processor")
	input := []HunterSelectorItem{{HunterID: "one"}, {HunterID: "two", Selected: true}}
	hs.SetHunters(input)
	hs.Update(selectorClick(selectorHit(t, hs.ModalOptions(), "hunter:one")))
	require.False(t, input[0].Selected, "unconfirmed choices must remain local")
	require.Equal(t, []string{"one", "two"}, hs.GetSelectedHunterIDs())
	hs.SetHunters([]HunterSelectorItem{{HunterID: "two"}, {HunterID: "one"}})
	require.Equal(t, "one", hs.hunters[hs.cursorIndex].HunterID)
	require.Equal(t, []string{"two", "one"}, hs.GetSelectedHunterIDs())
	hs.HandleModalAction("none")
	cmd := hs.HandleModalAction("confirm")
	result := cmd().(HunterSelectionConfirmedMsg)
	require.Equal(t, "processor", result.ProcessorAddr)
	require.NotNil(t, result.SelectedHunterIDs, "empty is an explicit subscription to none")
	require.Empty(t, result.SelectedHunterIDs)
	hs.Activate("processor")
	hs.SetHunters(input)
	hs.HandleModalAction("all")
	require.Len(t, hs.GetSelectedHunterIDs(), 2)
	require.Nil(t, hs.HandleModalAction("cancel"))
	require.False(t, hs.IsActive())
}

func TestHunterModalScrollAndPendingActions(t *testing.T) {
	hs := NewHunterSelector()
	hs.SetSize(70, 17)
	hs.Activate("processor")
	require.Nil(t, hs.HandleModalAction("confirm"))
	require.True(t, hs.IsActive())
	hunters := make([]HunterSelectorItem, 20)
	for i := range hunters {
		hunters[i].HunterID = fmt.Sprint(i)
	}
	hs.SetHunters(hunters)
	first := selectorHit(t, hs.ModalOptions(), "hunter:0")
	wheel := selectorClick(first)
	wheel.Button = tea.MouseButtonWheelDown
	hs.Update(wheel)
	require.Equal(t, 1, hs.rowOffset)
	selectorHit(t, hs.ModalOptions(), "hunter:1")
}

func TestConfirmationModalPayloadAndContextualButtons(t *testing.T) {
	for _, id := range []string{"confirm", "cancel"} {
		t.Run(id, func(t *testing.T) {
			c := NewConfirmDialog()
			c.SetSize(100, 35)
			c.Show(ConfirmDialogOptions{Title: "Delete filter", Message: "Delete?", Type: ConfirmDialogDanger, ConfirmText: "Delete", CancelText: "Keep", UserData: "filter-id"})
			opts := c.ModalOptions()
			require.Equal(t, "Delete", opts.Actions[0].Label)
			require.Equal(t, ButtonDanger, opts.Actions[0].Kind)
			cmd := c.Update(selectorClick(selectorHit(t, opts, id)))
			require.NotNil(t, cmd)
			require.Equal(t, ConfirmDialogResult{Confirmed: id == "confirm", UserData: "filter-id"}, cmd())
			require.False(t, c.IsActive())
		})
	}
}

func TestNodeModalFocusAndSubmission(t *testing.T) {
	n := NewNodesView()
	n.SetModalSize(100, 30)
	n.ShowAddNodeModal()
	m := nodeModal{&n}
	require.Nil(t, m.HandleModalAction("confirm"))
	require.True(t, n.IsModalOpen())
	n.nodeInput.SetValue("localhost:55555")
	n.Update(tea.KeyMsg{Type: tea.KeyTab})
	require.False(t, n.nodeInput.Focused())
	n.Update(selectorClick(selectorHit(t, m.ModalOptions(), "address")))
	require.True(t, n.nodeInput.Focused())
	cmd := n.Update(selectorClick(selectorHit(t, m.ModalOptions(), "confirm")))
	require.NotNil(t, cmd)
	require.Equal(t, AddNodeMsg{Address: "localhost:55555"}, cmd())
	require.False(t, n.IsModalOpen())
	require.Equal(t, []string{"localhost:55555"}, n.nodeHistory)
}
