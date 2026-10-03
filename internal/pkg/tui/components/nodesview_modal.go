//go:build tui || all

package components

import (
	"image"

	tea "github.com/charmbracelet/bubbletea"
)

// SetModalSize prepares terminal dimensions independently of the node viewport.
func (n *NodesView) SetModalSize(width, height int) {
	n.modalWidth = width
	n.modalHeight = height
	n.nodeInput.Width = max(1, ModalContentWidth(nodeModal{n}.ModalOptions())-2)
}

// Modal exposes the add-node dialog to the common input and geometry host.
func (n *NodesView) Modal() Modal { return nodeModal{n} }

type nodeModal struct{ nodes *NodesView }

func (m nodeModal) View() string {
	if !m.nodes.showModal {
		return ""
	}
	return RenderModal(m.ModalOptions())
}
func (m nodeModal) Dismiss() tea.Cmd { m.nodes.HideAddNodeModal(); return nil }
func (m nodeModal) ModalOptions() ModalRenderOptions {
	n := m.nodes
	width, height := n.modalWidth, n.modalHeight
	if width == 0 {
		width = n.width
	}
	if height == 0 {
		height = n.height
	}
	footer := ""
	if len(n.nodeHistory) > 0 {
		footer = "↑/↓: History"
	}
	return ModalRenderOptions{ID: "add-node", Title: "Add Node", Content: "Address (host:port):\n" + n.nodeInput.View(), Footer: footer, Width: width, Height: height, Theme: n.theme, ModalWidth: 60, State: &n.modalState,
		Targets: []ModalTarget{{ID: "address", Bounds: image.Rect(0, 0, ModalContentWidth(ModalRenderOptions{Width: width, ModalWidth: 60}), 2), Focusable: true}},
		Actions: []ModalAction{{ID: "confirm", Label: "Confirm", Shortcut: "Enter", Kind: ButtonPrimary, Disabled: n.nodeInput.Value() == ""}, {ID: "cancel", Label: "Cancel", Shortcut: "Esc"}}}
}
func (m nodeModal) HandleModalFocus(id string) tea.Cmd {
	if id == "address" {
		return m.nodes.nodeInput.Focus()
	}
	m.nodes.nodeInput.Blur()
	return nil
}
func (m nodeModal) HandleModalAction(id string) tea.Cmd {
	n := m.nodes
	if !n.showModal {
		return nil
	}
	switch id {
	case "cancel":
		return m.Dismiss()
	case "confirm":
		addr := n.nodeInput.Value()
		if addr == "" {
			return nil
		}
		n.AddNodeToHistory(addr)
		n.HideAddNodeModal()
		return func() tea.Msg { return AddNodeMsg{Address: addr} }
	case "address":
		return m.HandleModalFocus(id)
	}
	return nil
}
