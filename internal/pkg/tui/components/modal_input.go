//go:build tui || all

package components

import (
	"image"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func modalFocusTargets(opts ModalRenderOptions) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, target := range opts.Targets {
		if target.Focusable && !target.Disabled && !seen[target.ID] {
			ids = append(ids, target.ID)
			seen[target.ID] = true
		}
	}
	for _, action := range opts.Actions {
		if !action.Disabled && !seen[action.ID] {
			ids = append(ids, action.ID)
			seen[action.ID] = true
		}
	}
	return ids
}

func modalAction(opts ModalRenderOptions, id string) (ModalAction, bool) {
	for _, action := range opts.Actions {
		if action.ID == id {
			return action, true
		}
	}
	return ModalAction{}, false
}

// EnsureModalTargetVisible adjusts only interaction state, never rendered data.
func EnsureModalTargetVisible(opts ModalRenderOptions, id string) {
	if opts.State == nil {
		return
	}
	if _, button := modalAction(opts, id); button {
		return
	}
	// Obtain the unscrolled target position through the same layout calculation.
	state := *opts.State
	state.Scroll = 0
	probe := opts
	probe.State = &state
	layout := LayoutModal(probe)
	if layout.Fallback {
		return
	}
	// A probe with a tall canvas exposes targets below the current viewport.
	probe.Height = max(opts.Height, layout.FullContentHeight+opts.Height)
	full := LayoutModal(probe)
	for _, hit := range full.Hits {
		if hit.ID != id {
			continue
		}
		start := hit.Bounds.Min.Y - full.ContentBounds.Min.Y
		end := hit.Bounds.Max.Y - full.ContentBounds.Min.Y
		if start < opts.State.Scroll {
			opts.State.Scroll = start
		}
		if end > opts.State.Scroll+layout.ContentHeight {
			opts.State.Scroll = max(0, end-layout.ContentHeight)
		}
		return
	}
}

// HandleModalInput handles shared controls. Ordinary editing/navigation keys are
// left to the owner; shortcuts are not synthesized into a focused text field.
func HandleModalInput(modal InteractiveModal, msg tea.Msg) (tea.Cmd, bool) {
	if visible, ok := VisibleModal(modal).(InteractiveModal); ok {
		modal = visible
	}
	opts := modal.ModalOptions()
	state := opts.State
	if state == nil {
		return nil, false
	}
	if opts.ID != state.context {
		if state.context != "" {
			state.Reset()
		}
		state.context = opts.ID
	}
	if state.width != opts.Width || state.height != opts.Height {
		state.ResetClicks()
		state.width, state.height = opts.Width, opts.Height
	}
	order := modalFocusTargets(opts)
	if state.Focus != "" {
		valid := false
		for _, id := range order {
			if id == state.Focus {
				valid = true
				break
			}
		}
		if !valid {
			state.Focus = ""
			if len(order) > 0 {
				state.Focus = order[0]
			}
			modal.HandleModalFocus(state.Focus)
		}
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		state.ResetClicks()
		return nil, false
	case tea.KeyMsg:
		state.ResetClicks()
		if msg.Type == tea.KeyTab || msg.Type == tea.KeyShiftTab {
			if len(order) == 0 {
				return nil, true
			}
			index := -1
			for i, id := range order {
				if id == state.Focus {
					index = i
					break
				}
			}
			if msg.Type == tea.KeyShiftTab {
				if index < 0 {
					index = 0
				}
				index = (index - 1 + len(order)) % len(order)
			} else {
				index = (index + 1) % len(order)
			}
			state.Focus = order[index]
			cmd := modal.HandleModalFocus(state.Focus)
			EnsureModalTargetVisible(modal.ModalOptions(), state.Focus)
			return cmd, true
		}
		if action, ok := modalAction(opts, state.Focus); ok {
			if msg.Type == tea.KeyEnter || msg.Type == tea.KeySpace || msg.String() == " " {
				if !action.Disabled {
					return modal.HandleModalAction(action.ID), true
				}
				return nil, true
			}
			for _, shortcut := range opts.Actions {
				if shortcut.Disabled {
					continue
				}
				keys := append([]string{strings.ToLower(shortcut.Shortcut)}, shortcut.Keys...)
				for _, key := range keys {
					if key != "" && key == msg.String() {
						return modal.HandleModalAction(shortcut.ID), true
					}
				}
			}
			if owner, ok := modal.(interface {
				ModalShortcut(tea.KeyMsg) (tea.Cmd, bool)
			}); ok {
				if cmd, handled := owner.ModalShortcut(msg); handled {
					return cmd, true
				}
			}
			// Editing keys never leak into a field when an action has focus.
			if msg.Type != tea.KeyEsc && msg.Type != tea.KeyCtrlC {
				return nil, true
			}
		}
	case tea.MouseMsg:
		layout := LayoutModal(opts)
		point := image.Pt(msg.X, msg.Y)
		if msg.Action != tea.MouseActionPress {
			return nil, false
		}
		if msg.Button == tea.MouseButtonWheelUp || msg.Button == tea.MouseButtonWheelDown {
			state.ResetClicks()
			if !point.In(layout.ContentBounds) {
				return nil, false
			}
			delta := 1
			if msg.Button == tea.MouseButtonWheelUp {
				delta = -1
			}
			if scroller, ok := modal.(interface{ ScrollModalAt(int, int, int) tea.Cmd }); ok {
				return scroller.ScrollModalAt(delta, msg.X-layout.ContentBounds.Min.X, msg.Y-layout.ContentBounds.Min.Y+layout.ContentOffset), true
			}
			if scroller, ok := modal.(interface{ ScrollModal(int) tea.Cmd }); ok {
				return scroller.ScrollModal(delta), true
			}
			state.Scroll = max(0, min(layout.ContentOffset+delta, layout.FullContentHeight-layout.ContentHeight))
			return nil, true
		}
		if msg.Button != tea.MouseButtonLeft || layout.Fallback {
			return nil, false
		}
		for i := len(layout.Hits) - 1; i >= 0; i-- {
			hit := layout.Hits[i]
			if !point.In(hit.Bounds) {
				continue
			}
			if hit.Disabled {
				return nil, true
			}
			if hit.Focusable {
				state.Focus = hit.ID
				focusCmd := modal.HandleModalFocus(hit.ID)
				return tea.Batch(focusCmd, modal.HandleModalAction(hit.ID)), true
			}
			return modal.HandleModalAction(hit.ID), true
		}
	}
	return nil, false
}
