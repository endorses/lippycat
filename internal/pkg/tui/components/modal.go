//go:build tui || all

package components

import (
	"image"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Modal is the lifecycle contract for hosted dialogs. Dismiss cancels only the
// visible layer, including any cancellation result and asynchronous cleanup.
type Modal interface {
	View() string
	Dismiss() tea.Cmd
}

// InteractiveModal declares actions and content targets using the same layout
// as its View. Owners handle semantics; the host owns coordinates and gestures.
type InteractiveModal interface {
	Modal
	ModalOptions() ModalRenderOptions
	HandleModalAction(string) tea.Cmd
	HandleModalFocus(string) tea.Cmd
}

// VisibleModal resolves an optional nested layer without allowing click-through.
func VisibleModal(modal Modal) Modal {
	for i := 0; i < 16 && modal != nil; i++ {
		nested, ok := modal.(interface{ ActiveModal() Modal })
		if !ok {
			break
		}
		next := nested.ActiveModal()
		if next == nil {
			break
		}
		modal = next
	}
	return modal
}

func RenderHostedModal(modal Modal, width, height int) string {
	if modal == nil {
		return ""
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, modal.View())
}

// ModalRenderOptions separates information, controls and interaction state.
type ModalRenderOptions struct {
	ID, Title, Content, Footer string
	Width, Height              int
	Theme                      themes.Theme
	ModalWidth                 int
	ShowOverlay                bool
	Actions                    []ModalAction
	Targets                    []ModalTarget
	State                      *ModalState
}

// ModalLayout contains screen coordinates for the exact rendered canvas.
type ModalLayout struct {
	View                                            string
	Bounds, ContentBounds                           image.Rectangle
	Hits                                            []ModalTarget
	ContentHeight, ContentOffset, FullContentHeight int
	Fallback                                        bool
}

func modalContentWidth(opts ModalRenderOptions) int {
	width := opts.ModalWidth
	if width == 0 {
		width = max(60, min(80, opts.Width*7/10))
	}
	return max(1, min(width+2, opts.Width-2)-6)
}

// ModalContentWidth lets content owners size rows without copying modal chrome.
func ModalContentWidth(opts ModalRenderOptions) int { return modalContentWidth(opts) }

func wrappedModalLines(text string, width int) []string {
	return strings.Split(ansi.Hardwrap(text, max(1, width), true), "\n")
}

// LayoutModal is pure: hit testing is correct even before the next View call.
func LayoutModal(opts ModalRenderOptions) ModalLayout {
	var layout ModalLayout
	if opts.Width <= 0 || opts.Height <= 0 {
		layout.Fallback = true
		return layout
	}
	width := modalContentWidth(opts)
	focus := ""
	offset := 0
	if opts.State != nil {
		focus = opts.State.Focus
		offset = opts.State.Scroll
	}
	bar := layoutActionBar(opts.Actions, focus, width, opts.Theme)
	var title, footer []string
	if opts.Title != "" {
		title = wrappedModalLines(opts.Title, width)
		title = append(title, "")
	}
	if opts.Footer != "" {
		footer = append([]string{""}, wrappedModalLines(opts.Footer, width)...)
	}
	actionHeight := len(bar.lines)
	if actionHeight > 0 {
		actionHeight++
	}
	padY := 1
	overhead := 2 + 2*padY + len(title) + len(footer) + actionHeight
	if overhead+1 > opts.Height {
		padY = 0
		overhead -= 2
	}
	if overhead+1 > opts.Height {
		// Preserve controls before optional navigation hints and title wrapping.
		footer = nil
		if opts.Title != "" {
			title = []string{ansi.Truncate(opts.Title, width, "…")}
		}
		compact := append([]ModalAction(nil), opts.Actions...)
		for i := range compact {
			compact[i].Shortcut = ""
		}
		bar = layoutActionBar(compact, focus, width, opts.Theme)
		actionHeight = len(bar.lines)
		if actionHeight > 0 {
			actionHeight++
		}
		overhead = 2 + len(title) + actionHeight
	}
	if opts.Width < 16 || opts.Height < overhead+1 {
		layout.Fallback = true
		text := ansi.Truncate("Resize terminal · Esc: Cancel", max(1, opts.Width-4), "")
		if opts.Width >= 4 && opts.Height >= 3 {
			canvas := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(opts.Theme.InfoColor).Padding(0, 1).Render(text)
			layout.View = lipgloss.Place(opts.Width, opts.Height, lipgloss.Center, lipgloss.Center, canvas)
		} else {
			layout.View = lipgloss.Place(opts.Width, opts.Height, lipgloss.Center, lipgloss.Center, ansi.Truncate(text, opts.Width, ""))
		}
		layout.Bounds = modalBounds(layout.View, opts.Width, opts.Height)
		return layout
	}
	var content []string
	var localHits []ModalTarget
	for rawY, line := range strings.Split(opts.Content, "\n") {
		parts := wrappedModalLines(line, width)
		segmentStart := 0
		for partIndex, part := range parts {
			y := len(content)
			content = append(content, part)
			// Hardwrap preserves cell columns within each source line. Intersect each
			// target with the visible segment, retaining multiple fragments for wrapping.
			segmentEnd := segmentStart + ansi.StringWidth(part)
			if partIndex == len(parts)-1 {
				segmentEnd = segmentStart + width
			}
			segment := image.Rect(segmentStart, rawY, segmentEnd, rawY+1)
			for _, target := range opts.Targets {
				fragment := target.Bounds.Intersect(segment)
				if !fragment.Empty() {
					target.Bounds = image.Rect(fragment.Min.X-segmentStart, y, fragment.Max.X-segmentStart, y+1)
					localHits = append(localHits, target)
				}
			}
			segmentStart += ansi.StringWidth(part)
		}
	}
	layout.FullContentHeight = len(content)
	layout.ContentHeight = min(len(content), opts.Height-overhead)
	offset = max(0, min(offset, len(content)-layout.ContentHeight))
	layout.ContentOffset = offset
	lines := make([]string, 0, opts.Height)
	if padY > 0 {
		lines = append(lines, "")
	}
	for _, line := range title {
		lines = append(lines, lipgloss.NewStyle().Foreground(opts.Theme.HeaderBg).Bold(true).Render(line))
	}
	contentY := len(lines)
	for _, line := range content[offset : offset+layout.ContentHeight] {
		lines = append(lines, lipgloss.NewStyle().Foreground(opts.Theme.Foreground).Render(line))
	}
	for _, line := range footer {
		lines = append(lines, lipgloss.NewStyle().Foreground(opts.Theme.StatusBarFg).Render(line))
	}
	actionY := len(lines) + 1
	if len(bar.lines) > 0 {
		lines = append(lines, "")
		lines = append(lines, bar.lines...)
	}
	if padY > 0 {
		lines = append(lines, "")
	}
	for i := range lines {
		lines[i] = fitModalLine(lines[i], width)
	}
	canvas := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(opts.Theme.InfoColor).Padding(0, 2).Render(strings.Join(lines, "\n"))
	outerWidth, outerHeight := lipgloss.Width(canvas), lipgloss.Height(canvas)
	left, top := (opts.Width-outerWidth)/2, (opts.Height-outerHeight)/2
	layout.Bounds = image.Rect(left, top, left+outerWidth, top+outerHeight)
	origin := image.Pt(left+3, top+1)
	layout.ContentBounds = image.Rect(origin.X, origin.Y+contentY, origin.X+width, origin.Y+contentY+layout.ContentHeight)
	for _, target := range localHits {
		target.Bounds = target.Bounds.Add(image.Pt(origin.X, origin.Y+contentY-offset)).Intersect(layout.ContentBounds)
		if !target.Bounds.Empty() {
			layout.Hits = append(layout.Hits, target)
		}
	}
	for _, hit := range bar.hits {
		hit.Bounds = hit.Bounds.Add(image.Pt(origin.X, origin.Y+actionY))
		layout.Hits = append(layout.Hits, hit)
	}
	layout.View = lipgloss.Place(opts.Width, opts.Height, lipgloss.Center, lipgloss.Center, canvas)
	return layout
}

func RenderModal(opts ModalRenderOptions) string { return LayoutModal(opts).View }

// modalBounds also supports legacy/modal-adapter views that have no actions.
func modalBounds(view string, width, height int) image.Rectangle {
	lines := strings.Split(ansi.Strip(view), "\n")
	if height > 0 && len(lines) > height {
		lines = lines[len(lines)-height:]
	}
	bounds := image.Rectangle{}
	for y, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		left := ansi.StringWidth(line) - ansi.StringWidth(strings.TrimLeft(line, " "))
		right := ansi.StringWidth(strings.TrimRight(line, " "))
		bounds = bounds.Union(image.Rect(left, y, right, y+1))
	}
	return bounds.Intersect(image.Rect(0, 0, width, height))
}

func HandleModalMouse(modal Modal, msg tea.MouseMsg, width, height int) (tea.Cmd, bool) {
	if modal == nil || msg.X < 0 || msg.Y < 0 || msg.X >= width || msg.Y >= height {
		return nil, false
	}
	modal = VisibleModal(modal)
	if interactive, ok := modal.(InteractiveModal); ok {
		if cmd, handled := HandleModalInput(interactive, msg); handled {
			return cmd, true
		}
	}
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress {
		return nil, false
	}
	bounds := modalBounds(RenderHostedModal(modal, width, height), width, height)
	if bounds.Empty() || image.Pt(msg.X, msg.Y).In(bounds) {
		return nil, false
	}
	return modal.Dismiss(), true
}
