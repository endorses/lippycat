package components

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ToastType defines the type/severity of a toast notification
type ToastType int

const (
	ToastSuccess ToastType = iota
	ToastError
	ToastInfo
	ToastWarning
)

// Toast duration constants
const (
	ToastDurationShort  = 2 * time.Second // Short notification (e.g., action acknowledged)
	ToastDurationNormal = 3 * time.Second // Normal notification (e.g., operation started)
	ToastDurationLong   = 5 * time.Second // Long notification (e.g., operation completed, error messages)
)

// toastQueueItem represents a queued toast notification
type toastQueueItem struct {
	message   string
	toastType ToastType
	duration  time.Duration
}

// Toast represents a temporary notification that appears at the top-center of the screen
type Toast struct {
	active    bool
	message   string
	toastType ToastType
	startTime time.Time
	duration  time.Duration
	theme     themes.Theme
	width     int
	height    int
	queue     []toastQueueItem // Queue of pending toasts
}

// ToastTickMsg is sent periodically to check if the toast should be dismissed
type ToastTickMsg struct {
	Time time.Time
}

// NewToast creates a new Toast component
func NewToast() Toast {
	return Toast{
		active:   false,
		duration: ToastDurationShort, // Default short duration
	}
}

// Show displays a toast notification with the given message, type, and duration
// If a toast is already active, the new one is queued
func (t *Toast) Show(message string, toastType ToastType, duration time.Duration) tea.Cmd {
	if t.active {
		// Already showing a toast - add to queue
		t.queue = append(t.queue, toastQueueItem{
			message:   message,
			toastType: toastType,
			duration:  duration,
		})
		return nil // No command needed - will show when current toast expires
	}

	// Show the toast immediately
	t.active = true
	t.message = message
	t.toastType = toastType
	t.startTime = time.Now()
	t.duration = duration

	// Start a ticker to check for auto-dismiss
	return t.tickCmd()
}

// Hide immediately dismisses the toast
func (t *Toast) Hide() {
	t.active = false
}

// IsActive returns whether the toast is currently visible
func (t *Toast) IsActive() bool {
	return t.active
}

// SetTheme updates the toast's theme
func (t *Toast) SetTheme(theme themes.Theme) {
	t.theme = theme
}

// SetSize updates the toast's layout dimensions
func (t *Toast) SetSize(width, height int) {
	t.width = width
	t.height = height
}

// Update handles messages for the toast component
func (t *Toast) Update(msg tea.Msg) tea.Cmd {
	if !t.active {
		return nil
	}

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// Handle mouse clicks to dismiss toast
		if msg.Type == tea.MouseLeft {
			// Calculate toast bounds
			// Toast is in the bottom area (4 lines from bottom: 3 for toast + 1 for footer)
			content := " " + t.getIcon() + " " + t.message + " "
			toastWidth := lipgloss.Width(content) + 4 // +4 for padding (2 on each side)
			toastHeight := 3                          // 1 line content + 2 lines vertical padding

			// Toast is centered horizontally and positioned at bottom (above footer)
			toastX := (t.width - toastWidth) / 2
			toastY := t.height - 5 // Bottom area is 5 lines from bottom (3 for toast + 1 for footer + offset)

			// Check if click is within toast bounds
			if msg.X >= toastX && msg.X < toastX+toastWidth &&
				msg.Y >= toastY && msg.Y < toastY+toastHeight {
				// Click is inside toast - dismiss it
				t.Hide()

				// Check if there's a queued toast to show
				if len(t.queue) > 0 {
					next := t.queue[0]
					t.queue = t.queue[1:]
					return t.Show(next.message, next.toastType, next.duration)
				}
				return nil
			}
		}

	case ToastTickMsg:
		// Check if toast should be dismissed
		elapsed := msg.Time.Sub(t.startTime)
		if elapsed >= t.duration {
			t.Hide()

			// Check if there's a queued toast to show
			if len(t.queue) > 0 {
				// Get the next toast from queue
				next := t.queue[0]
				t.queue = t.queue[1:] // Remove from queue

				// Show the next toast
				return t.Show(next.message, next.toastType, next.duration)
			}
			return nil
		}
		// Continue ticking
		return t.tickCmd()
	}

	return nil
}

// tickCmd returns a command that sends a ToastTickMsg after a short delay
func (t *Toast) tickCmd() tea.Cmd {
	return tea.Tick(constants.TUITickInterval, func(time time.Time) tea.Msg {
		return ToastTickMsg{Time: time}
	})
}

// getIcon returns the icon for the current toast type
func (t *Toast) getIcon() string {
	switch t.toastType {
	case ToastSuccess:
		return "✓"
	case ToastError:
		return "✗"
	case ToastInfo:
		return "ⓘ " // Circled lowercase i (U+24D8) with extra space for visual spacing
	case ToastWarning:
		return "‼" // Double exclamation mark (U+203C)
	default:
		return "ⓘ "
	}
}

// View renders the toast notification
func (t *Toast) View() string {
	if !t.active {
		return ""
	}

	// Get colors based on toast type
	var bgColor, fgColor string
	switch t.toastType {
	case ToastSuccess:
		bgColor = "#859900" // Solarized green
		fgColor = "#fdf6e3" // Solarized base3
	case ToastError:
		bgColor = "#dc322f" // Solarized red
		fgColor = "#fdf6e3" // Solarized base3
	case ToastInfo:
		bgColor = "#268bd2" // Solarized blue
		fgColor = "#fdf6e3" // Solarized base3
	case ToastWarning:
		bgColor = "#b58900" // Solarized yellow
		fgColor = "#fdf6e3" // Solarized base3
	}

	// Build toast content with icon and message
	content := " " + t.getIcon() + " " + t.message + " "

	// Style the toast with background color only (no border)
	// Add vertical padding (1 line above, 1 line below)
	toastStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(fgColor)).
		Background(lipgloss.Color(bgColor)).
		Padding(1, 2) // Vertical padding of 1, horizontal padding of 2

	styledContent := toastStyle.Render(content)

	// Center the toast horizontally
	return lipgloss.PlaceHorizontal(
		t.width,
		lipgloss.Center,
		styledContent,
	)
}
