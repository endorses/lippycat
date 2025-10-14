//go:build tui || all
// +build tui all

package filtermanager

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HunterSelectorItem represents a hunter for selection UI
type HunterSelectorItem struct {
	HunterID string
	Hostname string
}

// RenderFormParams holds input parameters for rendering the filter form
type RenderFormParams struct {
	FilterID      string
	FilterType    management.FilterType
	PatternInput  textinput.Model
	DescInput     textinput.Model
	Enabled       bool
	TargetHunters []string
	ActiveField   int
	IsEditMode    bool
	Theme         themes.Theme
}

// RenderForm renders the add/edit filter form
func RenderForm(params RenderFormParams) string {
	var content strings.Builder

	labelStyle := lipgloss.NewStyle().
		Foreground(params.Theme.HeaderBg).
		Bold(true)
	valueStyle := lipgloss.NewStyle().
		Foreground(params.Theme.Foreground)
	activeIndicator := lipgloss.NewStyle().
		Foreground(params.Theme.SelectionBg).
		Bold(true).
		Render("→")
	inactiveIndicator := " "

	// Pattern field
	indicator := inactiveIndicator
	if params.ActiveField == 0 {
		indicator = activeIndicator
	}
	content.WriteString(fmt.Sprintf("%s %s\n", indicator, labelStyle.Render("Pattern:")))
	content.WriteString("  " + params.PatternInput.View() + "\n\n")

	// Description field
	indicator = inactiveIndicator
	if params.ActiveField == 1 {
		indicator = activeIndicator
	}
	content.WriteString(fmt.Sprintf("%s %s\n", indicator, labelStyle.Render("Description:")))
	content.WriteString("  " + params.DescInput.View() + "\n\n")

	// Filter type field
	indicator = inactiveIndicator
	if params.ActiveField == 2 {
		indicator = activeIndicator
	}
	typeStr := AbbreviateType(params.FilterType)
	content.WriteString(fmt.Sprintf("%s %s %s\n\n",
		indicator,
		labelStyle.Render("Type:"),
		valueStyle.Render(typeStr+" (Ctrl+T to cycle)")))

	// Enabled field
	indicator = inactiveIndicator
	if params.ActiveField == 3 {
		indicator = activeIndicator
	}
	enabledStr := "✗ Disabled"
	if params.Enabled {
		enabledStr = "✓ Enabled"
	}
	content.WriteString(fmt.Sprintf("%s %s %s\n\n",
		indicator,
		labelStyle.Render("Status:"),
		valueStyle.Render(enabledStr+" (Ctrl+E to toggle)")))

	// Target hunters field
	indicator = inactiveIndicator
	if params.ActiveField == 4 {
		indicator = activeIndicator
	}
	targetStr := "All hunters"
	if len(params.TargetHunters) > 0 {
		targetStr = strings.Join(params.TargetHunters, ", ")
	}
	targetHint := ""
	if params.ActiveField == 4 {
		targetHint = " (press s to select)"
	}
	content.WriteString(fmt.Sprintf("%s %s %s\n",
		indicator,
		labelStyle.Render("Targets:"),
		valueStyle.Render(targetStr+targetHint)))

	return content.String()
}

// RenderDeleteConfirmParams holds input parameters for rendering delete confirmation
type RenderDeleteConfirmParams struct {
	FilterPattern     string
	FilterType        management.FilterType
	FilterDescription string
	Theme             themes.Theme
}

// RenderDeleteConfirm renders the delete confirmation dialog content
func RenderDeleteConfirm(params RenderDeleteConfirmParams) string {
	var content strings.Builder

	// Warning message
	warningStyle := lipgloss.NewStyle().
		Foreground(params.Theme.ErrorColor).
		Bold(true)
	content.WriteString(warningStyle.Render("⚠️  Delete Filter"))
	content.WriteString("\n\n")

	// Question
	content.WriteString("Are you sure you want to delete this filter?\n\n")

	// Filter details - build as single block for consistent alignment
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Pattern: %s\n", params.FilterPattern))
	details.WriteString(fmt.Sprintf("Type: %s", params.FilterType.String()))
	if params.FilterDescription != "" {
		details.WriteString(fmt.Sprintf("\nDescription: %s", params.FilterDescription))
	}

	detailStyle := lipgloss.NewStyle().
		Foreground(params.Theme.Foreground)
	content.WriteString(detailStyle.Render(details.String()))

	// Warning emphasis
	content.WriteString("\n\n")
	emphasisStyle := lipgloss.NewStyle().
		Foreground(params.Theme.ErrorColor).
		Italic(true)
	content.WriteString(emphasisStyle.Render("This action cannot be undone."))

	return content.String()
}

// RenderHunterSelectionParams holds input parameters for rendering hunter selection
type RenderHunterSelectionParams struct {
	AvailableHunters []HunterSelectorItem
	SelectedHunters  []string
	CursorIndex      int
	ModalWidth       int
	Theme            themes.Theme
}

// RenderHunterSelection renders the hunter selection UI content
func RenderHunterSelection(params RenderHunterSelectionParams) string {
	var content strings.Builder

	// Calculate content width
	contentWidth := params.ModalWidth - 4
	itemWidth := contentWidth - 2 // Account for padding

	// Styles
	itemStyle := lipgloss.NewStyle().
		Foreground(params.Theme.Foreground).
		Padding(0, 1)

	selectedStyle := lipgloss.NewStyle().
		Foreground(params.Theme.SelectionFg).
		Background(params.Theme.SelectionBg).
		Bold(true).
		Padding(0, 1).
		Width(itemWidth)

	if len(params.AvailableHunters) == 0 {
		content.WriteString(itemStyle.Render("No hunters available"))
	} else {
		cursorIdx := params.CursorIndex
		if cursorIdx >= len(params.AvailableHunters) {
			cursorIdx = 0
		}

		for i, hunter := range params.AvailableHunters {
			// Check if this hunter is selected
			isSelected := false
			for _, id := range params.SelectedHunters {
				if id == hunter.HunterID {
					isSelected = true
					break
				}
			}

			// Checkbox
			checkbox := "[ ] "
			if isSelected {
				checkbox = "[✓] "
			}

			// Build row
			row := fmt.Sprintf("%s%s (%s)", checkbox, hunter.HunterID, hunter.Hostname)

			// Apply cursor style
			if i == cursorIdx {
				content.WriteString(selectedStyle.Render(row))
			} else {
				content.WriteString(itemStyle.Render(row))
			}
			content.WriteString("\n")
		}
	}

	return content.String()
}

// CycleFormFilterTypeParams holds input parameters for cycling filter type in form
type CycleFormFilterTypeParams struct {
	CurrentType management.FilterType
	Forward     bool
}

// CycleFormFilterType cycles to the next/previous filter type in the form
func CycleFormFilterType(current management.FilterType, forward bool) management.FilterType {
	if forward {
		switch current {
		case management.FilterType_FILTER_SIP_USER:
			return management.FilterType_FILTER_PHONE_NUMBER
		case management.FilterType_FILTER_PHONE_NUMBER:
			return management.FilterType_FILTER_IP_ADDRESS
		case management.FilterType_FILTER_IP_ADDRESS:
			return management.FilterType_FILTER_CALL_ID
		case management.FilterType_FILTER_CALL_ID:
			return management.FilterType_FILTER_CODEC
		case management.FilterType_FILTER_CODEC:
			return management.FilterType_FILTER_BPF
		case management.FilterType_FILTER_BPF:
			return management.FilterType_FILTER_SIP_USER
		default:
			return management.FilterType_FILTER_SIP_USER
		}
	} else {
		// Backward
		switch current {
		case management.FilterType_FILTER_SIP_USER:
			return management.FilterType_FILTER_BPF
		case management.FilterType_FILTER_BPF:
			return management.FilterType_FILTER_CODEC
		case management.FilterType_FILTER_CODEC:
			return management.FilterType_FILTER_CALL_ID
		case management.FilterType_FILTER_CALL_ID:
			return management.FilterType_FILTER_IP_ADDRESS
		case management.FilterType_FILTER_IP_ADDRESS:
			return management.FilterType_FILTER_PHONE_NUMBER
		case management.FilterType_FILTER_PHONE_NUMBER:
			return management.FilterType_FILTER_SIP_USER
		default:
			return management.FilterType_FILTER_SIP_USER
		}
	}
}
