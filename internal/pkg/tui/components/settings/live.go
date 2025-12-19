//go:build tui || all
// +build tui all

package settings

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/google/gopacket/pcap"
)

// LiveSettings encapsulates all settings for live capture mode
type LiveSettings struct {
	selectedIfaces map[string]bool
	promiscuous    bool
	bufferInput    textinput.Model
	filterInput    textinput.Model
	interfaceList  list.Model

	// For interface editing state
	savedInterfaceIndex int
	savedSelectedIfaces map[string]bool
}

// NewLiveSettings creates a new LiveSettings instance
func NewLiveSettings(currentInterface string, bufferSize int, promiscuous bool, filter string, theme themes.Theme) *LiveSettings {
	// Parse comma-separated interfaces
	selectedIfaces := make(map[string]bool)
	for _, iface := range strings.Split(currentInterface, ",") {
		iface = strings.TrimSpace(iface)
		if iface != "" {
			selectedIfaces[iface] = true
		}
	}

	// Get available interfaces
	ifaces, _ := pcap.FindAllDevs()
	availableIfaces := []string{"any"}
	for _, iface := range ifaces {
		if iface.Name != "" {
			availableIfaces = append(availableIfaces, iface.Name)
		}
	}

	// Create list items
	items := make([]list.Item, len(availableIfaces))
	selectedIdx := 0
	for i, iface := range availableIfaces {
		desc := "Capture from all interfaces"
		if iface != "any" {
			for _, pcapIface := range ifaces {
				if pcapIface.Name == iface {
					if pcapIface.Description != "" {
						desc = pcapIface.Description
					} else {
						desc = "Network interface"
					}
					break
				}
			}
		}
		items[i] = &settingItem{title: iface, desc: desc}
		if selectedIfaces[iface] {
			selectedIdx = i
		}
	}

	// Create interface list with custom delegate
	delegate := newInterfaceDelegate(selectedIfaces, theme)
	interfaceList := list.New(items, delegate, 80, 24)
	interfaceList.Title = "Network Interfaces (Space to toggle, Enter to confirm)"
	interfaceList.SetShowStatusBar(false)
	interfaceList.SetFilteringEnabled(true)
	interfaceList.SetShowFilter(true)
	interfaceList.DisableQuitKeybindings()
	interfaceList.Select(selectedIdx)

	bufferInput, filterInput := CreateCommonInputs(bufferSize, filter)

	return &LiveSettings{
		selectedIfaces: selectedIfaces,
		promiscuous:    promiscuous,
		bufferInput:    bufferInput,
		filterInput:    filterInput,
		interfaceList:  interfaceList,
	}
}

// settingItem implements list.Item for interface list
type settingItem struct {
	title, desc string
}

func (i *settingItem) FilterValue() string { return i.title }
func (i *settingItem) Title() string       { return i.title }
func (i *settingItem) Description() string { return i.desc }

// interfaceDelegate renders interface items with checkboxes
type interfaceDelegate struct {
	list.DefaultDelegate
	selectedIfaces map[string]bool
	theme          themes.Theme
}

func newInterfaceDelegate(selectedIfaces map[string]bool, theme themes.Theme) interfaceDelegate {
	delegate := list.NewDefaultDelegate()
	// Set item height to 1 to fit more interfaces per page
	delegate.SetHeight(1)
	// Disable spacing between items to maximize visible items
	delegate.SetSpacing(0)

	return interfaceDelegate{
		DefaultDelegate: delegate,
		selectedIfaces:  selectedIfaces,
		theme:           theme,
	}
}

func (d interfaceDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	settingItem, ok := item.(*settingItem)
	if !ok {
		d.DefaultDelegate.Render(w, m, index, item)
		return
	}

	checkbox := "[ ]"
	if d.selectedIfaces[settingItem.title] {
		checkbox = "[✓]"
	}

	isSelected := index == m.Index()
	var style lipgloss.Style
	if isSelected {
		style = lipgloss.NewStyle().Foreground(d.theme.InfoColor).Bold(true)
	} else {
		style = lipgloss.NewStyle().Foreground(d.theme.Foreground)
	}

	fmt.Fprint(w, style.Render(fmt.Sprintf("%s %s - %s", checkbox, settingItem.title, settingItem.desc)))
}

// Validate checks if live settings are valid
func (ls *LiveSettings) Validate() error {
	if len(ls.selectedIfaces) == 0 {
		return fmt.Errorf("at least one interface required for live capture")
	}
	if ls.promiscuous && ls.selectedIfaces["any"] {
		return fmt.Errorf("promiscuous mode cannot be used with 'any' interface")
	}
	return nil
}

// ToRestartMsg converts live settings to a restart message
func (ls *LiveSettings) ToRestartMsg() RestartCaptureMsg {
	return RestartCaptureMsg{
		Mode:        0, // CaptureModeLive
		Interface:   ls.GetInterface(),
		Filter:      ls.GetBPFFilter(),
		BufferSize:  ls.GetBufferSize(),
		Promiscuous: ls.promiscuous,
	}
}

// GetInterface returns selected interfaces as comma-separated string
func (ls *LiveSettings) GetInterface() string {
	if len(ls.selectedIfaces) == 0 {
		return "any"
	}
	var ifaces []string
	for iface := range ls.selectedIfaces {
		ifaces = append(ifaces, iface)
	}
	// Simple sort
	for i := 0; i < len(ifaces)-1; i++ {
		for j := 0; j < len(ifaces)-i-1; j++ {
			if ifaces[j] > ifaces[j+1] {
				ifaces[j], ifaces[j+1] = ifaces[j+1], ifaces[j]
			}
		}
	}
	return strings.Join(ifaces, ",")
}

// GetBufferSize returns the configured buffer size
func (ls *LiveSettings) GetBufferSize() int {
	size, err := strconv.Atoi(ls.bufferInput.Value())
	if err != nil || size <= 0 {
		return 10000
	}
	return size
}

// GetBPFFilter returns the configured BPF filter
func (ls *LiveSettings) GetBPFFilter() string {
	return ls.filterInput.Value()
}

// GetFocusableFieldCount returns 4: interface(1), promiscuous(2), buffer(3), filter(4)
func (ls *LiveSettings) GetFocusableFieldCount() int {
	return 4
}

// Render renders the live mode fields
func (ls *LiveSettings) Render(params RenderParams) []string {
	var sections []string

	// Use consistent fixed width (110 chars), but not wider than terminal
	boxWidth := 110
	if params.Width-4 < boxWidth {
		boxWidth = params.Width - 4
	}

	// Interface field (focus index 1)
	if params.FocusIndex == 1 && params.Editing {
		// Interface list needs full width for better UX
		sections = append(sections, params.EditingStyle.Width(params.Width-4).Render(ls.interfaceList.View()))
	} else if params.FocusIndex == 1 {
		sections = append(sections, params.SelectedStyle.Width(boxWidth).Render(
			params.LabelStyle.Render("Interfaces:")+" "+ls.GetInterface(),
		))
	} else {
		sections = append(sections, params.UnfocusedStyle.Width(boxWidth).Render(
			params.LabelStyle.Render("Interfaces:")+" "+ls.GetInterface(),
		))
	}

	// Promiscuous field (focus index 2)
	promiscStyle := params.UnfocusedStyle
	if params.FocusIndex == 2 {
		if params.Editing {
			promiscStyle = params.EditingStyle
		} else {
			promiscStyle = params.SelectedStyle
		}
	}
	promiscValue := "[ ]"
	if ls.promiscuous {
		promiscValue = "[✓]"
	}
	sections = append(sections, promiscStyle.Width(boxWidth).Render(
		params.LabelStyle.Render("Promiscuous Mode:")+" "+promiscValue,
	))

	// Buffer field (focus index 3)
	bufferStyle := params.UnfocusedStyle
	if params.FocusIndex == 3 {
		if params.Editing {
			bufferStyle = params.EditingStyle
		} else {
			bufferStyle = params.SelectedStyle
		}
	}
	sections = append(sections, bufferStyle.Width(boxWidth).Render(
		params.LabelStyle.Render("Buffer Size:")+" "+ls.bufferInput.View(),
	))

	// Filter field (focus index 4)
	filterStyle := params.UnfocusedStyle
	if params.FocusIndex == 4 {
		if params.Editing {
			filterStyle = params.EditingStyle
		} else {
			filterStyle = params.SelectedStyle
		}
	}
	sections = append(sections, filterStyle.Width(boxWidth).Render(
		params.LabelStyle.Render("Capture Filter:")+" "+ls.filterInput.View(),
	))

	return sections
}

// HandleKey handles keyboard input for live mode
func (ls *LiveSettings) HandleKey(key string, params KeyHandlerParams) KeyHandlerResult {
	result := KeyHandlerResult{
		Editing: params.Editing,
	}

	switch key {
	case "enter":
		switch params.FocusIndex {
		case 1: // Interface field
			// Handled specially by parent for editing state management
			result.Editing = true
			return result

		case 2: // Promiscuous toggle
			if ls.selectedIfaces["any"] {
				result.ErrorMessage = "Cannot enable promiscuous mode with 'any' interface"
			} else {
				ls.promiscuous = !ls.promiscuous
			}

		case 3: // Buffer size
			result.Editing = !params.Editing
			if result.Editing {
				ls.bufferInput.Focus()
			} else {
				ls.bufferInput.Blur()
				result.TriggerBufferUpdate = true
			}

		case 4: // Filter
			result.Editing = !params.Editing
			if result.Editing {
				ls.filterInput.Focus()
			} else {
				ls.filterInput.Blur()
				result.TriggerRestart = true
			}
		}

	case "esc":
		if params.Editing {
			switch params.FocusIndex {
			case 3: // Buffer - cancel edit, don't save
				ls.bufferInput.Blur()
				result.Editing = false
				// Don't trigger update - cancel the edit
			case 4: // Filter - cancel edit, don't save
				ls.filterInput.Blur()
				result.Editing = false
				// Don't trigger restart - cancel the edit
			}
		}
	}

	return result
}

// HandleInterfaceKey handles special interface list keyboard input
func (ls *LiveSettings) HandleInterfaceKey(msg tea.KeyMsg, theme themes.Theme) (bool, tea.Cmd) {
	switch msg.String() {
	case " ": // Toggle interface
		if item, ok := ls.interfaceList.SelectedItem().(*settingItem); ok {
			if item.title == "any" {
				ls.selectedIfaces = map[string]bool{"any": true}
				ls.promiscuous = false
			} else {
				delete(ls.selectedIfaces, "any")
				if ls.selectedIfaces[item.title] {
					delete(ls.selectedIfaces, item.title)
				} else {
					ls.selectedIfaces[item.title] = true
				}
			}
			delegate := newInterfaceDelegate(ls.selectedIfaces, theme)
			ls.interfaceList.SetDelegate(delegate)
		}
		return false, nil

	case "enter": // Confirm selection
		return true, nil // Signal to exit editing

	case "esc": // Cancel or clear filter
		var cmd tea.Cmd
		ls.interfaceList, cmd = ls.interfaceList.Update(msg)
		if !ls.interfaceList.SettingFilter() && !ls.interfaceList.IsFiltered() {
			// Revert to saved state
			ls.selectedIfaces = ls.savedSelectedIfaces
			delegate := newInterfaceDelegate(ls.selectedIfaces, theme)
			ls.interfaceList.SetDelegate(delegate)
			ls.interfaceList.Select(ls.savedInterfaceIndex)
			return true, cmd // Signal to exit editing
		}
		return false, cmd
	}

	// Pass other keys to list
	var cmd tea.Cmd
	ls.interfaceList, cmd = ls.interfaceList.Update(msg)
	return false, cmd
}

// SaveInterfaceState saves current interface selection state
func (ls *LiveSettings) SaveInterfaceState() {
	ls.savedInterfaceIndex = ls.interfaceList.Index()
	ls.savedSelectedIfaces = make(map[string]bool)
	for k, v := range ls.selectedIfaces {
		ls.savedSelectedIfaces[k] = v
	}
}

// UpdateTheme updates the theme for the interface list
func (ls *LiveSettings) UpdateTheme(theme themes.Theme) {
	delegate := newInterfaceDelegate(ls.selectedIfaces, theme)
	ls.interfaceList.SetDelegate(delegate)
}

// SetSize updates sizes for the interface list
func (ls *LiveSettings) SetSize(width, height int) {
	// Use about 2/3 of available height for better interface visibility
	// Subtract some space for header, footer, and other UI elements
	listHeight := (height * 2) / 3
	if listHeight < 10 {
		listHeight = 10 // Minimum height
	}
	ls.interfaceList.SetSize(width-8, listHeight)
}

// Update passes bubbletea messages to inputs when editing
func (ls *LiveSettings) Update(msg tea.Msg, focusIndex int) tea.Cmd {
	var cmd tea.Cmd
	switch focusIndex {
	case 3:
		ls.bufferInput, cmd = ls.bufferInput.Update(msg)
	case 4:
		ls.filterInput, cmd = ls.filterInput.Update(msg)
	}
	return cmd
}

// UpdateInterfaceList handles updates for the interface list during editing
// This is separate because it requires theme access for delegate updates
// Returns (shouldExitEditing bool, cmd tea.Cmd)
func (ls *LiveSettings) UpdateInterfaceList(msg tea.Msg, theme themes.Theme) (bool, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case " ": // Toggle interface
			if item, ok := ls.interfaceList.SelectedItem().(*settingItem); ok {
				// Initialize map if nil
				if ls.selectedIfaces == nil {
					ls.selectedIfaces = make(map[string]bool)
				}

				if item.title == "any" {
					ls.selectedIfaces = map[string]bool{"any": true}
					ls.promiscuous = false
				} else {
					delete(ls.selectedIfaces, "any")
					if ls.selectedIfaces[item.title] {
						delete(ls.selectedIfaces, item.title)
					} else {
						ls.selectedIfaces[item.title] = true
					}
				}
				delegate := newInterfaceDelegate(ls.selectedIfaces, theme)
				ls.interfaceList.SetDelegate(delegate)
			}
			return false, nil

		case "enter": // Confirm selection and exit editing
			return true, nil

		case "esc": // Cancel or clear filter
			var cmd tea.Cmd
			ls.interfaceList, cmd = ls.interfaceList.Update(msg)
			// Check if we cleared the filter or should exit editing
			if !ls.interfaceList.SettingFilter() && !ls.interfaceList.IsFiltered() {
				// Revert to saved state and exit
				ls.selectedIfaces = ls.savedSelectedIfaces
				delegate := newInterfaceDelegate(ls.selectedIfaces, theme)
				ls.interfaceList.SetDelegate(delegate)
				ls.interfaceList.Select(ls.savedInterfaceIndex)
				return true, cmd
			}
			return false, cmd
		}
	}
	// Pass all other messages to list
	var cmd tea.Cmd
	ls.interfaceList, cmd = ls.interfaceList.Update(msg)
	return false, cmd
}
