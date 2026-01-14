//go:build tui || all

package filtermanager

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// HunterSelectorItem represents a hunter for selection UI
type HunterSelectorItem struct {
	HunterID     string
	Hostname     string
	Capabilities *management.HunterCapabilities
}

// IsVoIPFilterType returns true if the filter type requires VoIP capabilities
func IsVoIPFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_SIP_USER ||
		filterType == management.FilterType_FILTER_PHONE_NUMBER ||
		filterType == management.FilterType_FILTER_CALL_ID ||
		filterType == management.FilterType_FILTER_CODEC ||
		filterType == management.FilterType_FILTER_SIP_URI
}

// IsDNSFilterType returns true if the filter type is DNS-related
func IsDNSFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_DNS_DOMAIN
}

// IsEmailFilterType returns true if the filter type is email-related
func IsEmailFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_EMAIL_ADDRESS ||
		filterType == management.FilterType_FILTER_EMAIL_SUBJECT
}

// IsTLSFilterType returns true if the filter type is TLS-related
func IsTLSFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_TLS_SNI ||
		filterType == management.FilterType_FILTER_TLS_JA3 ||
		filterType == management.FilterType_FILTER_TLS_JA3S ||
		filterType == management.FilterType_FILTER_TLS_JA4
}

// IsHTTPFilterType returns true if the filter type is HTTP-related
func IsHTTPFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_HTTP_HOST ||
		filterType == management.FilterType_FILTER_HTTP_URL
}

// IsUniversalFilterType returns true if the filter type works with all hunters
func IsUniversalFilterType(filterType management.FilterType) bool {
	return filterType == management.FilterType_FILTER_BPF ||
		filterType == management.FilterType_FILTER_IP_ADDRESS
}

// GetRequiredProtocolMode returns the protocol mode required for a filter type.
// Returns "generic" for universal filters that work with all hunters.
func GetRequiredProtocolMode(filterType management.FilterType) string {
	if IsVoIPFilterType(filterType) {
		return "voip"
	}
	if IsDNSFilterType(filterType) {
		return "dns"
	}
	if IsEmailFilterType(filterType) {
		return "email"
	}
	if IsHTTPFilterType(filterType) {
		return "http"
	}
	if IsTLSFilterType(filterType) {
		return "tls"
	}
	return "generic" // BPF, IP address work with all hunters
}

// HunterSupportsFilterType checks if a hunter supports a given filter type based on capabilities
func HunterSupportsFilterType(hunter HunterSelectorItem, filterType management.FilterType) bool {
	requiredMode := GetRequiredProtocolMode(filterType)

	// Universal filters (BPF, IP) are supported by all hunters
	if requiredMode == "generic" {
		return true
	}

	// Protocol-specific filters require matching hunter mode
	hunterMode := GetHunterProtocolMode(hunter)
	return hunterMode == requiredMode
}

// FilterHuntersByCapability filters hunters based on filter type capabilities
func FilterHuntersByCapability(hunters []HunterSelectorItem, filterType management.FilterType) []HunterSelectorItem {
	requiredMode := GetRequiredProtocolMode(filterType)

	// Universal filters - all hunters compatible
	if requiredMode == "generic" {
		return hunters
	}

	// Protocol-specific filters - only return compatible hunters
	compatible := make([]HunterSelectorItem, 0)
	for _, hunter := range hunters {
		if HunterSupportsFilterType(hunter, filterType) {
			compatible = append(compatible, hunter)
		}
	}

	return compatible
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
	CurrentType      management.FilterType
	Forward          bool
	AvailableHunters []HunterSelectorItem
}

// GetHunterProtocolMode returns the protocol mode of a hunter based on capabilities.
// Returns "voip", "dns", "email", "http", "tls", or "generic".
func GetHunterProtocolMode(hunter HunterSelectorItem) string {
	if hunter.Capabilities == nil || len(hunter.Capabilities.FilterTypes) == 0 {
		return "generic"
	}

	for _, ft := range hunter.Capabilities.FilterTypes {
		switch ft {
		case "sip_user":
			return "voip"
		case "dns_domain":
			return "dns"
		case "email_address":
			return "email"
		case "http_host":
			return "http"
		case "tls_sni":
			return "tls"
		}
	}

	return "generic"
}

// HasVoIPHunters checks if any hunters support VoIP filters
func HasVoIPHunters(hunters []HunterSelectorItem) bool {
	for _, hunter := range hunters {
		if GetHunterProtocolMode(hunter) == "voip" {
			return true
		}
	}
	return false
}

// HasDNSHunters checks if any hunters support DNS filters
func HasDNSHunters(hunters []HunterSelectorItem) bool {
	for _, hunter := range hunters {
		if GetHunterProtocolMode(hunter) == "dns" {
			return true
		}
	}
	return false
}

// HasEmailHunters checks if any hunters support Email filters
func HasEmailHunters(hunters []HunterSelectorItem) bool {
	for _, hunter := range hunters {
		if GetHunterProtocolMode(hunter) == "email" {
			return true
		}
	}
	return false
}

// HasHTTPHunters checks if any hunters support HTTP filters
func HasHTTPHunters(hunters []HunterSelectorItem) bool {
	for _, hunter := range hunters {
		if GetHunterProtocolMode(hunter) == "http" {
			return true
		}
	}
	return false
}

// HasTLSHunters checks if any hunters support TLS filters
func HasTLSHunters(hunters []HunterSelectorItem) bool {
	for _, hunter := range hunters {
		if GetHunterProtocolMode(hunter) == "tls" {
			return true
		}
	}
	return false
}

// CycleFormFilterType cycles to the next/previous filter type in the form.
// Filter types are skipped if no compatible hunters are available.
func CycleFormFilterType(current management.FilterType, forward bool, availableHunters []HunterSelectorItem) management.FilterType {
	// Check which protocol modes have available hunters
	hasVoIP := HasVoIPHunters(availableHunters)
	hasDNS := HasDNSHunters(availableHunters)
	hasEmail := HasEmailHunters(availableHunters)
	hasHTTP := HasHTTPHunters(availableHunters)
	hasTLS := HasTLSHunters(availableHunters)

	// All available filter types in order (grouped by category)
	allTypes := []management.FilterType{
		// Universal filters (work with all hunters)
		management.FilterType_FILTER_BPF,
		management.FilterType_FILTER_IP_ADDRESS,
		// VoIP filters
		management.FilterType_FILTER_SIP_USER,
		management.FilterType_FILTER_PHONE_NUMBER,
		management.FilterType_FILTER_CALL_ID,
		management.FilterType_FILTER_CODEC,
		management.FilterType_FILTER_SIP_URI,
		// DNS filters
		management.FilterType_FILTER_DNS_DOMAIN,
		// Email filters
		management.FilterType_FILTER_EMAIL_ADDRESS,
		management.FilterType_FILTER_EMAIL_SUBJECT,
		// TLS filters
		management.FilterType_FILTER_TLS_SNI,
		management.FilterType_FILTER_TLS_JA3,
		management.FilterType_FILTER_TLS_JA3S,
		management.FilterType_FILTER_TLS_JA4,
		// HTTP filters
		management.FilterType_FILTER_HTTP_HOST,
		management.FilterType_FILTER_HTTP_URL,
	}

	// Filter out types if no compatible hunters available
	availableTypes := make([]management.FilterType, 0, len(allTypes))
	for _, t := range allTypes {
		switch {
		case IsVoIPFilterType(t) && !hasVoIP:
			continue
		case IsDNSFilterType(t) && !hasDNS:
			continue
		case IsEmailFilterType(t) && !hasEmail:
			continue
		case IsHTTPFilterType(t) && !hasHTTP:
			continue
		case IsTLSFilterType(t) && !hasTLS:
			continue
		}
		availableTypes = append(availableTypes, t)
	}

	// If no types available (shouldn't happen), return current
	if len(availableTypes) == 0 {
		return current
	}

	// Find current type index
	currentIdx := 0
	for i, t := range availableTypes {
		if t == current {
			currentIdx = i
			break
		}
	}

	// Cycle to next/previous
	if forward {
		currentIdx = (currentIdx + 1) % len(availableTypes)
	} else {
		currentIdx = (currentIdx - 1 + len(availableTypes)) % len(availableTypes)
	}

	return availableTypes[currentIdx]
}
