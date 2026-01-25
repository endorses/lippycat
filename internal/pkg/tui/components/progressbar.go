//go:build tui || all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ProgressBarConfig holds configuration for a progress bar.
type ProgressBarConfig struct {
	Width          int     // Total width in characters
	ShowPercentage bool    // Show percentage value
	ShowValue      bool    // Show current/max values
	Label          string  // Optional label
	LowThreshold   float64 // Below this = green (default 0.3)
	HighThreshold  float64 // Above this = red (default 0.7)
}

// DefaultProgressBarConfig returns sensible defaults.
func DefaultProgressBarConfig() ProgressBarConfig {
	return ProgressBarConfig{
		Width:          40,
		ShowPercentage: true,
		ShowValue:      false,
		LowThreshold:   0.3,
		HighThreshold:  0.7,
	}
}

// ProgressBar represents a progress/utilization bar with threshold-based coloring.
type ProgressBar struct {
	config ProgressBarConfig
	theme  themes.Theme
}

// NewProgressBar creates a new progress bar with the given configuration.
func NewProgressBar(cfg ProgressBarConfig) *ProgressBar {
	if cfg.Width <= 0 {
		cfg.Width = 40
	}
	if cfg.LowThreshold <= 0 {
		cfg.LowThreshold = 0.3
	}
	if cfg.HighThreshold <= 0 {
		cfg.HighThreshold = 0.7
	}
	if cfg.HighThreshold <= cfg.LowThreshold {
		cfg.HighThreshold = cfg.LowThreshold + 0.4
	}

	return &ProgressBar{
		config: cfg,
		theme:  themes.Solarized(),
	}
}

// NewDefaultProgressBar creates a progress bar with default configuration.
func NewDefaultProgressBar() *ProgressBar {
	return NewProgressBar(DefaultProgressBarConfig())
}

// SetTheme updates the progress bar theme.
func (pb *ProgressBar) SetTheme(theme themes.Theme) {
	pb.theme = theme
}

// SetWidth updates the progress bar width.
func (pb *ProgressBar) SetWidth(width int) {
	if width > 0 {
		pb.config.Width = width
	}
}

// SetThresholds updates the color thresholds.
func (pb *ProgressBar) SetThresholds(low, high float64) {
	pb.config.LowThreshold = low
	pb.config.HighThreshold = high
}

// getColor returns the appropriate color based on value ratio and thresholds.
func (pb *ProgressBar) getColor(ratio float64) lipgloss.Color {
	switch {
	case ratio >= pb.config.HighThreshold:
		return pb.theme.ErrorColor
	case ratio >= pb.config.LowThreshold:
		return pb.theme.WarningColor
	default:
		return pb.theme.SuccessColor
	}
}

// Render draws the progress bar for a given ratio (0.0 to 1.0).
func (pb *ProgressBar) Render(ratio float64) string {
	// Clamp ratio to valid range
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	// Calculate bar dimensions
	barWidth := pb.config.Width
	if pb.config.ShowPercentage {
		barWidth -= 6 // "100.0%"
	}
	if barWidth < 10 {
		barWidth = 10
	}

	filledWidth := int(float64(barWidth) * ratio)
	emptyWidth := barWidth - filledWidth

	// Get appropriate color
	fillColor := pb.getColor(ratio)

	// Build the bar
	filledStyle := lipgloss.NewStyle().
		Background(fillColor).
		Foreground(lipgloss.Color("0"))
	emptyStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("236")). // Dark gray
		Foreground(lipgloss.Color("240"))

	filled := filledStyle.Render(strings.Repeat(" ", filledWidth))
	empty := emptyStyle.Render(strings.Repeat(" ", emptyWidth))

	var result strings.Builder
	result.WriteString(filled)
	result.WriteString(empty)

	if pb.config.ShowPercentage {
		pctStyle := lipgloss.NewStyle().Foreground(fillColor)
		result.WriteString(" ")
		result.WriteString(pctStyle.Render(fmt.Sprintf("%5.1f%%", ratio*100)))
	}

	return result.String()
}

// RenderWithLabel draws the progress bar with a label.
func (pb *ProgressBar) RenderWithLabel(label string, ratio float64) string {
	labelStyle := lipgloss.NewStyle().
		Foreground(pb.theme.StatusBarFg).
		Width(20)

	return labelStyle.Render(label) + " " + pb.Render(ratio)
}

// RenderWithValues draws the progress bar showing current/max values.
func (pb *ProgressBar) RenderWithValues(label string, current, max int64) string {
	ratio := float64(0)
	if max > 0 {
		ratio = float64(current) / float64(max)
	}

	labelStyle := lipgloss.NewStyle().
		Foreground(pb.theme.StatusBarFg).
		Width(20)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("244"))

	return fmt.Sprintf("%s %s %s",
		labelStyle.Render(label),
		pb.Render(ratio),
		valueStyle.Render(fmt.Sprintf("(%d/%d)", current, max)))
}

// HealthIndicator represents a simple health status indicator.
type HealthIndicator struct {
	theme themes.Theme
}

// NewHealthIndicator creates a new health indicator.
func NewHealthIndicator() *HealthIndicator {
	return &HealthIndicator{
		theme: themes.Solarized(),
	}
}

// SetTheme updates the health indicator theme.
func (hi *HealthIndicator) SetTheme(theme themes.Theme) {
	hi.theme = theme
}

// HealthLevel represents the health status level.
type HealthLevel int

const (
	HealthGood HealthLevel = iota
	HealthWarning
	HealthCritical
	HealthUnknown
)

// Render returns a colored health indicator.
func (hi *HealthIndicator) Render(level HealthLevel) string {
	var symbol string
	var color lipgloss.Color

	switch level {
	case HealthGood:
		symbol = "✓"
		color = hi.theme.SuccessColor
	case HealthWarning:
		symbol = "[!]"
		color = hi.theme.WarningColor
	case HealthCritical:
		symbol = "[X]"
		color = hi.theme.ErrorColor
	default:
		symbol = "[?]"
		color = lipgloss.Color("240")
	}

	style := lipgloss.NewStyle().
		Bold(true).
		Foreground(color)

	return style.Render(symbol)
}

// RenderWithLabel renders the health indicator with a label.
func (hi *HealthIndicator) RenderWithLabel(label string, level HealthLevel) string {
	labelStyle := lipgloss.NewStyle().
		Foreground(hi.theme.StatusBarFg)

	return hi.Render(level) + " " + labelStyle.Render(label)
}

// HealthFromRatio determines health level from a ratio and thresholds.
// Inverted mode (true) means high ratio is bad (e.g., CPU usage).
// Normal mode (false) means high ratio is good (e.g., success rate).
func HealthFromRatio(ratio, warnThreshold, critThreshold float64, inverted bool) HealthLevel {
	if inverted {
		// High ratio = bad (e.g., drop rate, CPU usage)
		switch {
		case ratio >= critThreshold:
			return HealthCritical
		case ratio >= warnThreshold:
			return HealthWarning
		default:
			return HealthGood
		}
	}
	// High ratio = good (e.g., success rate)
	switch {
	case ratio < critThreshold:
		return HealthCritical
	case ratio < warnThreshold:
		return HealthWarning
	default:
		return HealthGood
	}
}

// RenderHealthSummary renders a compact health summary with multiple indicators.
func RenderHealthSummary(theme themes.Theme, items []struct {
	Label string
	Level HealthLevel
}) string {
	hi := &HealthIndicator{theme: theme}

	var parts []string
	for _, item := range items {
		parts = append(parts, hi.RenderWithLabel(item.Label, item.Level))
	}

	return strings.Join(parts, "  ")
}

// UtilizationBar is a specialized progress bar for showing resource utilization.
// It includes built-in formatting for common metrics like queue depth, memory, etc.
type UtilizationBar struct {
	*ProgressBar
}

// NewUtilizationBar creates a new utilization bar.
func NewUtilizationBar(width int) *UtilizationBar {
	cfg := ProgressBarConfig{
		Width:          width,
		ShowPercentage: true,
		LowThreshold:   0.5,  // 50% = warning
		HighThreshold:  0.85, // 85% = critical
	}
	return &UtilizationBar{
		ProgressBar: NewProgressBar(cfg),
	}
}

// RenderQueue renders a queue depth utilization bar.
func (ub *UtilizationBar) RenderQueue(current, max int64, label string) string {
	ratio := float64(0)
	if max > 0 {
		ratio = float64(current) / float64(max)
	}

	labelStyle := lipgloss.NewStyle().
		Foreground(ub.theme.StatusBarFg).
		Width(18)

	return fmt.Sprintf("%s %s  %d/%d",
		labelStyle.Render(label),
		ub.Render(ratio),
		current, max)
}

// RenderMemory renders a memory utilization bar with formatted bytes.
func (ub *UtilizationBar) RenderMemory(usedBytes, totalBytes int64) string {
	ratio := float64(0)
	if totalBytes > 0 {
		ratio = float64(usedBytes) / float64(totalBytes)
	}

	labelStyle := lipgloss.NewStyle().
		Foreground(ub.theme.StatusBarFg).
		Width(18)

	return fmt.Sprintf("%s %s  %s / %s",
		labelStyle.Render("Memory"),
		ub.Render(ratio),
		formatBytesCompact(usedBytes),
		formatBytesCompact(totalBytes))
}

// formatBytesCompact formats bytes in a compact form.
func formatBytesCompact(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
