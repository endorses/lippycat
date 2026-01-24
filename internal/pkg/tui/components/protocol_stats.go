//go:build tui || all

package components

import (
	"fmt"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ProtocolMetrics holds generic metrics that can be exported or displayed.
type ProtocolMetrics struct {
	// Core counts
	TotalItems     int64   // Total items tracked (calls, queries, sessions, etc.)
	ActiveItems    int64   // Currently active items
	CompletedItems int64   // Successfully completed items
	FailedItems    int64   // Failed items
	SuccessRate    float64 // Percentage of successful completions

	// Quality metrics (protocol-specific, may be empty)
	AvgLatency    float64 // Average latency/duration
	AvgQuality    float64 // Average quality metric (MOS, response time, etc.)
	QualityMetric string  // Name of the quality metric (e.g., "MOS", "Response Time")

	// Distribution data (for bar charts)
	Distribution map[string]int64 // Key -> count (e.g., codec -> count, status -> count)
}

// ProtocolStatsProvider interface defines what each protocol stats provider must implement.
// Providers are responsible for collecting and rendering protocol-specific statistics.
type ProtocolStatsProvider interface {
	// ProtocolName returns the protocol name as shown in the protocol selector
	// (e.g., "VoIP (SIP/RTP)", "DNS", "HTTP")
	ProtocolName() string

	// IsActive returns true if this provider has data to display.
	// Providers should return false if no relevant traffic has been captured.
	IsActive() bool

	// Render renders the protocol-specific statistics section.
	// width is the available terminal width for rendering.
	// Returns the formatted string for display.
	Render(width int, theme themes.Theme) string

	// GetMetrics returns the current metrics for export/programmatic access.
	GetMetrics() ProtocolMetrics

	// SetTheme updates the provider's theme for consistent styling.
	SetTheme(theme themes.Theme)
}

// ProtocolStatsRegistry manages protocol stats providers.
// It allows dynamic registration and lookup of providers by protocol name.
type ProtocolStatsRegistry struct {
	mu        sync.RWMutex
	providers map[string]ProtocolStatsProvider
	order     []string // Preserve registration order for consistent display
}

// NewProtocolStatsRegistry creates a new empty registry.
func NewProtocolStatsRegistry() *ProtocolStatsRegistry {
	return &ProtocolStatsRegistry{
		providers: make(map[string]ProtocolStatsProvider),
		order:     make([]string, 0),
	}
}

// Register adds a provider to the registry.
// If a provider with the same protocol name already exists, it is replaced.
func (r *ProtocolStatsRegistry) Register(provider ProtocolStatsProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := provider.ProtocolName()

	// Track order for new providers
	if _, exists := r.providers[name]; !exists {
		r.order = append(r.order, name)
	}

	r.providers[name] = provider
}

// Get returns the provider for a given protocol name, or nil if not found.
func (r *ProtocolStatsRegistry) Get(protocolName string) ProtocolStatsProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.providers[protocolName]
}

// GetActive returns all providers that have active data.
func (r *ProtocolStatsRegistry) GetActive() []ProtocolStatsProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	active := make([]ProtocolStatsProvider, 0)
	for _, name := range r.order {
		if provider, exists := r.providers[name]; exists && provider.IsActive() {
			active = append(active, provider)
		}
	}
	return active
}

// All returns all registered providers in registration order.
func (r *ProtocolStatsRegistry) All() []ProtocolStatsProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]ProtocolStatsProvider, 0, len(r.order))
	for _, name := range r.order {
		if provider, exists := r.providers[name]; exists {
			all = append(all, provider)
		}
	}
	return all
}

// SetTheme updates the theme for all registered providers.
func (r *ProtocolStatsRegistry) SetTheme(theme themes.Theme) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, provider := range r.providers {
		provider.SetTheme(theme)
	}
}

// RenderProtocolSection renders protocol-specific stats section with consistent styling.
// This helper can be used by providers for consistent section rendering.
func RenderProtocolSection(title, content string, theme themes.Theme) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(theme.InfoColor).
		MarginBottom(1)

	return titleStyle.Render(title) + "\n\n" + content
}

// RenderDistributionBar renders a horizontal bar chart for distribution data.
// Returns the formatted bar chart string.
func RenderDistributionBar(label string, value int64, maxValue int64, barWidth int, theme themes.Theme) string {
	if maxValue == 0 {
		maxValue = 1 // Avoid division by zero
	}

	// Calculate bar length
	barLen := int(float64(value) / float64(maxValue) * float64(barWidth))
	if barLen < 1 && value > 0 {
		barLen = 1
	}

	// Build the bar
	bar := ""
	empty := ""
	for i := 0; i < barLen; i++ {
		bar += "█"
	}
	for i := barLen; i < barWidth; i++ {
		empty += "░"
	}

	barStyle := lipgloss.NewStyle().Foreground(theme.InfoColor)
	emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	labelStyle := lipgloss.NewStyle().Foreground(theme.StatusBarFg)
	valueStyle := lipgloss.NewStyle().Foreground(theme.StatusBarFg).Bold(true)

	return labelStyle.Render(label) + " " +
		barStyle.Render(bar) +
		emptyStyle.Render(empty) + " " +
		valueStyle.Render(formatNumber64(value))
}

// RenderMetricRow renders a labeled metric row with optional color based on thresholds.
func RenderMetricRow(label string, value string, theme themes.Theme) string {
	labelStyle := lipgloss.NewStyle().
		Foreground(theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(theme.StatusBarFg)

	return labelStyle.Render(label+": ") + valueStyle.Render(value)
}

// RenderMetricRowWithColor renders a metric row with a colored value.
func RenderMetricRowWithColor(label string, value string, color lipgloss.Color, theme themes.Theme) string {
	labelStyle := lipgloss.NewStyle().
		Foreground(theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(color)

	return labelStyle.Render(label+": ") + valueStyle.Render(value)
}

// RenderSuccessRate renders a success rate with color coding.
// rate should be a percentage (0-100).
func RenderSuccessRate(rate float64, theme themes.Theme) string {
	var color lipgloss.Color
	if rate >= 95 {
		color = theme.SuccessColor
	} else if rate >= 80 {
		color = theme.WarningColor
	} else {
		color = theme.ErrorColor
	}

	style := lipgloss.NewStyle().Foreground(color).Bold(true)
	return style.Render(formatPercentage(rate))
}

// RenderQualityMetric renders a quality metric with color coding based on thresholds.
// value is the metric value, goodThreshold is the value above which it's "good",
// badThreshold is the value below which it's "bad".
func RenderQualityMetric(value float64, goodThreshold, badThreshold float64, higherIsBetter bool, theme themes.Theme) string {
	var color lipgloss.Color

	if higherIsBetter {
		if value >= goodThreshold {
			color = theme.SuccessColor
		} else if value >= badThreshold {
			color = theme.WarningColor
		} else {
			color = theme.ErrorColor
		}
	} else {
		// Lower is better (e.g., latency, packet loss)
		if value <= goodThreshold {
			color = theme.SuccessColor
		} else if value <= badThreshold {
			color = theme.WarningColor
		} else {
			color = theme.ErrorColor
		}
	}

	style := lipgloss.NewStyle().Foreground(color).Bold(true)
	return style.Render(formatFloat(value))
}

// formatPercentage formats a percentage value.
func formatPercentage(pct float64) string {
	if pct == 100.0 {
		return "100%"
	}
	return formatFloat(pct) + "%"
}

// formatFloat formats a float with appropriate precision.
func formatFloat(f float64) string {
	if f == 0 {
		return "0"
	}
	if f < 0.1 {
		return formatFloatPrec(f, 3)
	}
	if f < 10 {
		return formatFloatPrec(f, 2)
	}
	return formatFloatPrec(f, 1)
}

// formatFloatPrec formats a float with specified precision.
func formatFloatPrec(f float64, prec int) string {
	switch prec {
	case 1:
		return trimTrailingZeros(f, "%.1f")
	case 2:
		return trimTrailingZeros(f, "%.2f")
	case 3:
		return trimTrailingZeros(f, "%.3f")
	default:
		return trimTrailingZeros(f, "%.2f")
	}
}

// trimTrailingZeros formats and trims unnecessary trailing zeros.
func trimTrailingZeros(f float64, format string) string {
	s := formatWithPrintf(f, format)
	// Trim trailing zeros after decimal point
	if hasDecimalPoint(s) {
		for len(s) > 0 && s[len(s)-1] == '0' {
			s = s[:len(s)-1]
		}
		// Remove trailing decimal point
		if len(s) > 0 && s[len(s)-1] == '.' {
			s = s[:len(s)-1]
		}
	}
	return s
}

// hasDecimalPoint checks if a string contains a decimal point.
func hasDecimalPoint(s string) bool {
	for _, c := range s {
		if c == '.' {
			return true
		}
	}
	return false
}

// formatWithPrintf is a helper to format floats using fmt.Sprintf pattern.
func formatWithPrintf(f float64, format string) string {
	return fmt.Sprintf(format, f)
}
