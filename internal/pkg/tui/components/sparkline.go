//go:build tui || all

package components

import (
	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// SparklineConfig holds configuration for a sparkline chart.
type SparklineConfig struct {
	Width    int
	Height   int
	MaxValue float64 // If 0, auto-scales
	Style    lipgloss.Style
	Braille  bool // Use braille characters for higher resolution
}

// DefaultSparklineConfig returns sensible defaults for a sparkline.
func DefaultSparklineConfig() SparklineConfig {
	return SparklineConfig{
		Width:   60,
		Height:  3,
		Braille: false,
	}
}

// Sparkline wraps ntcharts sparkline with theme-aware styling.
type Sparkline struct {
	model  sparkline.Model
	config SparklineConfig
	theme  themes.Theme
}

// NewSparkline creates a new sparkline with the given configuration.
func NewSparkline(cfg SparklineConfig) *Sparkline {
	opts := []sparkline.Option{}

	if cfg.MaxValue > 0 {
		opts = append(opts, sparkline.WithMaxValue(cfg.MaxValue))
	}

	if cfg.Style.Value() != "" {
		opts = append(opts, sparkline.WithStyle(cfg.Style))
	}

	sl := &Sparkline{
		model:  sparkline.New(cfg.Width, cfg.Height, opts...),
		config: cfg,
		theme:  themes.Solarized(),
	}

	return sl
}

// NewSparklineWithTheme creates a new sparkline with theme-based styling.
func NewSparklineWithTheme(width, height int, theme themes.Theme) *Sparkline {
	style := lipgloss.NewStyle().Foreground(theme.InfoColor)

	cfg := SparklineConfig{
		Width:   width,
		Height:  height,
		Style:   style,
		Braille: false,
	}

	sl := &Sparkline{
		model:  sparkline.New(width, height, sparkline.WithStyle(style)),
		config: cfg,
		theme:  theme,
	}

	return sl
}

// SetTheme updates the sparkline theme.
func (s *Sparkline) SetTheme(theme themes.Theme) {
	s.theme = theme
	// Update style based on theme
	style := lipgloss.NewStyle().Foreground(theme.InfoColor)
	s.model.Style = style
}

// SetStyle sets a custom style for the sparkline.
func (s *Sparkline) SetStyle(style lipgloss.Style) {
	s.model.Style = style
}

// SetBraille enables or disables braille mode.
func (s *Sparkline) SetBraille(enabled bool) {
	s.config.Braille = enabled
}

// SetMaxValue sets the maximum value for scaling.
// If 0, auto-scaling is used.
func (s *Sparkline) SetMaxValue(max float64) {
	if max > 0 {
		s.model.SetMax(max)
		s.model.AutoMaxValue = false
	} else {
		s.model.AutoMaxValue = true
	}
}

// Resize changes the sparkline dimensions.
func (s *Sparkline) Resize(width, height int) {
	s.config.Width = width
	s.config.Height = height
	s.model.Resize(width, height)
}

// Clear resets the sparkline data.
func (s *Sparkline) Clear() {
	s.model.Clear()
}

// Push adds a single data point.
func (s *Sparkline) Push(value float64) {
	s.model.Push(value)
}

// PushAll adds multiple data points at once.
func (s *Sparkline) PushAll(values []float64) {
	s.model.PushAll(values)
}

// SetData replaces all data with new values.
func (s *Sparkline) SetData(values []float64) {
	s.model.Clear()
	s.model.PushAll(values)
}

// View renders the sparkline.
func (s *Sparkline) View() string {
	if s.config.Braille {
		s.model.DrawBraille()
	} else {
		s.model.DrawColumnsOnly()
	}
	return s.model.View()
}

// RenderWithLabel renders the sparkline with a label above it.
func (s *Sparkline) RenderWithLabel(label string) string {
	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.StatusBarFg)

	return labelStyle.Render(label) + "\n" + s.View()
}

// RenderRateSparkline is a convenience function to render rate data as a sparkline.
// It takes rate samples from RateTracker and displays them with appropriate styling.
func RenderRateSparkline(rates []float64, width, height int, theme themes.Theme, peakRate float64) string {
	if len(rates) == 0 {
		return ""
	}

	// Create sparkline with theme color
	style := lipgloss.NewStyle().Foreground(theme.InfoColor)
	opts := []sparkline.Option{
		sparkline.WithStyle(style),
		sparkline.WithData(rates),
	}

	// Set max value if peak is known for consistent scaling
	if peakRate > 0 {
		opts = append(opts, sparkline.WithMaxValue(peakRate*1.1)) // 10% headroom
	}

	sl := sparkline.New(width, height, opts...)
	sl.DrawColumnsOnly()
	return sl.View()
}

// RenderBytesRateSparkline renders a bytes/sec rate sparkline with appropriate colors.
// Uses green for low utilization, yellow for moderate, red for high.
func RenderBytesRateSparkline(rates []float64, width, height int, theme themes.Theme, maxRate float64) string {
	if len(rates) == 0 {
		return ""
	}

	// Determine color based on current rate vs max
	var color lipgloss.Color
	if len(rates) > 0 && maxRate > 0 {
		current := rates[len(rates)-1]
		ratio := current / maxRate
		switch {
		case ratio > 0.8:
			color = theme.ErrorColor // High utilization
		case ratio > 0.5:
			color = theme.WarningColor // Moderate
		default:
			color = theme.SuccessColor // Low/normal
		}
	} else {
		color = theme.InfoColor
	}

	style := lipgloss.NewStyle().Foreground(color)
	opts := []sparkline.Option{
		sparkline.WithStyle(style),
		sparkline.WithData(rates),
	}

	if maxRate > 0 {
		opts = append(opts, sparkline.WithMaxValue(maxRate*1.1))
	}

	sl := sparkline.New(width, height, opts...)
	sl.DrawColumnsOnly()
	return sl.View()
}

// RenderCPUSparkline renders a CPU percentage sparkline with utilization-based colors.
// Uses green for low CPU (<30%), yellow for moderate (30-70%), red for high (>70%).
func RenderCPUSparkline(samples []float64, width, height int, theme themes.Theme) string {
	if len(samples) == 0 {
		return ""
	}

	// Determine color based on current CPU percentage
	var color lipgloss.Color
	if len(samples) > 0 {
		current := samples[len(samples)-1]
		switch {
		case current > 70:
			color = theme.ErrorColor // High CPU
		case current > 30:
			color = theme.WarningColor // Moderate CPU
		default:
			color = theme.SuccessColor // Low CPU
		}
	} else {
		color = theme.InfoColor
	}

	style := lipgloss.NewStyle().Foreground(color)
	opts := []sparkline.Option{
		sparkline.WithStyle(style),
		sparkline.WithData(samples),
		sparkline.WithMaxValue(100), // CPU is always 0-100%
	}

	sl := sparkline.New(width, height, opts...)
	sl.DrawColumnsOnly()
	return sl.View()
}
