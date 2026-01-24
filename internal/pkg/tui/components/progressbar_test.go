//go:build tui || all

package components

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProgressBar(t *testing.T) {
	cfg := DefaultProgressBarConfig()
	pb := NewProgressBar(cfg)

	require.NotNil(t, pb)
	assert.Equal(t, 40, pb.config.Width)
	assert.True(t, pb.config.ShowPercentage)
}

func TestNewDefaultProgressBar(t *testing.T) {
	pb := NewDefaultProgressBar()

	require.NotNil(t, pb)
	assert.Equal(t, 40, pb.config.Width)
}

func TestProgressBar_Render(t *testing.T) {
	pb := NewDefaultProgressBar()

	tests := []struct {
		name  string
		ratio float64
	}{
		{"zero", 0.0},
		{"quarter", 0.25},
		{"half", 0.5},
		{"three_quarters", 0.75},
		{"full", 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := pb.Render(tt.ratio)
			assert.NotEmpty(t, view)
		})
	}
}

func TestProgressBar_RenderClampsValues(t *testing.T) {
	pb := NewDefaultProgressBar()

	// Values below 0 should clamp to 0
	view := pb.Render(-0.5)
	assert.NotEmpty(t, view)

	// Values above 1 should clamp to 1
	view = pb.Render(1.5)
	assert.NotEmpty(t, view)
}

func TestProgressBar_RenderWithLabel(t *testing.T) {
	pb := NewDefaultProgressBar()

	view := pb.RenderWithLabel("Test Label", 0.5)
	assert.Contains(t, view, "Test Label")
}

func TestProgressBar_RenderWithValues(t *testing.T) {
	pb := NewDefaultProgressBar()

	view := pb.RenderWithValues("Queue", 50, 100)
	assert.Contains(t, view, "Queue")
	assert.Contains(t, view, "50/100")
}

func TestProgressBar_SetTheme(t *testing.T) {
	pb := NewDefaultProgressBar()
	theme := themes.Solarized()

	pb.SetTheme(theme)
	assert.Equal(t, theme.SuccessColor, pb.theme.SuccessColor)
}

func TestProgressBar_SetWidth(t *testing.T) {
	pb := NewDefaultProgressBar()

	pb.SetWidth(60)
	assert.Equal(t, 60, pb.config.Width)

	// Invalid width should be ignored
	pb.SetWidth(-10)
	assert.Equal(t, 60, pb.config.Width)
}

func TestProgressBar_SetThresholds(t *testing.T) {
	pb := NewDefaultProgressBar()

	pb.SetThresholds(0.4, 0.8)
	assert.Equal(t, 0.4, pb.config.LowThreshold)
	assert.Equal(t, 0.8, pb.config.HighThreshold)
}

func TestProgressBar_getColor(t *testing.T) {
	pb := NewProgressBar(ProgressBarConfig{
		Width:         40,
		LowThreshold:  0.3,
		HighThreshold: 0.7,
	})

	// Below low threshold = green (success)
	color := pb.getColor(0.1)
	assert.Equal(t, pb.theme.SuccessColor, color)

	// Between thresholds = yellow (warning)
	color = pb.getColor(0.5)
	assert.Equal(t, pb.theme.WarningColor, color)

	// Above high threshold = red (error)
	color = pb.getColor(0.9)
	assert.Equal(t, pb.theme.ErrorColor, color)
}

func TestNewHealthIndicator(t *testing.T) {
	hi := NewHealthIndicator()
	require.NotNil(t, hi)
}

func TestHealthIndicator_Render(t *testing.T) {
	hi := NewHealthIndicator()

	tests := []struct {
		level    HealthLevel
		expected string
	}{
		{HealthGood, "[OK]"},
		{HealthWarning, "[!]"},
		{HealthCritical, "[X]"},
		{HealthUnknown, "[?]"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			view := hi.Render(tt.level)
			assert.Contains(t, view, tt.expected)
		})
	}
}

func TestHealthIndicator_RenderWithLabel(t *testing.T) {
	hi := NewHealthIndicator()

	view := hi.RenderWithLabel("Test Status", HealthGood)
	assert.Contains(t, view, "Test Status")
	assert.Contains(t, view, "[OK]")
}

func TestHealthIndicator_SetTheme(t *testing.T) {
	hi := NewHealthIndicator()
	theme := themes.Solarized()

	hi.SetTheme(theme)
	assert.Equal(t, theme.SuccessColor, hi.theme.SuccessColor)
}

func TestHealthFromRatio_Inverted(t *testing.T) {
	// Inverted mode: high ratio = bad (e.g., drop rate)
	tests := []struct {
		ratio    float64
		expected HealthLevel
	}{
		{0.0, HealthGood},
		{0.02, HealthWarning},
		{0.10, HealthCritical},
	}

	for _, tt := range tests {
		level := HealthFromRatio(tt.ratio, 0.01, 0.05, true)
		assert.Equal(t, tt.expected, level, "ratio %.2f", tt.ratio)
	}
}

func TestHealthFromRatio_Normal(t *testing.T) {
	// Normal mode: high ratio = good (e.g., success rate)
	tests := []struct {
		ratio    float64
		expected HealthLevel
	}{
		{0.95, HealthGood},
		{0.75, HealthWarning},
		{0.40, HealthCritical},
	}

	for _, tt := range tests {
		level := HealthFromRatio(tt.ratio, 0.8, 0.5, false)
		assert.Equal(t, tt.expected, level, "ratio %.2f", tt.ratio)
	}
}

func TestRenderHealthSummary(t *testing.T) {
	theme := themes.Solarized()
	items := []struct {
		Label string
		Level HealthLevel
	}{
		{"Drops", HealthGood},
		{"Queue", HealthWarning},
		{"CPU", HealthCritical},
	}

	view := RenderHealthSummary(theme, items)
	assert.Contains(t, view, "Drops")
	assert.Contains(t, view, "Queue")
	assert.Contains(t, view, "CPU")
	assert.Contains(t, view, "[OK]")
	assert.Contains(t, view, "[!]")
	assert.Contains(t, view, "[X]")
}

func TestNewUtilizationBar(t *testing.T) {
	ub := NewUtilizationBar(40)

	require.NotNil(t, ub)
	assert.Equal(t, 40, ub.config.Width)
	assert.Equal(t, 0.5, ub.config.LowThreshold)
	assert.Equal(t, 0.85, ub.config.HighThreshold)
}

func TestUtilizationBar_RenderQueue(t *testing.T) {
	ub := NewUtilizationBar(30)

	view := ub.RenderQueue(50, 100, "Queue Depth")
	assert.Contains(t, view, "Queue Depth")
	assert.Contains(t, view, "50/100")
}

func TestUtilizationBar_RenderMemory(t *testing.T) {
	ub := NewUtilizationBar(30)

	// 512 MB used, 1 GB total
	view := ub.RenderMemory(512*1024*1024, 1024*1024*1024)
	assert.Contains(t, view, "Memory")
}

func TestFormatBytesCompact(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{100, "100B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1024 * 1024, "1.0MB"},
		{1024 * 1024 * 1024, "1.0GB"},
	}

	for _, tt := range tests {
		result := formatBytesCompact(tt.bytes)
		assert.Equal(t, tt.expected, result, "bytes %d", tt.bytes)
	}
}

func TestProgressBarConfig_Defaults(t *testing.T) {
	// Test that NewProgressBar handles edge cases in config
	cfg := ProgressBarConfig{
		Width:         -10, // Invalid
		LowThreshold:  0,   // Should default
		HighThreshold: 0,   // Should default
	}

	pb := NewProgressBar(cfg)
	assert.Equal(t, 40, pb.config.Width)          // Defaulted
	assert.Equal(t, 0.3, pb.config.LowThreshold)  // Defaulted
	assert.Equal(t, 0.7, pb.config.HighThreshold) // Defaulted
}

func TestProgressBarConfig_ThresholdOrdering(t *testing.T) {
	// Test that high threshold is adjusted if lower than low threshold
	cfg := ProgressBarConfig{
		Width:         40,
		LowThreshold:  0.8,
		HighThreshold: 0.5, // Invalid: lower than low threshold
	}

	pb := NewProgressBar(cfg)
	assert.Greater(t, pb.config.HighThreshold, pb.config.LowThreshold)
}
