//go:build tui || all

package components

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSparkline(t *testing.T) {
	cfg := DefaultSparklineConfig()
	sl := NewSparkline(cfg)

	require.NotNil(t, sl)
	assert.Equal(t, 60, sl.config.Width)
	assert.Equal(t, 3, sl.config.Height)
}

func TestNewSparklineWithTheme(t *testing.T) {
	theme := themes.Solarized()
	sl := NewSparklineWithTheme(40, 5, theme)

	require.NotNil(t, sl)
	assert.Equal(t, 40, sl.config.Width)
	assert.Equal(t, 5, sl.config.Height)
}

func TestSparkline_SetData(t *testing.T) {
	cfg := DefaultSparklineConfig()
	sl := NewSparkline(cfg)

	data := []float64{1.0, 2.0, 3.0, 4.0, 5.0}
	sl.SetData(data)

	// View should return non-empty string with data
	view := sl.View()
	assert.NotEmpty(t, view)
}

func TestSparkline_Push(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)

	sl.Push(1.0)
	sl.Push(2.0)
	sl.Push(3.0)

	view := sl.View()
	assert.NotEmpty(t, view)
}

func TestSparkline_PushAll(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)

	sl.PushAll([]float64{1.0, 2.0, 3.0, 4.0, 5.0})

	view := sl.View()
	assert.NotEmpty(t, view)
}

func TestSparkline_Clear(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)

	sl.PushAll([]float64{1.0, 2.0, 3.0})
	sl.Clear()

	// After clear, pushing new data should work
	sl.Push(5.0)
	view := sl.View()
	assert.NotEmpty(t, view)
}

func TestSparkline_SetMaxValue(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)

	sl.SetMaxValue(100.0)
	sl.PushAll([]float64{10, 20, 30, 40, 50})

	view := sl.View()
	assert.NotEmpty(t, view)
}

func TestSparkline_Resize(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)

	sl.Resize(40, 5)
	assert.Equal(t, 40, sl.config.Width)
	assert.Equal(t, 5, sl.config.Height)
}

func TestSparkline_SetTheme(t *testing.T) {
	cfg := DefaultSparklineConfig()
	sl := NewSparkline(cfg)

	theme := themes.Solarized()
	sl.SetTheme(theme)

	assert.Equal(t, theme.InfoColor, sl.theme.InfoColor)
}

func TestSparkline_SetBraille(t *testing.T) {
	cfg := DefaultSparklineConfig()
	sl := NewSparkline(cfg)

	sl.SetBraille(true)
	assert.True(t, sl.config.Braille)

	sl.SetBraille(false)
	assert.False(t, sl.config.Braille)
}

func TestSparkline_RenderWithLabel(t *testing.T) {
	cfg := SparklineConfig{
		Width:  20,
		Height: 3,
	}
	sl := NewSparkline(cfg)
	sl.PushAll([]float64{1.0, 2.0, 3.0})

	view := sl.RenderWithLabel("Test Label")
	assert.Contains(t, view, "Test Label")
}

func TestRenderRateSparkline(t *testing.T) {
	rates := []float64{10.0, 20.0, 30.0, 40.0, 50.0}
	theme := themes.Solarized()

	view := RenderRateSparkline(rates, 20, 3, theme, 50.0)
	assert.NotEmpty(t, view)
}

func TestRenderRateSparkline_EmptyData(t *testing.T) {
	theme := themes.Solarized()

	view := RenderRateSparkline([]float64{}, 20, 3, theme, 50.0)
	assert.Empty(t, view)
}

func TestRenderBytesRateSparkline(t *testing.T) {
	rates := []float64{1024.0, 2048.0, 3072.0, 4096.0, 5120.0}
	theme := themes.Solarized()

	view := RenderBytesRateSparkline(rates, 20, 3, theme, 10240.0)
	assert.NotEmpty(t, view)
}

func TestRenderBytesRateSparkline_HighUtilization(t *testing.T) {
	// Test high utilization coloring (>80%)
	rates := []float64{800.0, 850.0, 900.0, 950.0, 990.0}
	theme := themes.Solarized()

	view := RenderBytesRateSparkline(rates, 20, 3, theme, 1000.0)
	assert.NotEmpty(t, view)
}

func TestSparkline_SetStyle(t *testing.T) {
	cfg := DefaultSparklineConfig()
	sl := NewSparkline(cfg)

	customStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	sl.SetStyle(customStyle)

	// Style should be applied - just verify no panic
	sl.PushAll([]float64{1, 2, 3})
	view := sl.View()
	assert.NotEmpty(t, view)
}
