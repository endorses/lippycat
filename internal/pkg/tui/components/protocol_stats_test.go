//go:build tui || all

package components

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
)

// mockProvider is a mock implementation of ProtocolStatsProvider for testing.
type mockProvider struct {
	name     string
	active   bool
	metrics  ProtocolMetrics
	rendered string
}

func (m *mockProvider) ProtocolName() string                        { return m.name }
func (m *mockProvider) IsActive() bool                              { return m.active }
func (m *mockProvider) Render(width int, theme themes.Theme) string { return m.rendered }
func (m *mockProvider) GetMetrics() ProtocolMetrics                 { return m.metrics }
func (m *mockProvider) SetTheme(theme themes.Theme)                 {}

func TestNewProtocolStatsRegistry(t *testing.T) {
	registry := NewProtocolStatsRegistry()
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.providers)
	assert.NotNil(t, registry.order)
	assert.Empty(t, registry.providers)
	assert.Empty(t, registry.order)
}

func TestProtocolStatsRegistry_Register(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	provider := &mockProvider{name: "TestProtocol", active: true}
	registry.Register(provider)

	assert.Len(t, registry.providers, 1)
	assert.Len(t, registry.order, 1)
	assert.Equal(t, "TestProtocol", registry.order[0])
}

func TestProtocolStatsRegistry_RegisterMultiple(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	p1 := &mockProvider{name: "Protocol1", active: true}
	p2 := &mockProvider{name: "Protocol2", active: false}
	p3 := &mockProvider{name: "Protocol3", active: true}

	registry.Register(p1)
	registry.Register(p2)
	registry.Register(p3)

	assert.Len(t, registry.providers, 3)
	assert.Len(t, registry.order, 3)

	// Check order is preserved
	assert.Equal(t, "Protocol1", registry.order[0])
	assert.Equal(t, "Protocol2", registry.order[1])
	assert.Equal(t, "Protocol3", registry.order[2])
}

func TestProtocolStatsRegistry_RegisterReplaces(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	p1 := &mockProvider{name: "TestProtocol", active: true, rendered: "first"}
	p2 := &mockProvider{name: "TestProtocol", active: true, rendered: "second"}

	registry.Register(p1)
	registry.Register(p2)

	// Should have only one entry (replaced)
	assert.Len(t, registry.providers, 1)
	assert.Len(t, registry.order, 1)

	// Should have the second provider
	provider := registry.Get("TestProtocol")
	assert.Equal(t, "second", provider.Render(80, themes.Solarized()))
}

func TestProtocolStatsRegistry_Get(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	provider := &mockProvider{name: "TestProtocol", active: true}
	registry.Register(provider)

	// Get existing provider
	result := registry.Get("TestProtocol")
	assert.NotNil(t, result)
	assert.Equal(t, "TestProtocol", result.ProtocolName())

	// Get non-existent provider
	result = registry.Get("NonExistent")
	assert.Nil(t, result)
}

func TestProtocolStatsRegistry_GetActive(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	p1 := &mockProvider{name: "Active1", active: true}
	p2 := &mockProvider{name: "Inactive", active: false}
	p3 := &mockProvider{name: "Active2", active: true}

	registry.Register(p1)
	registry.Register(p2)
	registry.Register(p3)

	active := registry.GetActive()
	assert.Len(t, active, 2)
	assert.Equal(t, "Active1", active[0].ProtocolName())
	assert.Equal(t, "Active2", active[1].ProtocolName())
}

func TestProtocolStatsRegistry_All(t *testing.T) {
	registry := NewProtocolStatsRegistry()

	p1 := &mockProvider{name: "Protocol1", active: true}
	p2 := &mockProvider{name: "Protocol2", active: false}

	registry.Register(p1)
	registry.Register(p2)

	all := registry.All()
	assert.Len(t, all, 2)
	assert.Equal(t, "Protocol1", all[0].ProtocolName())
	assert.Equal(t, "Protocol2", all[1].ProtocolName())
}

func TestRenderDistributionBar(t *testing.T) {
	theme := themes.Solarized()

	// Test with normal values
	result := RenderDistributionBar("Test", 50, 100, 10, theme)
	assert.Contains(t, result, "Test")
	assert.Contains(t, result, "50")

	// Test with zero max (should not panic)
	result = RenderDistributionBar("Zero", 0, 0, 10, theme)
	assert.Contains(t, result, "Zero")

	// Test with value > max
	result = RenderDistributionBar("Over", 150, 100, 10, theme)
	assert.Contains(t, result, "Over")
}

func TestRenderMetricRow(t *testing.T) {
	theme := themes.Solarized()

	result := RenderMetricRow("Label", "Value", theme)
	assert.Contains(t, result, "Label")
	assert.Contains(t, result, "Value")
}

func TestRenderSuccessRate(t *testing.T) {
	theme := themes.Solarized()

	// Test excellent rate
	result := RenderSuccessRate(100.0, theme)
	assert.Contains(t, result, "100%")

	// Test good rate
	result = RenderSuccessRate(95.0, theme)
	assert.Contains(t, result, "95%")

	// Test warning rate
	result = RenderSuccessRate(85.0, theme)
	assert.Contains(t, result, "85%")

	// Test poor rate
	result = RenderSuccessRate(50.0, theme)
	assert.Contains(t, result, "50%")
}

func TestRenderQualityMetric(t *testing.T) {
	theme := themes.Solarized()

	// Test higher is better (MOS)
	result := RenderQualityMetric(4.5, 4.0, 3.0, true, theme)
	assert.NotEmpty(t, result)

	result = RenderQualityMetric(3.5, 4.0, 3.0, true, theme)
	assert.NotEmpty(t, result)

	result = RenderQualityMetric(2.5, 4.0, 3.0, true, theme)
	assert.NotEmpty(t, result)

	// Test lower is better (latency)
	result = RenderQualityMetric(10, 20, 50, false, theme)
	assert.NotEmpty(t, result)

	result = RenderQualityMetric(30, 20, 50, false, theme)
	assert.NotEmpty(t, result)

	result = RenderQualityMetric(100, 20, 50, false, theme)
	assert.NotEmpty(t, result)
}

func TestFormatPercentage(t *testing.T) {
	assert.Equal(t, "100%", formatPercentage(100.0))
	assert.Contains(t, formatPercentage(99.5), "99")
	assert.Contains(t, formatPercentage(0), "0")
}

func TestFormatFloat(t *testing.T) {
	assert.Equal(t, "0", formatFloat(0))
	assert.Contains(t, formatFloat(0.05), "0.05")
	assert.Contains(t, formatFloat(5.5), "5.5")
	assert.Contains(t, formatFloat(50.5), "50")
}
