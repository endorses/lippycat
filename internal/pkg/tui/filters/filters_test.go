//go:build tui || all
// +build tui all

package filters

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/assert"
)

// TestFilterChain_SortsBySelectivity verifies filters are sorted by selectivity
func TestFilterChain_SortsBySelectivity(t *testing.T) {
	fc := NewFilterChain()

	// Add filters in random order (least to most selective)
	textFilter := NewTextFilter("test", []string{"all"})         // 0.3
	voipFilter := NewVoIPFilter("user", "alicent")               // 0.7
	bpfFilter, _ := NewBPFFilter("tcp")                          // 0.9
	specificTextFilter := NewTextFilter("test", []string{"src"}) // 0.6

	fc.Add(textFilter)
	fc.Add(voipFilter)
	fc.Add(bpfFilter)
	fc.Add(specificTextFilter)

	filters := fc.GetFilters()
	assert.Equal(t, 4, len(filters))

	// Verify sorted order: BPF (0.9) > VoIP (0.7) > TextSpecific (0.6) > TextAll (0.3)
	assert.Equal(t, "bpf", filters[0].Type())
	assert.Equal(t, 0.9, filters[0].Selectivity())

	assert.Equal(t, "voip", filters[1].Type())
	assert.Equal(t, 0.7, filters[1].Selectivity())

	assert.Equal(t, "text", filters[2].Type())
	assert.Equal(t, 0.6, filters[2].Selectivity())

	assert.Equal(t, "text", filters[3].Type())
	assert.Equal(t, 0.3, filters[3].Selectivity())
}

// TestFilterChain_EmptyChainMatchesAll verifies empty chain matches everything
func TestFilterChain_EmptyChainMatchesAll(t *testing.T) {
	fc := NewFilterChain()

	packet := components.PacketDisplay{
		Protocol: "TCP",
		SrcIP:    "192.168.1.1",
		DstIP:    "10.0.0.1",
	}

	assert.True(t, fc.Match(packet))
	assert.True(t, fc.IsEmpty())
}

// TestFilterChain_ShortCircuitEvaluation verifies early exit on non-match
func TestFilterChain_ShortCircuitEvaluation(t *testing.T) {
	fc := NewFilterChain()

	// Add a very selective filter that won't match
	bpfFilter, _ := NewBPFFilter("port 5060") // 0.85 selectivity
	fc.Add(bpfFilter)

	// Add a less selective filter that would match
	textFilter := NewTextFilter("192.168", []string{"all"}) // 0.3 selectivity
	fc.Add(textFilter)

	packet := components.PacketDisplay{
		Protocol: "TCP",
		SrcIP:    "192.168.1.1",
		DstIP:    "10.0.0.1",
		SrcPort:  "12345", // Does not match port 5060
	}

	// Should fail fast on BPF filter (checked first due to higher selectivity)
	assert.False(t, fc.Match(packet))

	filters := fc.GetFilters()
	// Verify BPF is checked first
	assert.Equal(t, "bpf", filters[0].Type())
	assert.Equal(t, "text", filters[1].Type())
}

// TestFilterChain_AllFiltersMustMatch verifies AND logic
func TestFilterChain_AllFiltersMustMatch(t *testing.T) {
	fc := NewFilterChain()

	bpfFilter, _ := NewBPFFilter("tcp")
	fc.Add(bpfFilter)

	textFilter := NewTextFilter("192.168", []string{"src"})
	fc.Add(textFilter)

	// Packet matches both filters
	matchingPacket := components.PacketDisplay{
		Protocol: "TCP",
		SrcIP:    "192.168.1.1",
		DstIP:    "10.0.0.1",
	}
	assert.True(t, fc.Match(matchingPacket))

	// Packet matches only one filter
	partialPacket := components.PacketDisplay{
		Protocol: "UDP", // Doesn't match BPF
		SrcIP:    "192.168.1.1",
	}
	assert.False(t, fc.Match(partialPacket))
}

// TestFilterChain_Clear verifies clearing all filters
func TestFilterChain_Clear(t *testing.T) {
	fc := NewFilterChain()

	fc.Add(NewTextFilter("test", []string{"all"}))
	fc.Add(NewVoIPFilter("user", "alicent"))

	assert.False(t, fc.IsEmpty())
	assert.Equal(t, 2, len(fc.GetFilters()))

	fc.Clear()

	assert.True(t, fc.IsEmpty())
	assert.Equal(t, 0, len(fc.GetFilters()))
}

// TestBooleanFilter_SelectivityAND verifies AND selectivity calculation
func TestBooleanFilter_SelectivityAND(t *testing.T) {
	// AND: average of children
	left := NewTextFilter("test", []string{"all"})  // 0.3
	right := NewTextFilter("test", []string{"src"}) // 0.6

	boolFilter := NewBooleanFilter(OpAND, left, right, "test AND test")

	// Expected: (0.3 + 0.6) / 2.0 = 0.45
	assert.InDelta(t, 0.45, boolFilter.Selectivity(), 0.0001)
}

// TestBooleanFilter_SelectivityOR verifies OR selectivity calculation
func TestBooleanFilter_SelectivityOR(t *testing.T) {
	// OR: minimum of children (least selective determines)
	left := NewTextFilter("test", []string{"all"})  // 0.3
	right := NewTextFilter("test", []string{"src"}) // 0.6

	boolFilter := NewBooleanFilter(OpOR, left, right, "test OR test")

	// Expected: min(0.3, 0.6) = 0.3
	assert.Equal(t, 0.3, boolFilter.Selectivity())
}

// TestBooleanFilter_SelectivityNOT verifies NOT selectivity calculation
func TestBooleanFilter_SelectivityNOT(t *testing.T) {
	// NOT: inverse of child
	child := NewTextFilter("test", []string{"all"}) // 0.3

	boolFilter := NewBooleanFilter(OpNOT, child, nil, "NOT test")

	// Expected: 1.0 - 0.3 = 0.7
	assert.Equal(t, 0.7, boolFilter.Selectivity())
}

// TestBPFFilter_Selectivity verifies BPF selectivity values
func TestBPFFilter_Selectivity(t *testing.T) {
	tests := []struct {
		name        string
		expr        string
		selectivity float64
	}{
		{"protocol", "tcp", 0.9},
		{"port", "port 5060", 0.85},
		{"host", "host 192.168.1.1", 0.85},
		{"net", "net 192.168.0.0/16", 0.75},
		{"unknown", "complex expression", 0.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, err := NewBPFFilter(tt.expr)
			assert.NoError(t, err)
			assert.Equal(t, tt.selectivity, filter.Selectivity())
		})
	}
}

// TestVoIPFilter_Selectivity verifies VoIP selectivity
func TestVoIPFilter_Selectivity(t *testing.T) {
	filter := NewVoIPFilter("user", "alicent")
	assert.Equal(t, 0.7, filter.Selectivity())
}

// TestTextFilter_Selectivity verifies text filter selectivity
func TestTextFilter_Selectivity(t *testing.T) {
	allFieldsFilter := NewTextFilter("test", []string{"all"})
	assert.Equal(t, 0.3, allFieldsFilter.Selectivity())

	specificFieldFilter := NewTextFilter("test", []string{"src"})
	assert.Equal(t, 0.6, specificFieldFilter.Selectivity())
}

// TestFilterChain_RemoveLastByInsertionOrder verifies RemoveLast removes by insertion order, not sorted position
func TestFilterChain_RemoveLastByInsertionOrder(t *testing.T) {
	fc := NewFilterChain()

	// Add filters in a specific insertion order
	textFilter := NewTextFilter("first", []string{"all"})         // Selectivity: 0.3 (inserted first)
	voipFilter := NewVoIPFilter("user", "alicent")                // Selectivity: 0.7 (inserted second)
	specificTextFilter := NewTextFilter("third", []string{"src"}) // Selectivity: 0.6 (inserted third)

	fc.Add(textFilter)
	fc.Add(voipFilter)
	fc.Add(specificTextFilter)

	// Filters are sorted by selectivity: [VoIP(0.7), Text(0.6), Text(0.3)]
	// But insertion order is: [Text(0.3), VoIP(0.7), Text(0.6)]
	filters := fc.GetFilters()
	assert.Equal(t, 3, len(filters))
	assert.Equal(t, "voip", filters[0].Type()) // Most selective (0.7)
	assert.Equal(t, "text", filters[1].Type()) // Second most selective (0.6)
	assert.Equal(t, "text", filters[2].Type()) // Least selective (0.3)

	// Remove last filter (should remove third inserted filter, which is Text(0.6))
	removed := fc.RemoveLast()
	assert.True(t, removed)

	// Verify the filter with selectivity 0.6 was removed (third inserted)
	filters = fc.GetFilters()
	assert.Equal(t, 2, len(filters))
	assert.Equal(t, "voip", filters[0].Type()) // VoIP (0.7) still present
	assert.Equal(t, "text", filters[1].Type()) // Text (0.3) still present
	assert.Equal(t, 0.7, filters[0].Selectivity())
	assert.Equal(t, 0.3, filters[1].Selectivity())

	// Remove last again (should remove second inserted filter, which is VoIP(0.7))
	removed = fc.RemoveLast()
	assert.True(t, removed)

	filters = fc.GetFilters()
	assert.Equal(t, 1, len(filters))
	assert.Equal(t, "text", filters[0].Type()) // Only Text (0.3) remains (first inserted)
	assert.Equal(t, 0.3, filters[0].Selectivity())

	// Remove last again (should remove first inserted filter, which is Text(0.3))
	removed = fc.RemoveLast()
	assert.True(t, removed)

	filters = fc.GetFilters()
	assert.Equal(t, 0, len(filters))
	assert.True(t, fc.IsEmpty())

	// Try to remove from empty chain
	removed = fc.RemoveLast()
	assert.False(t, removed)
}
