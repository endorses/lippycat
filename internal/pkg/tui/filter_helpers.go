//go:build tui || all

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// parseAndApplyFilter parses and applies a filter expression to the packet list.
// For offline mode or paused: Reapplies filter to existing packets immediately.
// For live mode (not paused): Does NOT reapply - at high traffic rates the buffer refills quickly.
// This prevents UI freezing at 300-400+ Mbit/s by avoiding O(n) scans.
func (m *Model) parseAndApplyFilter(filterStr string) tea.Cmd {
	// NOTE: We do NOT clear existing filters - this allows filter stacking
	// Use 'c' to clear all filters or 'C' to remove the last filter

	if filterStr == "" {
		return nil
	}

	// Try to parse as boolean expression first
	filter, err := filters.ParseBooleanExpression(filterStr, m.parseSimpleFilter)
	if err == nil && filter != nil {
		m.packetStore.AddFilter(filter)
	} else if err != nil {
		// Show error toast for invalid filter
		return m.uiState.Toast.Show(
			fmt.Sprintf("Invalid filter: %s", err.Error()),
			components.ToastError,
			components.ToastDurationLong,
		)
	}

	// For offline mode or when paused, reapply filters to existing packets immediately
	// since no new packets will arrive.
	if m.captureMode == components.CaptureModeOffline || m.uiState.IsPaused() {
		m.packetStore.ReapplyFilters()
		m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
		// Reset sync counters for incremental updates
		_, _, _, matchedPackets := m.packetStore.GetBufferInfo()
		m.lastSyncedFilteredCount = matchedPackets
		m.lastFilterState = true
	} else {
		// For live mode (not paused), clear filtered packets - new packets will flow through
		// filter automatically via AddPacketBatch() and incremental updates.
		// At high traffic rates (300-400 Mbit/s), buffer refills in seconds anyway.
		m.packetStore.ClearFilteredPackets()
		m.uiState.PacketList.SetPackets([]components.PacketDisplay{})
		// Reset sync counters so incremental updates work correctly
		m.lastSyncedFilteredCount = 0
		m.lastFilterState = true
	}

	// Show toast with filter count
	filterCount := m.packetStore.FilterChain.Count()
	if filterCount > 1 {
		return m.uiState.Toast.Show(
			fmt.Sprintf("Filter added (%d filters active)", filterCount),
			components.ToastSuccess,
			components.ToastDurationShort,
		)
	}

	return nil
}

// parseSimpleFilter parses a simple (non-boolean) filter expression
func (m *Model) parseSimpleFilter(filterStr string) filters.Filter {
	filterStr = strings.TrimSpace(filterStr)

	// Detect filter type based on syntax
	if strings.Contains(filterStr, "sip.") {
		// VoIP filter: sip.user:alicent, sip.from:555*, etc.
		parts := strings.SplitN(filterStr, ":", 2)
		if len(parts) == 2 {
			field := strings.TrimPrefix(parts[0], "sip.")
			value := parts[1]
			return filters.NewVoIPFilter(field, value)
		}
	} else if strings.HasPrefix(strings.ToLower(filterStr), "has:") {
		// Metadata filter: has:voip (checks for presence of metadata)
		metadataType := strings.TrimPrefix(strings.ToLower(filterStr), "has:")
		return filters.NewMetadataFilter(metadataType)
	} else if strings.HasPrefix(strings.ToLower(filterStr), "node:") {
		// Node filter: node:hunter-kamailio, node:edge-*, node:* (filters by NodeID)
		nodePattern := strings.TrimPrefix(filterStr, "node:")
		nodePattern = strings.TrimPrefix(nodePattern, "node:") // handle case variations
		return filters.NewNodeFilter(nodePattern)
	} else if strings.Contains(filterStr, ":") && !isBPFExpression(filterStr) {
		// Field-specific filter: field:value
		// Supported fields: protocol, src, dst, info
		parts := strings.SplitN(filterStr, ":", 2)
		if len(parts) == 2 {
			field := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])

			// Map field names to text filter fields
			validFields := map[string]bool{
				"protocol": true,
				"src":      true,
				"dst":      true,
				"info":     true,
			}

			if validFields[field] {
				return filters.NewTextFilter(value, []string{field})
			}
		}
	} else if isBPFExpression(filterStr) {
		// BPF filter: port 5060, host 192.168.1.1, tcp, udp, etc.
		filter, err := filters.NewBPFFilter(filterStr)
		if err == nil {
			return filter
		}
		// Fall back to text filter if BPF parse fails
	}

	// Simple text filter for anything else
	return filters.NewTextFilter(filterStr, []string{"all"})
}

// isBPFExpression checks if a string looks like a BPF expression
func isBPFExpression(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))

	// Protocol keywords
	if s == "tcp" || s == "udp" || s == "icmp" || s == "ip" {
		return true
	}

	// BPF keywords
	bpfKeywords := []string{"port", "host", "net", "src", "dst", "and", "or", "not"}
	for _, keyword := range bpfKeywords {
		if strings.Contains(s, keyword+" ") || strings.HasPrefix(s, keyword+" ") {
			return true
		}
	}

	return false
}

// Note: applyFilters() was removed in favor of async reapplication
// via startAsyncFilterReapply() to prevent UI freezing at high packet rates.

// parseCallFilter parses a filter expression for call filtering
// Supports:
//   - state:active, state:ringing,ended -> CallStateFilter
//   - duration:>30s, duration:>=5m -> NumericComparisonFilter
//   - mos:>3.5, jitter:<50, loss:>5, packets:>100 -> NumericComparisonFilter
//   - from:alice, to:bob, user:alice, callid:abc123, codec:g711 -> TextFilter
//   - node:hunter-1, node:edge-* -> NodeFilter
//   - plain text -> TextFilter on all call fields
func parseCallFilter(filterStr string) (filters.Filter, error) {
	filterStr = strings.TrimSpace(filterStr)
	if filterStr == "" {
		return nil, nil
	}

	lowerStr := strings.ToLower(filterStr)

	// Check for state: prefix
	if strings.HasPrefix(lowerStr, "state:") {
		statesStr := strings.TrimPrefix(filterStr, "state:")
		statesStr = strings.TrimPrefix(statesStr, "State:") // handle case variations
		return filters.NewCallStateFilter(statesStr), nil
	}

	// Check for numeric comparison fields
	numericFields := map[string]bool{
		"duration": true,
		"mos":      true,
		"jitter":   true,
		"loss":     true,
		"packets":  true,
	}

	// Parse field:operator syntax for numeric fields
	if colonIdx := strings.Index(filterStr, ":"); colonIdx != -1 {
		field := strings.ToLower(strings.TrimSpace(filterStr[:colonIdx]))
		value := strings.TrimSpace(filterStr[colonIdx+1:])

		// Check if this is a numeric field with an operator
		if numericFields[field] && len(value) > 0 {
			// Check if value starts with a comparison operator
			if value[0] == '>' || value[0] == '<' || value[0] == '=' {
				filter, err := filters.NewNumericComparisonFilter(field, value)
				if err != nil {
					return nil, fmt.Errorf("invalid %s filter: %v", field, err)
				}
				return filter, nil
			}
		}

		// Check for node: prefix
		if field == "node" {
			return filters.NewNodeFilter(value), nil
		}

		// Check for text field filters
		textFields := map[string][]string{
			"from":   {"from"},
			"to":     {"to"},
			"user":   {"user"}, // searches both from and to
			"callid": {"callid"},
			"codec":  {"codec"},
		}

		if searchFields, ok := textFields[field]; ok {
			return filters.NewTextFilter(value, searchFields), nil
		}
	}

	// Default: plain text search on all call fields
	return filters.NewTextFilter(filterStr, []string{"all"}), nil
}
