//go:build tui || all
// +build tui all

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/filters"
)

// parseAndApplyFilter parses and applies a filter expression to the packet list
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
		toastCmd := m.uiState.Toast.Show(
			fmt.Sprintf("Invalid filter: %s", err.Error()),
			components.ToastError,
			components.ToastDurationLong,
		)

		// Reapply filters to all packets (don't clear - keep existing filters)
		m.applyFilters()

		// Update display
		if !m.packetStore.HasFilter() {
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		} else {
			m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
		}

		return toastCmd
	}

	// Reapply filters to all packets
	m.applyFilters()

	// Update display
	if !m.packetStore.HasFilter() {
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	} else {
		m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
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

// applyFilters re-applies all active filters to the packet list
func (m *Model) applyFilters() {
	if !m.packetStore.HasFilter() {
		m.packetStore.MatchedPackets = m.packetStore.PacketsCount
		m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
		return
	}

	orderedPackets := m.getPacketsInOrder()
	m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0, len(orderedPackets))
	for _, pkt := range orderedPackets {
		if m.packetStore.MatchFilter(pkt) {
			m.packetStore.FilteredPackets = append(m.packetStore.FilteredPackets, pkt)
		}
	}
	m.packetStore.MatchedPackets = len(m.packetStore.FilteredPackets)
}
