//go:build tui || all
// +build tui all

package filters

import (
	"strings"

	"github.com/endorses/lippycat/cmd/tui/components"
)

// NodeFilter filters packets by node/hunter ID
// Supports wildcards: node:* matches all nodes, node:edge-* matches all edge hunters
type NodeFilter struct {
	nodePattern string
	isWildcard  bool
	prefix      string // for prefix matching (e.g., "edge-" from "edge-*")
}

// NewNodeFilter creates a new node filter
// Pattern can be:
//   - Exact match: "hunter-kamailio"
//   - Wildcard: "*" (all nodes), "hunter-*" (prefix match), "*-kamailio" (suffix match)
func NewNodeFilter(pattern string) *NodeFilter {
	f := &NodeFilter{
		nodePattern: pattern,
		isWildcard:  strings.Contains(pattern, "*"),
	}

	// Pre-calculate prefix for optimization
	if f.isWildcard {
		// For "edge-*" pattern, extract "edge-" prefix
		if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
			f.prefix = strings.TrimSuffix(pattern, "*")
		}
	}

	return f
}

// Match checks if the packet's NodeID matches the filter pattern
func (f *NodeFilter) Match(packet components.PacketDisplay) bool {
	nodeID := packet.NodeID

	// Exact match (fast path)
	if !f.isWildcard {
		return nodeID == f.nodePattern
	}

	// Wildcard matching
	if f.nodePattern == "*" {
		// Match all nodes (except empty/Local)
		return nodeID != "" && nodeID != "Local"
	}

	// Prefix wildcard: "edge-*"
	if f.prefix != "" {
		return strings.HasPrefix(nodeID, f.prefix)
	}

	// Suffix wildcard: "*-kamailio"
	if strings.HasPrefix(f.nodePattern, "*") {
		suffix := strings.TrimPrefix(f.nodePattern, "*")
		return strings.HasSuffix(nodeID, suffix)
	}

	// Middle wildcard: "hunter-*-01" (contains matching)
	// Convert pattern to regex-like matching
	parts := strings.Split(f.nodePattern, "*")
	if len(parts) == 2 {
		return strings.HasPrefix(nodeID, parts[0]) && strings.HasSuffix(nodeID, parts[1])
	}

	// Fallback: exact match
	return nodeID == f.nodePattern
}

// String returns a human-readable representation
func (f *NodeFilter) String() string {
	return "node:" + f.nodePattern
}

// Type returns the filter type
func (f *NodeFilter) Type() string {
	return "node"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Node filters are highly selective (typically filter out most packets)
func (f *NodeFilter) Selectivity() float64 {
	if f.nodePattern == "*" {
		// Matches all nodes - least selective
		return 0.1
	}
	// Specific node/hunter - highly selective
	return 0.9
}
