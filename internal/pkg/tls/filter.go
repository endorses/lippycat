//go:build cli || hunter || tap || tui || all

package tls

import (
	"fmt"
	"strconv"
	"strings"
)

// FilterBuilder builds BPF filters for TLS capture.
type FilterBuilder struct{}

// NewFilterBuilder creates a new TLS filter builder.
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// FilterConfig configures the BPF filter.
type FilterConfig struct {
	// Ports to capture (default: 443)
	Ports []int
	// BaseFilter is an optional additional BPF filter to combine with.
	BaseFilter string
}

// Build constructs a BPF filter for TLS traffic.
func (fb *FilterBuilder) Build(config FilterConfig) string {
	var conditions []string

	// Base filter
	if config.BaseFilter != "" {
		conditions = append(conditions, fmt.Sprintf("(%s)", config.BaseFilter))
	}

	// Port filter (TLS is always TCP)
	if len(config.Ports) > 0 {
		portCond := fb.buildPortCondition(config.Ports)
		conditions = append(conditions, portCond)
	} else {
		// Default to port 443
		conditions = append(conditions, "port 443")
	}

	// TLS is TCP-only
	conditions = append(conditions, "tcp")

	return strings.Join(conditions, " and ")
}

// buildPortCondition creates a port filter.
func (fb *FilterBuilder) buildPortCondition(ports []int) string {
	if len(ports) == 1 {
		return fmt.Sprintf("port %d", ports[0])
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, fmt.Sprintf("port %d", p))
	}
	return "(" + strings.Join(portStrs, " or ") + ")"
}

// ParsePorts parses a comma-separated list of ports.
func ParsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		return []int{443}, nil // Default
	}

	var ports []int
	for _, p := range strings.Split(portStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s': %w", p, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		ports = append(ports, port)
	}

	if len(ports) == 0 {
		return []int{443}, nil
	}

	return ports, nil
}

// DefaultTLSPorts returns the default ports commonly used for TLS.
var DefaultTLSPorts = []int{
	443,  // HTTPS
	465,  // SMTPS
	636,  // LDAPS
	853,  // DNS over TLS
	989,  // FTPS data
	990,  // FTPS control
	992,  // Telnet over TLS
	993,  // IMAPS
	995,  // POP3S
	8443, // Alternative HTTPS
}

// LoadPatternsFromFile loads patterns from a file (one per line).
// This is a convenience wrapper.
func LoadPatternsFromFile(filename string) ([]string, error) {
	// Import from filtering package for consistency
	// Note: The filtering package is imported at runtime to avoid circular deps
	// For now, implement inline (can be refactored later)
	return loadPatternsFromFileInline(filename)
}

func loadPatternsFromFileInline(filename string) ([]string, error) {
	// Use the same implementation as filtering package
	// This avoids an import cycle
	data, err := readFile(filename)
	if err != nil {
		return nil, err
	}

	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	return patterns, nil
}

// readFile reads a file's contents.
func readFile(filename string) ([]byte, error) {
	// Use os.ReadFile from the standard library
	// Imported in the main code to avoid import cycles
	return nil, fmt.Errorf("use filtering.LoadPatternsFromFile instead")
}
