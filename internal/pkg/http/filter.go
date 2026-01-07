package http

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultHTTPPorts are the default ports for HTTP traffic.
var DefaultHTTPPorts = []uint16{80, 8080, 8000, 3000, 8888, 8443}

// FilterBuilder builds BPF filters for HTTP capture.
type FilterBuilder struct{}

// FilterConfig holds filter configuration.
type FilterConfig struct {
	Ports      []int  // HTTP ports to capture
	BaseFilter string // User-provided additional filter
}

// NewFilterBuilder creates a new filter builder.
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// Build constructs a BPF filter string for HTTP capture.
func (fb *FilterBuilder) Build(config FilterConfig) string {
	parts := []string{}

	// Build port filter
	if len(config.Ports) > 0 {
		portParts := make([]string, len(config.Ports))
		for i, port := range config.Ports {
			portParts[i] = fmt.Sprintf("port %d", port)
		}
		portFilter := strings.Join(portParts, " or ")
		parts = append(parts, fmt.Sprintf("tcp and (%s)", portFilter))
	} else {
		// Default ports
		portParts := make([]string, len(DefaultHTTPPorts))
		for i, port := range DefaultHTTPPorts {
			portParts[i] = fmt.Sprintf("port %d", port)
		}
		portFilter := strings.Join(portParts, " or ")
		parts = append(parts, fmt.Sprintf("tcp and (%s)", portFilter))
	}

	// Add base filter if provided
	if config.BaseFilter != "" {
		parts = append(parts, fmt.Sprintf("(%s)", config.BaseFilter))
	}

	return strings.Join(parts, " and ")
}

// ParsePorts parses a comma-separated port string.
func ParsePorts(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}

	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}

		ports = append(ports, port)
	}

	return ports, nil
}

// ParseStatusCodes parses a comma-separated status code string.
// Supports: "404", "4xx", "400-499"
func ParseStatusCodes(s string) []string {
	if s == "" {
		return nil
	}

	var codes []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			codes = append(codes, part)
		}
	}

	return codes
}

// ParseMethods parses a comma-separated HTTP method string.
func ParseMethods(s string) []string {
	if s == "" {
		return nil
	}

	var methods []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.ToUpper(part))
		if part != "" {
			methods = append(methods, part)
		}
	}

	return methods
}
