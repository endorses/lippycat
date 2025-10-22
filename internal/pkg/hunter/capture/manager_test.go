//go:build hunter || all

package capture

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPortFromAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "standard port",
			addr:     "processor.example.com:50051",
			expected: "50051",
		},
		{
			name:     "custom port",
			addr:     "10.0.0.5:8443",
			expected: "8443",
		},
		{
			name:     "IPv4 with port",
			addr:     "192.168.1.100:9090",
			expected: "9090",
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:50051",
			expected: "50051",
		},
		{
			name:     "IPv6 full address with port",
			addr:     "[2001:db8::1]:8080",
			expected: "8080",
		},
		{
			name:     "empty address",
			addr:     "",
			expected: "",
		},
		{
			name:     "no port",
			addr:     "processor.example.com",
			expected: "",
		},
		{
			name:     "invalid format",
			addr:     "not:a:valid:address:format",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPortFromAddr(tt.addr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildProcessorPortExclusionFilter(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		processorAddr string
		expected      string
	}{
		{
			name:          "standard port",
			processorAddr: "processor.example.com:50051",
			expected:      "not port 50051",
		},
		{
			name:          "custom port",
			processorAddr: "10.0.0.5:8443",
			expected:      "not port 8443",
		},
		{
			name:          "IPv6 with port",
			processorAddr: "[::1]:9090",
			expected:      "not port 9090",
		},
		{
			name:          "empty address",
			processorAddr: "",
			expected:      "",
		},
		{
			name:          "no port",
			processorAddr: "processor.example.com",
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(Config{
				Interfaces:    []string{"eth0"},
				ProcessorAddr: tt.processorAddr,
			}, ctx)

			result := m.buildProcessorPortExclusionFilter()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildCombinedBPFFilter(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		baseFilter     string
		processorAddr  string
		dynamicFilters []*management.Filter
		expected       string
	}{
		{
			name:           "no filters at all",
			baseFilter:     "",
			processorAddr:  "",
			dynamicFilters: nil,
			expected:       "",
		},
		{
			name:           "only processor port exclusion",
			baseFilter:     "",
			processorAddr:  "processor:50051",
			dynamicFilters: nil,
			expected:       "not port 50051",
		},
		{
			name:           "only base filter",
			baseFilter:     "not port 22",
			processorAddr:  "",
			dynamicFilters: nil,
			expected:       "not port 22",
		},
		{
			name:           "base filter and processor exclusion",
			baseFilter:     "not port 22",
			processorAddr:  "processor:50051",
			dynamicFilters: nil,
			expected:       "(not port 22) and (not port 50051)",
		},
		{
			name:          "dynamic filter only",
			baseFilter:    "",
			processorAddr: "",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
			},
			expected: "(port 443)",
		},
		{
			name:          "dynamic filter with processor exclusion",
			baseFilter:    "",
			processorAddr: "processor:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
			},
			expected: "((port 443)) and (not port 50051)",
		},
		{
			name:          "dynamic filter with base filter and processor exclusion",
			baseFilter:    "not port 22",
			processorAddr: "processor:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
			},
			expected: "((port 443)) and ((not port 22) and (not port 50051))",
		},
		{
			name:          "multiple dynamic filters with processor exclusion",
			baseFilter:    "",
			processorAddr: "processor:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 5060", Enabled: true},
			},
			expected: "((port 443) or (port 5060)) and (not port 50051)",
		},
		{
			name:          "multiple dynamic filters with base filter and processor exclusion",
			baseFilter:    "not port 22",
			processorAddr: "processor:8443",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 5060", Enabled: true},
			},
			expected: "((port 443) or (port 5060)) and ((not port 22) and (not port 8443))",
		},
		{
			name:          "disabled dynamic filter ignored",
			baseFilter:    "",
			processorAddr: "processor:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 80", Enabled: false},
			},
			expected: "((port 443)) and (not port 50051)",
		},
		{
			name:          "non-BPF filter ignored",
			baseFilter:    "",
			processorAddr: "processor:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
				{Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true},
			},
			expected: "((port 443)) and (not port 50051)",
		},
		{
			name:          "IPv6 processor address",
			baseFilter:    "",
			processorAddr: "[2001:db8::1]:50051",
			dynamicFilters: []*management.Filter{
				{Type: management.FilterType_FILTER_BPF, Pattern: "port 443", Enabled: true},
			},
			expected: "((port 443)) and (not port 50051)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(Config{
				Interfaces:    []string{"eth0"},
				BaseFilter:    tt.baseFilter,
				ProcessorAddr: tt.processorAddr,
			}, ctx)

			result := m.buildCombinedBPFFilter(tt.dynamicFilters)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestManagerConfigPropagation(t *testing.T) {
	ctx := context.Background()

	config := Config{
		Interfaces:    []string{"eth0", "eth1"},
		BaseFilter:    "not port 22",
		BufferSize:    1000,
		ProcessorAddr: "processor.example.com:50051",
	}

	m := New(config, ctx)

	require.NotNil(t, m)
	assert.Equal(t, config.Interfaces, m.interfaces)
	assert.Equal(t, config.BaseFilter, m.baseFilter)
	assert.Equal(t, config.BufferSize, m.bufferSize)
	assert.Equal(t, config.ProcessorAddr, m.processorAddr)
}
