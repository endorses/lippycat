package voip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRTPPortRange(t *testing.T) {
	r := DefaultRTPPortRange()
	assert.Equal(t, DefaultRTPPortRangeStart, r.Start)
	assert.Equal(t, DefaultRTPPortRangeEnd, r.End)
	assert.Equal(t, 10000, r.Start)
	assert.Equal(t, 32768, r.End)
}

func TestNewVoIPFilterBuilder(t *testing.T) {
	builder := NewVoIPFilterBuilder()
	require.NotNil(t, builder)
}

// TestVoIPFilterBuilder_Build tests all filter construction combinations
// from the research report (§3 and §4)
//
// NOTE: All filters now include the IP fragment clause (ip[6:2] & 0x1fff > 0)
// to capture subsequent fragments of fragmented UDP packets. This is critical
// for capturing large SIP INVITEs that exceed MTU. See Fix #12 in
// docs/debug/rtp-sip-correlation.md for details.
func TestVoIPFilterBuilder_Build(t *testing.T) {
	builder := NewVoIPFilterBuilder()

	// Helper constant for readability
	const frag = IPFragmentClause // "(ip[6:2] & 0x1fff > 0)"

	tests := []struct {
		name     string
		config   VoIPFilterConfig
		expected string
	}{
		// Basic cases - no VoIP-specific filtering
		{
			name:     "no flags - empty filter",
			config:   VoIPFilterConfig{},
			expected: "",
		},
		{
			name: "base filter only",
			config: VoIPFilterConfig{
				BaseFilter: "host 10.0.0.1",
			},
			expected: "(host 10.0.0.1) or " + frag,
		},

		// UDP-only flag
		{
			name: "udp-only flag alone",
			config: VoIPFilterConfig{
				UDPOnly: true,
			},
			expected: "udp or " + frag,
		},
		{
			name: "udp-only with base filter",
			config: VoIPFilterConfig{
				UDPOnly:    true,
				BaseFilter: "host 10.0.0.1",
			},
			expected: "((host 10.0.0.1) and udp) or " + frag,
		},

		// SIP port flag (with default RTP range)
		{
			name: "single SIP port",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060},
			},
			expected: "((port 5060) or (udp portrange 10000-32768)) or " + frag,
		},
		{
			name: "multiple SIP ports",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060, 5080},
			},
			expected: "((port 5060 or port 5080) or (udp portrange 10000-32768)) or " + frag,
		},
		{
			name: "three SIP ports",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060, 5061, 5080},
			},
			expected: "((port 5060 or port 5061 or port 5080) or (udp portrange 10000-32768)) or " + frag,
		},

		// SIP port + UDP-only
		{
			name: "SIP port with udp-only",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060},
				UDPOnly:  true,
			},
			expected: "(udp and ((port 5060) or (portrange 10000-32768))) or " + frag,
		},
		{
			name: "multiple SIP ports with udp-only",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060, 5080},
				UDPOnly:  true,
			},
			expected: "(udp and ((port 5060 or port 5080) or (portrange 10000-32768))) or " + frag,
		},

		// Custom RTP port range
		{
			name: "custom RTP range only (no SIP ports)",
			config: VoIPFilterConfig{
				RTPPortRanges: []PortRange{{Start: 8000, End: 9000}},
			},
			expected: "((udp portrange 8000-9000)) or " + frag,
		},
		{
			name: "SIP port with custom RTP range",
			config: VoIPFilterConfig{
				SIPPorts:      []int{5060},
				RTPPortRanges: []PortRange{{Start: 8000, End: 9000}},
			},
			expected: "((port 5060) or (udp portrange 8000-9000)) or " + frag,
		},
		{
			name: "multiple custom RTP ranges",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060},
				RTPPortRanges: []PortRange{
					{Start: 8000, End: 9000},
					{Start: 40000, End: 50000},
				},
			},
			expected: "((port 5060) or (udp portrange 8000-9000) or (udp portrange 40000-50000)) or " + frag,
		},
		{
			name: "multiple SIP ports with multiple RTP ranges",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060, 5080},
				RTPPortRanges: []PortRange{
					{Start: 8000, End: 9000},
					{Start: 40000, End: 50000},
				},
			},
			expected: "((port 5060 or port 5080) or (udp portrange 8000-9000) or (udp portrange 40000-50000)) or " + frag,
		},

		// Custom RTP range + UDP-only
		{
			name: "custom RTP range with udp-only",
			config: VoIPFilterConfig{
				RTPPortRanges: []PortRange{{Start: 8000, End: 9000}},
				UDPOnly:       true,
			},
			expected: "(udp and ((portrange 8000-9000))) or " + frag,
		},
		{
			name: "SIP port + custom RTP range + udp-only",
			config: VoIPFilterConfig{
				SIPPorts:      []int{5060},
				RTPPortRanges: []PortRange{{Start: 8000, End: 9000}},
				UDPOnly:       true,
			},
			expected: "(udp and ((port 5060) or (portrange 8000-9000))) or " + frag,
		},
		{
			name: "multiple RTP ranges with udp-only",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060},
				RTPPortRanges: []PortRange{
					{Start: 8000, End: 9000},
					{Start: 40000, End: 50000},
				},
				UDPOnly: true,
			},
			expected: "(udp and ((port 5060) or (portrange 8000-9000) or (portrange 40000-50000))) or " + frag,
		},

		// Combined with base filter
		{
			name: "SIP port with base filter",
			config: VoIPFilterConfig{
				SIPPorts:   []int{5060},
				BaseFilter: "host 10.0.0.1",
			},
			expected: "(host 10.0.0.1) and (((port 5060) or (udp portrange 10000-32768)) or " + frag + ")",
		},
		{
			name: "SIP port + udp-only with base filter",
			config: VoIPFilterConfig{
				SIPPorts:   []int{5060},
				UDPOnly:    true,
				BaseFilter: "host 10.0.0.1",
			},
			expected: "(host 10.0.0.1) and ((udp and ((port 5060) or (portrange 10000-32768))) or " + frag + ")",
		},
		{
			name: "SIP port + custom RTP with base filter",
			config: VoIPFilterConfig{
				SIPPorts:      []int{5060},
				RTPPortRanges: []PortRange{{Start: 8000, End: 9000}},
				BaseFilter:    "not port 22",
			},
			expected: "(not port 22) and (((port 5060) or (udp portrange 8000-9000)) or " + frag + ")",
		},
		{
			name: "complex combination",
			config: VoIPFilterConfig{
				SIPPorts: []int{5060, 5080},
				RTPPortRanges: []PortRange{
					{Start: 8000, End: 9000},
					{Start: 40000, End: 50000},
				},
				UDPOnly:    true,
				BaseFilter: "net 192.168.0.0/24",
			},
			expected: "(net 192.168.0.0/24) and ((udp and ((port 5060 or port 5080) or (portrange 8000-9000) or (portrange 40000-50000))) or " + frag + ")",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.Build(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []int
		expectError bool
		errorMsg    string
	}{
		// Valid inputs
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single port",
			input:    "5060",
			expected: []int{5060},
		},
		{
			name:     "two ports",
			input:    "5060,5061",
			expected: []int{5060, 5061},
		},
		{
			name:     "multiple ports",
			input:    "5060,5061,5080",
			expected: []int{5060, 5061, 5080},
		},
		{
			name:     "ports with spaces",
			input:    "5060, 5061, 5080",
			expected: []int{5060, 5061, 5080},
		},
		{
			name:     "trailing comma ignored",
			input:    "5060,5061,",
			expected: []int{5060, 5061},
		},
		{
			name:     "leading comma ignored",
			input:    ",5060,5061",
			expected: []int{5060, 5061},
		},
		{
			name:     "min valid port",
			input:    "1",
			expected: []int{1},
		},
		{
			name:     "max valid port",
			input:    "65535",
			expected: []int{65535},
		},

		// Invalid inputs
		{
			name:        "invalid port string",
			input:       "abc",
			expectError: true,
			errorMsg:    "invalid port",
		},
		{
			name:        "negative port",
			input:       "-1",
			expectError: true,
			errorMsg:    "invalid port",
		},
		{
			name:        "port zero",
			input:       "0",
			expectError: true,
			errorMsg:    "port must be between 1 and 65535",
		},
		{
			name:        "port too high",
			input:       "65536",
			expectError: true,
			errorMsg:    "port must be between 1 and 65535",
		},
		{
			name:        "one valid one invalid",
			input:       "5060,abc",
			expectError: true,
			errorMsg:    "invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePorts(tt.input)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParsePortRanges(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []PortRange
		expectError bool
		errorMsg    string
	}{
		// Valid inputs
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "single range",
			input: "8000-9000",
			expected: []PortRange{
				{Start: 8000, End: 9000},
			},
		},
		{
			name:  "two ranges",
			input: "8000-9000,40000-50000",
			expected: []PortRange{
				{Start: 8000, End: 9000},
				{Start: 40000, End: 50000},
			},
		},
		{
			name:  "ranges with spaces",
			input: "8000-9000, 40000-50000",
			expected: []PortRange{
				{Start: 8000, End: 9000},
				{Start: 40000, End: 50000},
			},
		},
		{
			name:  "spaces around dash",
			input: "8000 - 9000",
			expected: []PortRange{
				{Start: 8000, End: 9000},
			},
		},
		{
			name:  "trailing comma ignored",
			input: "8000-9000,",
			expected: []PortRange{
				{Start: 8000, End: 9000},
			},
		},
		{
			name:  "single port range (same start and end)",
			input: "5060-5060",
			expected: []PortRange{
				{Start: 5060, End: 5060},
			},
		},
		{
			name:  "min valid ports",
			input: "1-2",
			expected: []PortRange{
				{Start: 1, End: 2},
			},
		},
		{
			name:  "max valid ports",
			input: "65534-65535",
			expected: []PortRange{
				{Start: 65534, End: 65535},
			},
		},
		{
			name:  "three ranges",
			input: "8000-9000,16384-32768,40000-50000",
			expected: []PortRange{
				{Start: 8000, End: 9000},
				{Start: 16384, End: 32768},
				{Start: 40000, End: 50000},
			},
		},

		// Invalid inputs
		{
			name:        "missing dash",
			input:       "8000",
			expectError: true,
			errorMsg:    "invalid port range format",
		},
		{
			name:        "too many dashes",
			input:       "8000-9000-10000",
			expectError: true,
			errorMsg:    "invalid port range format",
		},
		{
			name:        "invalid start port",
			input:       "abc-9000",
			expectError: true,
			errorMsg:    "invalid start port",
		},
		{
			name:        "invalid end port",
			input:       "8000-abc",
			expectError: true,
			errorMsg:    "invalid end port",
		},
		{
			name:        "start greater than end",
			input:       "9000-8000",
			expectError: true,
			errorMsg:    "start port (9000) must be less than or equal to end port (8000)",
		},
		{
			name:        "port zero in start",
			input:       "0-1000",
			expectError: true,
			errorMsg:    "start port must be between 1 and 65535",
		},
		{
			name:        "port zero in end",
			input:       "1-0",
			expectError: true,
			errorMsg:    "end port must be between 1 and 65535",
		},
		{
			name:        "port too high",
			input:       "1000-70000",
			expectError: true,
			errorMsg:    "end port must be between 1 and 65535",
		},
		{
			name:        "negative port",
			input:       "-100-5000",
			expectError: true,
			errorMsg:    "invalid port range format",
		},
		{
			name:        "one valid one invalid range",
			input:       "8000-9000,invalid",
			expectError: true,
			errorMsg:    "invalid port range format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePortRanges(tt.input)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port        int
		expectError bool
	}{
		{port: 1, expectError: false},
		{port: 5060, expectError: false},
		{port: 65535, expectError: false},
		{port: 0, expectError: true},
		{port: -1, expectError: true},
		{port: 65536, expectError: true},
		{port: 100000, expectError: true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.port)), func(t *testing.T) {
			err := validatePort(tt.port)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name        string
		start       int
		end         int
		expectError bool
	}{
		{name: "valid range", start: 8000, end: 9000, expectError: false},
		{name: "same start and end", start: 5060, end: 5060, expectError: false},
		{name: "min range", start: 1, end: 2, expectError: false},
		{name: "max range", start: 65534, end: 65535, expectError: false},
		{name: "start > end", start: 9000, end: 8000, expectError: true},
		{name: "invalid start", start: 0, end: 5000, expectError: true},
		{name: "invalid end", start: 5000, end: 70000, expectError: true},
		{name: "both invalid", start: 0, end: 70000, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortRange(tt.start, tt.end)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestVoIPFilterBuilder_Build_EdgeCases tests edge cases not covered in the main test
func TestVoIPFilterBuilder_Build_EdgeCases(t *testing.T) {
	builder := NewVoIPFilterBuilder()
	frag := IPFragmentClause

	t.Run("empty port list has no effect", func(t *testing.T) {
		result := builder.Build(VoIPFilterConfig{
			SIPPorts: []int{},
		})
		assert.Equal(t, "", result)
	})

	t.Run("empty RTP ranges uses default", func(t *testing.T) {
		// When SIP ports are specified but RTP ranges are empty,
		// the default RTP range should be used
		result := builder.Build(VoIPFilterConfig{
			SIPPorts:      []int{5060},
			RTPPortRanges: []PortRange{},
		})
		assert.Equal(t, "((port 5060) or (udp portrange 10000-32768)) or "+frag, result)
	})

	t.Run("base filter with complex expression", func(t *testing.T) {
		result := builder.Build(VoIPFilterConfig{
			SIPPorts:   []int{5060},
			BaseFilter: "(host 10.0.0.1 or host 10.0.0.2) and not port 22",
		})
		assert.Equal(t, "((host 10.0.0.1 or host 10.0.0.2) and not port 22) and (((port 5060) or (udp portrange 10000-32768)) or "+frag+")", result)
	})

	t.Run("single port in RTP range (start equals end)", func(t *testing.T) {
		result := builder.Build(VoIPFilterConfig{
			SIPPorts:      []int{5060},
			RTPPortRanges: []PortRange{{Start: 5004, End: 5004}},
		})
		assert.Equal(t, "((port 5060) or (udp portrange 5004-5004)) or "+frag, result)
	})
}

// TestIPFragmentClauseConstant verifies the fragment clause constant is correct
func TestIPFragmentClauseConstant(t *testing.T) {
	// The clause should match packets with non-zero fragment offset
	// ip[6:2] reads the 16-bit flags/fragment offset field
	// & 0x1fff masks to get the 13-bit fragment offset
	// > 0 matches subsequent fragments (not first fragment)
	assert.Equal(t, "(ip[6:2] & 0x1fff > 0)", IPFragmentClause)
}

// BenchmarkVoIPFilterBuilder_Build benchmarks filter building performance
func BenchmarkVoIPFilterBuilder_Build(b *testing.B) {
	builder := NewVoIPFilterBuilder()
	config := VoIPFilterConfig{
		SIPPorts: []int{5060, 5061, 5080},
		RTPPortRanges: []PortRange{
			{Start: 8000, End: 9000},
			{Start: 16384, End: 32768},
			{Start: 40000, End: 50000},
		},
		UDPOnly:    true,
		BaseFilter: "net 192.168.0.0/24",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = builder.Build(config)
	}
}

func BenchmarkParsePorts(b *testing.B) {
	input := "5060,5061,5080,8080,9090"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ParsePorts(input)
	}
}

func BenchmarkParsePortRanges(b *testing.B) {
	input := "8000-9000,16384-32768,40000-50000"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ParsePortRanges(input)
	}
}
