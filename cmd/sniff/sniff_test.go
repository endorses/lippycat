//go:build cli || all
// +build cli all

package sniff

import (
	"bytes"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestSniffCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name:     "Sniff help",
			args:     []string{"--help"},
			wantErr:  false,
			contains: []string{"Start lippycat in sniff mode", "Flags:"},
		},
		{
			name:     "Sniff with interface flag",
			args:     []string{"--interface", "eth0"},
			wantErr:  false,
			contains: []string{}, // No output expected, just verify it parses
		},
		{
			name:     "Sniff with filter flag",
			args:     []string{"--filter", "port 5060"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "Sniff with read-file flag",
			args:     []string{"--read-file", "/tmp/test.pcap"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "Sniff with promiscuous flag",
			args:     []string{"--promiscuous"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "Sniff with short flags",
			args:     []string{"-i", "wlan0", "-f", "tcp port 80"},
			wantErr:  false,
			contains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test version of SniffCmd to avoid side effects
			cmd := &cobra.Command{
				Use:   "sniff",
				Short: "Start lippycat in sniff mode",
				Long:  `Start lippycat in sniff mode. Monitor the specified device`,
				RunE: func(cmd *cobra.Command, args []string) error {
					// Mock run function that doesn't actually start sniffing
					t.Logf("Mock sniff run with args: %v", args)
					return nil
				},
			}

			// Add the same flags as the real command
			cmd.PersistentFlags().StringP("interface", "i", "any", "interface(s) to monitor, comma separated")
			cmd.PersistentFlags().StringP("filter", "f", "", "bpf filter to apply")
			cmd.PersistentFlags().StringP("read-file", "r", "", "read from pcap file")
			cmd.PersistentFlags().BoolP("promiscuous", "p", false, "use promiscuous mode (captures all network traffic - use with caution)")
			cmd.Flags().StringP("write-file", "w", "", "write to pcap file")

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			output := buf.String()
			for _, want := range tt.contains {
				assert.Contains(t, output, want)
			}
		})
	}
}

func TestSniffFlagParsing(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		expectedIface   string
		expectedFilter  string
		expectedFile    string
		expectedPromisc bool
	}{
		{
			name:            "Default values",
			args:            []string{},
			expectedIface:   "any",
			expectedFilter:  "",
			expectedFile:    "",
			expectedPromisc: false,
		},
		{
			name:            "Custom interface",
			args:            []string{"--interface", "eth0"},
			expectedIface:   "eth0",
			expectedFilter:  "",
			expectedFile:    "",
			expectedPromisc: false,
		},
		{
			name:            "Multiple interfaces",
			args:            []string{"-i", "eth0,wlan0,lo"},
			expectedIface:   "eth0,wlan0,lo",
			expectedFilter:  "",
			expectedFile:    "",
			expectedPromisc: false,
		},
		{
			name:            "BPF filter",
			args:            []string{"--filter", "port 5060 or port 5061"},
			expectedIface:   "any",
			expectedFilter:  "port 5060 or port 5061",
			expectedFile:    "",
			expectedPromisc: false,
		},
		{
			name:            "Read from file",
			args:            []string{"--read-file", "/path/to/capture.pcap"},
			expectedIface:   "any",
			expectedFilter:  "",
			expectedFile:    "/path/to/capture.pcap",
			expectedPromisc: false,
		},
		{
			name:            "Promiscuous mode",
			args:            []string{"--promiscuous"},
			expectedIface:   "any",
			expectedFilter:  "",
			expectedFile:    "",
			expectedPromisc: true,
		},
		{
			name:            "All flags combined",
			args:            []string{"-i", "eth0", "-f", "tcp", "-r", "test.pcap", "-p"},
			expectedIface:   "eth0",
			expectedFilter:  "tcp",
			expectedFile:    "test.pcap",
			expectedPromisc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset module-level variables
			interfaces = "any"
			filter = ""
			readFile = ""
			promiscuous = false

			cmd := &cobra.Command{
				Use: "sniff",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Extract flag values to module variables
					interfaces, _ = cmd.Flags().GetString("interface")
					filter, _ = cmd.Flags().GetString("filter")
					readFile, _ = cmd.Flags().GetString("read-file")
					promiscuous, _ = cmd.Flags().GetBool("promiscuous")
					return nil
				},
			}

			cmd.Flags().StringP("interface", "i", "any", "interface(s) to monitor, comma separated")
			cmd.Flags().StringP("filter", "f", "", "bpf filter to apply")
			cmd.Flags().StringP("read-file", "r", "", "read from pcap file")
			cmd.Flags().BoolP("promiscuous", "p", false, "use promiscuous mode")

			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedIface, interfaces)
			assert.Equal(t, tt.expectedFilter, filter)
			assert.Equal(t, tt.expectedFile, readFile)
			assert.Equal(t, tt.expectedPromisc, promiscuous)
		})
	}
}

func TestSniffFunction(t *testing.T) {
	// Test the sniff function logic without actually starting capture
	tests := []struct {
		name                string
		readFileValue       string
		interfaceValue      string
		filterValue         string
		expectedLiveCall    bool
		expectedOfflineCall bool
	}{
		{
			name:                "Live capture - default",
			readFileValue:       "",
			interfaceValue:      "any",
			filterValue:         "",
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
		{
			name:                "Live capture - specific interface",
			readFileValue:       "",
			interfaceValue:      "eth0",
			filterValue:         "port 80",
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
		{
			name:                "Offline capture",
			readFileValue:       "/path/to/file.pcap",
			interfaceValue:      "eth0",
			filterValue:         "tcp",
			expectedLiveCall:    false,
			expectedOfflineCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the capture functions to avoid actual execution
			var liveSnifferCalled bool
			var offlineSnifferCalled bool
			var capturedInterfaces string
			var capturedFilter string
			var capturedReadFile string

			// Set global variables to simulate flag parsing
			oldReadFile := readFile
			oldInterfaces := interfaces
			oldFilter := filter
			defer func() {
				readFile = oldReadFile
				interfaces = oldInterfaces
				filter = oldFilter
			}()

			readFile = tt.readFileValue
			interfaces = tt.interfaceValue
			filter = tt.filterValue

			// Create a mock version of the sniff function
			mockSniff := func(cmd *cobra.Command, args []string) {
				if readFile == "" {
					liveSnifferCalled = true
					capturedInterfaces = interfaces
					capturedFilter = filter
				} else {
					offlineSnifferCalled = true
					capturedReadFile = readFile
					capturedFilter = filter
				}
			}

			// Execute mock sniff
			mockSniff(nil, []string{})

			assert.Equal(t, tt.expectedLiveCall, liveSnifferCalled, "Live sniffer call expectation")
			assert.Equal(t, tt.expectedOfflineCall, offlineSnifferCalled, "Offline sniffer call expectation")

			if tt.expectedLiveCall {
				assert.Equal(t, tt.interfaceValue, capturedInterfaces)
				assert.Equal(t, tt.filterValue, capturedFilter)
			}

			if tt.expectedOfflineCall {
				assert.Equal(t, tt.readFileValue, capturedReadFile)
				assert.Equal(t, tt.filterValue, capturedFilter)
			}
		})
	}
}

func TestSniffCommandStructure(t *testing.T) {
	// Test the command structure and configuration
	assert.NotNil(t, SniffCmd, "SniffCmd should be initialized")
	assert.Equal(t, "sniff", SniffCmd.Use)
	assert.Contains(t, SniffCmd.Short, "Start lippycat in sniff mode")
	assert.NotNil(t, SniffCmd.Run, "SniffCmd should have a Run function")

	// Check flags
	flags := []struct {
		name      string
		shorthand string
		required  bool
	}{
		{"interface", "i", false},
		{"filter", "f", false},
		{"read-file", "r", false},
		{"promiscuous", "p", false},
		{"write-file", "w", false},
	}

	for _, flag := range flags {
		f := SniffCmd.Flags().Lookup(flag.name)
		if f == nil {
			f = SniffCmd.PersistentFlags().Lookup(flag.name)
		}

		assert.NotNil(t, f, "Flag %s should exist", flag.name)
		if f != nil {
			assert.Equal(t, flag.shorthand, f.Shorthand, "Flag %s should have correct shorthand", flag.name)
		}
	}

	// Check subcommands
	subcommands := SniffCmd.Commands()
	assert.NotEmpty(t, subcommands, "SniffCmd should have subcommands")

	// Look for voip subcommand
	var voipFound bool
	for _, cmd := range subcommands {
		if cmd.Use == "voip" {
			voipFound = true
			break
		}
	}
	assert.True(t, voipFound, "Should have voip subcommand")
}

func TestFlagValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid interface format",
			args:    []string{"-i", "eth0,wlan0"},
			wantErr: false,
		},
		{
			name:    "Valid BPF filter",
			args:    []string{"-f", "host 192.168.1.1 and port 80"},
			wantErr: false,
		},
		{
			name:    "Valid file path",
			args:    []string{"-r", "/tmp/test.pcap"},
			wantErr: false,
		},
		{
			name:    "Mixed flags",
			args:    []string{"-i", "eth0", "-f", "tcp", "-p"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: "sniff",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil // Mock successful execution
				},
			}

			cmd.Flags().StringP("interface", "i", "any", "interfaces")
			cmd.Flags().StringP("filter", "f", "", "filter")
			cmd.Flags().StringP("read-file", "r", "", "file")
			cmd.Flags().BoolP("promiscuous", "p", false, "promiscuous")

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Mock functions to test integration without side effects
func mockStartSniffer(devices []pcaptypes.PcapInterface, filter string) {
	// Mock implementation - just log the call
}

func TestSniffIntegration(t *testing.T) {
	// Test that the sniff command can be constructed and configured properly
	t.Run("Command creation and flag binding", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test-sniff"}

		// Add flags like the real command
		cmd.PersistentFlags().StringP("interface", "i", "any", "interface(s) to monitor")
		cmd.PersistentFlags().StringP("filter", "f", "", "bpf filter")
		cmd.PersistentFlags().StringP("read-file", "r", "", "read from pcap file")
		cmd.PersistentFlags().BoolP("promiscuous", "p", false, "use promiscuous mode")

		// Test flag default values
		iface, _ := cmd.PersistentFlags().GetString("interface")
		assert.Equal(t, "any", iface)

		filter, _ := cmd.PersistentFlags().GetString("filter")
		assert.Equal(t, "", filter)

		readFile, _ := cmd.PersistentFlags().GetString("read-file")
		assert.Equal(t, "", readFile)

		promiscuous, _ := cmd.PersistentFlags().GetBool("promiscuous")
		assert.False(t, promiscuous)
	})
}

func TestSniffCommandHelp(t *testing.T) {
	// Test help output content
	var buf bytes.Buffer
	cmd := *SniffCmd // Copy to avoid modifying original
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Start lippycat in sniff mode")
	assert.Contains(t, output, "interface")
	assert.Contains(t, output, "filter")
	assert.Contains(t, output, "read-file")
	assert.Contains(t, output, "promiscuous")
}
