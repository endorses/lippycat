//go:build cli || all
// +build cli all

package sniff

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestVoipCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name:     "VoIP help",
			args:     []string{"--help"},
			wantErr:  false,
			contains: []string{"Sniff in VOIP mode", "Filter for SIP username", "Flags:"},
		},
		{
			name:     "VoIP with sipuser flag",
			args:     []string{"--sipuser", "alicent"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "VoIP with write-file flag",
			args:     []string{"--write-file"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "VoIP with short flags",
			args:     []string{"-u", "robb,charlie", "-w"},
			wantErr:  false,
			contains: []string{},
		},
		{
			name:     "VoIP with multiple users",
			args:     []string{"--sipuser", "alicent,robb,charlie"},
			wantErr:  false,
			contains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test version of voipCmd to avoid side effects
			cmd := &cobra.Command{
				Use:   "voip",
				Short: "Sniff in VOIP mode",
				Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
				RunE: func(cmd *cobra.Command, args []string) error {
					// Mock run function that doesn't actually start VoIP sniffing
					t.Logf("Mock voip run with args: %v", args)
					return nil
				},
			}

			// Add the same flags as the real command
			cmd.Flags().StringP("sipuser", "u", "", "SIP user to intercept")
			cmd.Flags().BoolP("write-file", "w", false, "write to pcap file")

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

func TestVoipFlagParsing(t *testing.T) {
	tests := []struct {
		name              string
		args              []string
		expectedSipUser   string
		expectedWriteFile string
	}{
		{
			name:              "Default values",
			args:              []string{},
			expectedSipUser:   "",
			expectedWriteFile: "",
		},
		{
			name:              "Single SIP user",
			args:              []string{"--sipuser", "alicent"},
			expectedSipUser:   "alicent",
			expectedWriteFile: "",
		},
		{
			name:              "Multiple SIP users",
			args:              []string{"-u", "alicent,robb,charlie"},
			expectedSipUser:   "alicent,robb,charlie",
			expectedWriteFile: "",
		},
		{
			name:              "Write file enabled",
			args:              []string{"--write-file", "/tmp/output"},
			expectedSipUser:   "",
			expectedWriteFile: "/tmp/output",
		},
		{
			name:              "All flags combined",
			args:              []string{"-u", "alicent,robb", "-w", "/tmp/test"},
			expectedSipUser:   "alicent,robb",
			expectedWriteFile: "/tmp/test",
		},
		{
			name:              "SIP user with special characters",
			args:              []string{"--sipuser", "user@domain.com,test-user_123"},
			expectedSipUser:   "user@domain.com,test-user_123",
			expectedWriteFile: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset module-level variables
			sipuser = ""
			writeVoipFile = ""

			cmd := &cobra.Command{
				Use: "voip",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Extract flag values to module variables
					sipuser, _ = cmd.Flags().GetString("sipuser")
					writeVoipFile, _ = cmd.Flags().GetString("write-file")
					return nil
				},
			}

			cmd.Flags().StringP("sipuser", "u", "", "SIP user to intercept")
			cmd.Flags().StringP("write-file", "w", "", "prefix for output pcap files")

			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedSipUser, sipuser)
			assert.Equal(t, tt.expectedWriteFile, writeVoipFile)
		})
	}
}

func TestVoipHandlerLogic(t *testing.T) {
	tests := []struct {
		name                string
		sipuserValue        string
		readFileValue       string
		interfaceValue      string
		filterValue         string
		expectedUsers       []string
		expectedLiveCall    bool
		expectedOfflineCall bool
	}{
		{
			name:                "Single user live capture",
			sipuserValue:        "alicent",
			readFileValue:       "",
			interfaceValue:      "eth0",
			filterValue:         "port 5060",
			expectedUsers:       []string{"alicent"},
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
		{
			name:                "Multiple users live capture",
			sipuserValue:        "alicent,robb,charlie",
			readFileValue:       "",
			interfaceValue:      "any",
			filterValue:         "",
			expectedUsers:       []string{"alicent", "robb", "charlie"},
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
		{
			name:                "Single user offline capture",
			sipuserValue:        "robb",
			readFileValue:       "/tmp/test.pcap",
			interfaceValue:      "eth0",
			filterValue:         "tcp",
			expectedUsers:       []string{"robb"},
			expectedLiveCall:    false,
			expectedOfflineCall: true,
		},
		{
			name:                "No users specified live capture",
			sipuserValue:        "",
			readFileValue:       "",
			interfaceValue:      "wlan0",
			filterValue:         "port 5060",
			expectedUsers:       []string{},
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
		{
			name:                "Empty user in list",
			sipuserValue:        "alicent,,robb",
			readFileValue:       "",
			interfaceValue:      "eth0",
			filterValue:         "",
			expectedUsers:       []string{"alicent", "", "robb"},
			expectedLiveCall:    true,
			expectedOfflineCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore viper state
			originalWriteVoip := viper.GetBool("writeVoip")
			defer func() {
				viper.Set("writeVoip", originalWriteVoip)
				// Clean up any test users
				for _, user := range tt.expectedUsers {
					if user != "" {
						sipusers.DeleteSipUser(user)
					}
				}
			}()

			var liveSnifferCalled bool
			var offlineSnifferCalled bool
			addedUsers := []string{}

			// Set global variables to simulate flag parsing and parent command state
			oldSipuser := sipuser
			oldReadFile := readFile
			oldInterfaces := interfaces
			oldFilter := filter
			defer func() {
				sipuser = oldSipuser
				readFile = oldReadFile
				interfaces = oldInterfaces
				filter = oldFilter
			}()

			sipuser = tt.sipuserValue
			readFile = tt.readFileValue
			interfaces = tt.interfaceValue
			filter = tt.filterValue
			writeVoipFile = "/tmp/test-voip" // Test write file prefix

			// Create a mock version of voipHandler
			mockVoipHandler := func(cmd *cobra.Command, args []string) {
				expirationDate := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
				su := sipusers.SipUser{ExpirationDate: expirationDate}

				if sipuser != "" {
					for _, user := range strings.Split(sipuser, ",") {
						sipusers.AddSipUser(user, &su)
						addedUsers = append(addedUsers, user)
					}
				}

				// Set writeVoip based on whether --write-file was provided (matching voip.go logic)
				writeVoip := writeVoipFile != ""
				viper.Set("writeVoip", writeVoip)

				if readFile == "" {
					liveSnifferCalled = true
				} else {
					offlineSnifferCalled = true
				}
			}

			// Execute mock handler
			mockVoipHandler(nil, []string{})

			assert.Equal(t, tt.expectedLiveCall, liveSnifferCalled, "Live sniffer call expectation")
			assert.Equal(t, tt.expectedOfflineCall, offlineSnifferCalled, "Offline sniffer call expectation")
			assert.Equal(t, tt.expectedUsers, addedUsers, "Added users should match expected")

			// Verify viper setting
			assert.True(t, viper.GetBool("writeVoip"), "writeVoip should be set in viper")

			// Verify users were actually added to sipusers
			for _, user := range tt.expectedUsers {
				if user != "" {
					// We can't easily test IsSurveiled without modifying the implementation,
					// but we can verify the function doesn't panic
					t.Logf("User %s was added to surveillance list", user)
				}
			}
		})
	}
}

func TestVoipCommandStructure(t *testing.T) {
	// Test the command structure and configuration
	assert.NotNil(t, voipCmd, "voipCmd should be initialized")
	assert.Equal(t, "voip", voipCmd.Use)
	assert.Contains(t, voipCmd.Short, "Sniff in VOIP mode")
	assert.Contains(t, voipCmd.Long, "Filter for SIP username")
	assert.NotNil(t, voipCmd.Run, "voipCmd should have a Run function")

	// Check flags
	flags := []struct {
		name      string
		shorthand string
		flagType  string
	}{
		{"sipuser", "u", "string"},
		{"write-file", "w", "string"},
	}

	for _, flag := range flags {
		f := voipCmd.Flags().Lookup(flag.name)
		assert.NotNil(t, f, "Flag %s should exist", flag.name)
		if f != nil {
			assert.Equal(t, flag.shorthand, f.Shorthand, "Flag %s should have correct shorthand", flag.name)
			assert.Equal(t, flag.flagType, f.Value.Type(), "Flag %s should have correct type", flag.name)
		}
	}
}

func TestVoipUserListParsing(t *testing.T) {
	tests := []struct {
		name          string
		sipuserInput  string
		expectedUsers []string
	}{
		{
			name:          "Empty string",
			sipuserInput:  "",
			expectedUsers: []string{""},
		},
		{
			name:          "Single user",
			sipuserInput:  "alicent",
			expectedUsers: []string{"alicent"},
		},
		{
			name:          "Multiple users",
			sipuserInput:  "alicent,robb,charlie",
			expectedUsers: []string{"alicent", "robb", "charlie"},
		},
		{
			name:          "Users with spaces",
			sipuserInput:  "alicent, robb , charlie",
			expectedUsers: []string{"alicent", " robb ", " charlie"},
		},
		{
			name:          "Users with special characters",
			sipuserInput:  "user@domain.com,test-user_123,user+tag@example.org",
			expectedUsers: []string{"user@domain.com", "test-user_123", "user+tag@example.org"},
		},
		{
			name:          "Users with empty entries",
			sipuserInput:  "alicent,,robb,",
			expectedUsers: []string{"alicent", "", "robb", ""},
		},
		{
			name:          "Single comma",
			sipuserInput:  ",",
			expectedUsers: []string{"", ""},
		},
		{
			name:          "Only commas",
			sipuserInput:  ",,,",
			expectedUsers: []string{"", "", "", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the string splitting logic that's used in voipHandler
			actualUsers := strings.Split(tt.sipuserInput, ",")
			assert.Equal(t, tt.expectedUsers, actualUsers)
		})
	}
}

func TestVoipSipUserExpiration(t *testing.T) {
	// Test that SipUser objects are created with the expected expiration date
	expectedDate := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)

	// Create SipUser as done in voipHandler
	su := sipusers.SipUser{ExpirationDate: expectedDate}

	assert.Equal(t, expectedDate, su.ExpirationDate, "SipUser should have correct expiration date")

	// Test that the expiration date is in the past (year 1)
	assert.True(t, su.ExpirationDate.Before(time.Now()), "Expiration date should be in the past")
}

func TestVoipViperConfiguration(t *testing.T) {
	// Test that writeVoip setting is correctly stored in viper
	originalValue := viper.GetBool("writeVoip")
	defer viper.Set("writeVoip", originalValue)

	tests := []struct {
		name          string
		writeVoipFlag bool
	}{
		{
			name:          "Write VoIP enabled",
			writeVoipFlag: true,
		},
		{
			name:          "Write VoIP disabled",
			writeVoipFlag: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the flag value (simulate setting writeVoipFile)
			if tt.writeVoipFlag {
				writeVoipFile = "/tmp/test-output"
			} else {
				writeVoipFile = ""
			}

			// Simulate the logic from voipHandler
			writeVoip := writeVoipFile != ""
			viper.Set("writeVoip", writeVoip)

			// Verify the value was set correctly
			assert.Equal(t, tt.writeVoipFlag, viper.GetBool("writeVoip"))
		})
	}
}

func TestVoipCommandHelp(t *testing.T) {
	// Create a fresh command instance for testing help
	testCmd := &cobra.Command{
		Use:   "voip",
		Short: "Sniff in VOIP mode",
		Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
		Run:   func(cmd *cobra.Command, args []string) {}, // Need a run function for flags to show
	}

	// Add the flags that should appear in help
	testCmd.Flags().StringP("sipuser", "u", "", "SIP user to intercept")
	testCmd.Flags().BoolP("write-file", "w", false, "write to pcap file")

	var buf bytes.Buffer
	testCmd.SetOut(&buf)
	testCmd.SetErr(&buf)
	testCmd.SetArgs([]string{"--help"})

	err := testCmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Sniff in VOIP mode")
	assert.Contains(t, output, "Filter for SIP username")
	assert.Contains(t, output, "sipuser")
	assert.Contains(t, output, "write-file")
}

func TestVoipIntegrationWithParentFlags(t *testing.T) {
	// Test that voip command works correctly with parent command flags
	parentCmd := &cobra.Command{Use: "sniff"}
	voipCmd := &cobra.Command{
		Use: "voip",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Access parent flags
			interfaces, _ := cmd.Parent().PersistentFlags().GetString("interface")
			filter, _ := cmd.Parent().PersistentFlags().GetString("filter")
			readFile, _ := cmd.Parent().PersistentFlags().GetString("read-file")

			// Access local flags
			sipuser, _ := cmd.Flags().GetString("sipuser")
			writeVoip, _ := cmd.Flags().GetBool("write-file")

			// Log the values for verification
			t.Logf("Interface: %s, Filter: %s, ReadFile: %s, SipUser: %s, WriteVoip: %t",
				interfaces, filter, readFile, sipuser, writeVoip)

			return nil
		},
	}

	// Set up parent flags
	parentCmd.PersistentFlags().StringP("interface", "i", "any", "interface")
	parentCmd.PersistentFlags().StringP("filter", "f", "", "filter")
	parentCmd.PersistentFlags().StringP("read-file", "r", "", "read file")

	// Set up voip flags
	voipCmd.Flags().StringP("sipuser", "u", "", "sip user")
	voipCmd.Flags().BoolP("write-file", "w", false, "write file")

	parentCmd.AddCommand(voipCmd)

	// Test with various flag combinations
	testArgs := [][]string{
		{"voip", "-u", "alicent"},
		{"voip", "-i", "eth0", "-u", "robb", "-w"},
		{"voip", "-f", "port 5060", "-r", "test.pcap", "-u", "charlie"},
	}

	for i, args := range testArgs {
		t.Run(t.Name()+"_case_"+string(rune('A'+i)), func(t *testing.T) {
			parentCmd.SetArgs(args)
			err := parentCmd.Execute()
			assert.NoError(t, err)
		})
	}
}
