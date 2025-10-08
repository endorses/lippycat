//go:build all
// +build all

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name:     "No arguments shows help",
			args:     []string{},
			wantErr:  false,
			contains: []string{"lippycat sniffs traffic for you"},
		},
		{
			name:     "Help flag",
			args:     []string{"--help"},
			wantErr:  false,
			contains: []string{"lippycat sniffs traffic for you"},
		},
		{
			name:     "Short help flag",
			args:     []string{"-h"},
			wantErr:  false,
			contains: []string{"lippycat sniffs traffic for you"},
		},
		{
			name:     "Version-like command (non-existent)",
			args:     []string{"version"},
			wantErr:  false, // No subcommands = no error
			contains: []string{"lippycat sniffs traffic for you"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh root command for each test
			cmd := &cobra.Command{
				Use:   "lippycat",
				Short: "lippycat sniffs for you",
				Long:  `lippycat sniffs traffic for you, including voip traffic.`,
			}

			// Add the same configuration as the real root command
			cmd.PersistentFlags().String("config", "", "config file (default is $HOME/.lippycat.yaml)")
			cmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

			// Capture output
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
				assert.Contains(t, output, want, "Output should contain expected text")
			}
		})
	}
}

func TestInitConfig(t *testing.T) {
	// Save original viper state
	originalConfig := viper.GetString("test")
	defer func() {
		viper.Reset()
		if originalConfig != "" {
			viper.Set("test", originalConfig)
		}
	}()

	tests := []struct {
		name           string
		setupConfig    func(*testing.T) (string, func())
		expectedConfig bool
	}{
		{
			name: "Custom config file",
			setupConfig: func(t *testing.T) (string, func()) {
				tmpDir := t.TempDir()
				configFile := filepath.Join(tmpDir, "test-config.yaml")

				configContent := `test_setting: custom_value`
				err := os.WriteFile(configFile, []byte(configContent), 0644)
				require.NoError(t, err)

				return configFile, func() { os.Remove(configFile) }
			},
			expectedConfig: true,
		},
		{
			name: "Default config location (not found)",
			setupConfig: func(t *testing.T) (string, func()) {
				// Return empty string to trigger default config behavior
				return "", func() {}
			},
			expectedConfig: false,
		},
		{
			name: "Non-existent custom config",
			setupConfig: func(t *testing.T) (string, func()) {
				return "/path/that/does/not/exist/config.yaml", func() {}
			},
			expectedConfig: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()

			configFile, cleanup := tt.setupConfig(t)
			defer cleanup()

			// Simulate the initConfig function behavior
			if configFile != "" {
				viper.SetConfigFile(configFile)
			} else {
				// Simulate default behavior
				home, err := os.UserHomeDir()
				if err == nil {
					viper.AddConfigPath(home)
					viper.SetConfigType("yaml")
					viper.SetConfigName(".lippycat")
				}
			}

			viper.AutomaticEnv()

			// Try to read config - this may or may not succeed
			err := viper.ReadInConfig()

			if tt.expectedConfig {
				assert.NoError(t, err, "Should successfully read config file")
				assert.NotEmpty(t, viper.ConfigFileUsed(), "Should have a config file path")
			} else {
				// For non-existent configs, we don't assert error since it's handled gracefully
				t.Logf("Config read result: %v", err)
			}
		})
	}
}

func TestCommandStructure(t *testing.T) {
	// Test the overall command structure
	assert.NotNil(t, rootCmd, "Root command should be initialized")
	assert.Equal(t, "lippycat", rootCmd.Use, "Root command should have correct Use")
	assert.Contains(t, rootCmd.Short, "lippycat sniffs for you", "Root command should have correct Short description")

	// Check that subcommands are added
	commands := rootCmd.Commands()
	assert.NotEmpty(t, commands, "Root command should have subcommands")

	// Look for sniff command
	var sniffCmd *cobra.Command
	for _, cmd := range commands {
		if cmd.Use == "sniff" {
			sniffCmd = cmd
			break
		}
	}
	assert.NotNil(t, sniffCmd, "Should have sniff subcommand")
}

func TestFlagConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		flagType string
		required bool
	}{
		{
			name:     "Config flag",
			flagName: "config",
			flagType: "string",
			required: false,
		},
		{
			name:     "Toggle flag",
			flagName: "toggle",
			flagType: "bool",
			required: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				flag = rootCmd.PersistentFlags().Lookup(tt.flagName)
			}

			require.NotNil(t, flag, "Flag should exist")
			assert.Equal(t, tt.flagName, flag.Name, "Flag name should match")

			// Check flag type based on Value type
			switch tt.flagType {
			case "string":
				assert.Equal(t, "string", flag.Value.Type(), "Flag should be string type")
			case "bool":
				assert.Equal(t, "bool", flag.Value.Type(), "Flag should be bool type")
			}
		})
	}
}

func TestEnvironmentVariableHandling(t *testing.T) {
	// Save original environment
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	tests := []struct {
		name   string
		envVar string
		envVal string
	}{
		{
			name:   "Set environment variable",
			envVar: "LIPPYCAT_TEST",
			envVal: "test_value",
		},
		{
			name:   "Set config path via env",
			envVar: "LIPPYCAT_CONFIG",
			envVal: "/tmp/test-config.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			// Set environment variable
			err := os.Setenv(tt.envVar, tt.envVal)
			require.NoError(t, err)

			// Enable automatic env
			viper.AutomaticEnv()

			// The environment variable should be accessible
			// Note: Viper converts env var names, so we need to use the right key
			envKey := strings.ToLower(strings.TrimPrefix(tt.envVar, "LIPPYCAT_"))
			if envKey == "lippycat_test" {
				envKey = "test" // Viper strips the prefix
			}

			value := viper.GetString(envKey)
			if envKey == "config" {
				// Config might be handled specially
				t.Logf("Config environment handling: %s", value)
			}
		})
	}
}

func TestCommandExecution_DryRun(t *testing.T) {
	// Test command execution without actually running the commands
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "Help command",
			args:    []string{"--help"},
			wantErr: false,
		},
		{
			name:    "Invalid command",
			args:    []string{"invalid-command"},
			wantErr: true,
		},
		{
			name:    "No arguments",
			args:    []string{},
			wantErr: false, // Should show help
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the actual root command
			cmd := rootCmd

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
		})
	}
}

func TestConfigFileFormats(t *testing.T) {
	tests := []struct {
		name        string
		configName  string
		configType  string
		content     string
		expectValid bool
	}{
		{
			name:        "YAML config",
			configName:  ".lippycat.yaml",
			configType:  "yaml",
			content:     "test_key: test_value\ninterface: eth0\n",
			expectValid: true,
		},
		{
			name:        "JSON config (if supported)",
			configName:  ".lippycat.json",
			configType:  "json",
			content:     `{"test_key": "test_value", "interface": "eth0"}`,
			expectValid: true,
		},
		{
			name:        "Invalid YAML",
			configName:  ".lippycat.yaml",
			configType:  "yaml",
			content:     "invalid: yaml: content: [unclosed",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, tt.configName)

			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			viper.SetConfigFile(configFile)
			err = viper.ReadInConfig()

			if tt.expectValid {
				assert.NoError(t, err, "Should read valid config without error")
				if err == nil {
					t.Logf("Successfully read config from: %s", viper.ConfigFileUsed())
				}
			} else {
				assert.Error(t, err, "Should fail to read invalid config")
			}
		})
	}
}

func TestConfigPrecedence(t *testing.T) {
	// Test that explicit config file takes precedence over default locations
	tmpDir := t.TempDir()

	// Create explicit config
	explicitConfig := filepath.Join(tmpDir, "explicit-config.yaml")
	explicitContent := "test_setting: explicit_value\n"
	err := os.WriteFile(explicitConfig, []byte(explicitContent), 0644)
	require.NoError(t, err)

	// Create default config in home directory
	homeDir := tmpDir // Use tmpDir as fake home
	defaultConfig := filepath.Join(homeDir, ".lippycat.yaml")
	defaultContent := "test_setting: default_value\n"
	err = os.WriteFile(defaultConfig, []byte(defaultContent), 0644)
	require.NoError(t, err)

	viper.Reset()

	// Test explicit config takes precedence
	viper.SetConfigFile(explicitConfig)
	err = viper.ReadInConfig()
	assert.NoError(t, err)

	value := viper.GetString("test_setting")
	assert.Equal(t, "explicit_value", value, "Explicit config should take precedence")
}

func TestAddSubCommandPalettes(t *testing.T) {
	// We can't directly test addSubCommandPalattes since it operates on global rootCmd
	// But we can verify the structure is correct
	commands := rootCmd.Commands()
	assert.NotEmpty(t, commands, "Root command should have subcommands after initialization")

	// Should have at least one command (sniff)
	commandNames := make([]string, len(commands))
	for i, cmd := range commands {
		commandNames[i] = cmd.Use
	}
	t.Logf("Available commands: %v", commandNames)

	assert.Contains(t, commandNames, "sniff", "Should contain sniff command")
}

func TestMainExecutionPath(t *testing.T) {
	// Test that Execute() function exists and has basic structure
	// We can't actually call Execute() in tests as it would cause os.Exit
	assert.NotNil(t, rootCmd, "Root command should be initialized for Execute()")

	// Verify that rootCmd has the right structure for execution
	assert.NotEmpty(t, rootCmd.Use, "Root command should have Use defined")
	assert.NotEmpty(t, rootCmd.Short, "Root command should have Short description")

	// Verify subcommands are properly attached
	commands := rootCmd.Commands()
	assert.NotEmpty(t, commands, "Root command should have subcommands for proper CLI functionality")
}
