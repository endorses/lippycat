//go:build tui || all

package tui

import (
	"os"
	"path/filepath"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/spf13/viper"
)

// saveThemePreference saves the current theme preference to config file
func saveThemePreference(theme themes.Theme) {
	var themeName string
	if theme.Name == "Solarized Light" {
		themeName = "light"
	} else {
		themeName = "dark"
	}

	// Set in viper
	viper.Set("tui.theme", themeName)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it in ~/.config/lippycat/config.yaml
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - theme will still work for this session
				return
			}
		}
	}
}

// loadFilterHistory loads filter history from config
func loadFilterHistory(filterInput *components.FilterInput) {
	history := viper.GetStringSlice("tui.filter_history")
	if len(history) > 0 {
		filterInput.SetHistory(history)
	}
}

// saveFilterHistory saves filter history to config
func saveFilterHistory(filterInput *components.FilterInput) {
	history := filterInput.GetHistory()
	viper.Set("tui.filter_history", history)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - history will still work for this session
				return
			}
		}
	}
}

// loadCallFilterHistory loads call filter history from config
func loadCallFilterHistory(filterInput *components.FilterInput) {
	history := viper.GetStringSlice("tui.call_filter_history")
	if len(history) > 0 {
		filterInput.SetHistory(history)
	}
}

// saveCallFilterHistory saves call filter history to config
func saveCallFilterHistory(filterInput *components.FilterInput) {
	history := filterInput.GetHistory()
	viper.Set("tui.call_filter_history", history)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - history will still work for this session
				return
			}
		}
	}
}

// loadNodeHistory loads node address history from config
func loadNodeHistory(nodesView *components.NodesView) {
	history := viper.GetStringSlice("tui.node_history")
	if len(history) > 0 {
		nodesView.SetNodeHistory(history)
	}
}

// saveNodeHistory saves node address history to config
func saveNodeHistory(nodesView *components.NodesView) {
	history := nodesView.GetNodeHistory()
	viper.Set("tui.node_history", history)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - history will still work for this session
				return
			}
		}
	}
}
