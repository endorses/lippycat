//go:build tui && !all
// +build tui,!all

package cmd

import (
	"fmt"
	"os"

	"github.com/endorses/lippycat/cmd/tui"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:     "lippycat",
	Short:   "lippycat sniffs for you",
	Long:    fmt.Sprintf("lippycat %s - Network traffic sniffer and analyzer (TUI build)\n\n%s", version.GetVersion(), "http://🫦🐱.ws"),
	Version: version.GetFullVersion(),
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubCommandPalattes() {
	rootCmd.AddCommand(tui.TuiCmd)
	// interfacesCmd is registered directly in root.AddCommand() in its init() function
}

func init() {
	cobra.OnInitialize(initConfig)

	// Initialize structured logging
	logger.Initialize()

	addSubCommandPalattes()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.lippycat.yaml)")

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Priority order for config files:
		// 1. ~/.config/lippycat/config.yaml (preferred, with directory for other files)
		// 2. ~/.config/lippycat.yaml (XDG standard)
		// 3. ~/.lippycat.yaml (legacy)
		viper.AddConfigPath(home + "/.config/lippycat")
		viper.AddConfigPath(home + "/.config")
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")

		// Try "config" name first (in ~/.config/lippycat/config.yaml)
		viper.SetConfigName("config")
		if err := viper.ReadInConfig(); err != nil {
			// Fall back to "lippycat" name
			viper.SetConfigName("lippycat")
		}
	}

	viper.AutomaticEnv()

	// Set defaults for capture configuration
	viper.SetDefault("pcap_timeout_ms", 200) // 200ms default for pcap read timeout

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
