package cmd

import (
	"fmt"
	"os"

	"github.com/endorses/lippycat/cmd/sniff"
	"github.com/endorses/lippycat/cmd/tui"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "lippycat",
	Short: "lippycat sniffs for you",
	Long:  `lippycat sniffs traffic for you, including voip traffic.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubCommandPalattes() {
	rootCmd.AddCommand(sniff.SniffCmd)
	rootCmd.AddCommand(tui.TuiCmd)
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

		// Check ~/.config/lippycat.yaml first (XDG standard)
		viper.AddConfigPath(home + "/.config")
		// Fall back to ~/.lippycat.yaml (legacy)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName("lippycat")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
