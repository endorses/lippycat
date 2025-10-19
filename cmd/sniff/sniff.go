//go:build cli || all
// +build cli all

package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var SniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start lippycat in sniff mode",
	Long:  `Start lippycat in sniff mode. Monitor the specified device`,
	Run:   sniff,
}

var (
	interfaces  string
	filter      string
	readFile    string
	writeFile   string
	promiscuous bool
	quiet       bool
	format      string
)

func sniff(cmd *cobra.Command, args []string) {
	// Set quiet mode in viper so it's accessible globally
	viper.Set("sniff.quiet", quiet)
	viper.Set("sniff.format", format)

	if readFile == "" {
		capture.StartLiveSniffer(interfaces, filter, capture.StartSniffer)
	} else {
		capture.StartOfflineSniffer(readFile, filter, capture.StartSniffer)
	}
}

func init() {
	SniffCmd.AddCommand(voipCmd)
	SniffCmd.PersistentFlags().StringVarP(&interfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	SniffCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
	SniffCmd.PersistentFlags().StringVarP(&readFile, "read-file", "r", "", "read from pcap file")
	SniffCmd.PersistentFlags().BoolVarP(&promiscuous, "promiscuous", "p", false, "use promiscuous mode (captures all network traffic - use with caution)")
	SniffCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet mode - don't print packets (better performance)")
	SniffCmd.PersistentFlags().StringVar(&format, "format", "json", "output format: json, text")
	SniffCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "write to pcap file")

	_ = viper.BindPFlag("promiscuous", SniffCmd.PersistentFlags().Lookup("promiscuous"))
	_ = viper.BindPFlag("sniff.quiet", SniffCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("sniff.format", SniffCmd.PersistentFlags().Lookup("format"))
}
