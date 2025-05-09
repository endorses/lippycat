package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/spf13/cobra"
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
)

func sniff(cmd *cobra.Command, args []string) {
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
	SniffCmd.PersistentFlags().BoolVarP(&promiscuous, "promiscuous", "p", true, "use promiscuous mode")
	SniffCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "write to pcap file")
}
