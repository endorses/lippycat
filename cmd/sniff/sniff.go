package sniff

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/spf13/cobra"
)

var SniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Start lippycat in sniff mode",
	Long:  `Start lippycat in sniff mode. Monitor the specified device`,
	Run:   sniff,
}

var (
	interfaces string
	filter     string
	readFile   string
)

func sniff(cmd *cobra.Command, args []string) {
	var ifaces []pcaptypes.PcapInterface
	for _, device := range strings.Split(interfaces, ",") {
		iface := pcaptypes.CreateLiveInterface(device)
		ifaces = append(ifaces, iface)
	}
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
	// sniffCmd.Flags().BoolVarP("promiscuous", "p", false, "use promiscuous mode")
}
