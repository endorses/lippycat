//go:build cli || all

package sniff

import (
	"time"

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

	// Virtual interface flags
	virtualInterface     bool
	virtualInterfaceName string
	vifStartupDelay      time.Duration
	vifReplayTiming      bool
	vifType              string
	vifBufferSize        int
	vifNetNS             string
	vifDropPrivileges    string
)

func sniff(cmd *cobra.Command, args []string) {
	// Set quiet mode in viper so it's accessible globally
	viper.Set("sniff.quiet", quiet)
	viper.Set("sniff.format", format)
	viper.Set("sniff.write_file", writeFile)

	// Set virtual interface configuration values
	if cmd.Flags().Changed("virtual-interface") {
		viper.Set("sniff.virtual_interface", virtualInterface)
	}
	if cmd.Flags().Changed("vif-name") {
		viper.Set("sniff.vif_name", virtualInterfaceName)
	}
	if cmd.Flags().Changed("vif-startup-delay") {
		viper.Set("sniff.vif_startup_delay", vifStartupDelay)
	}
	if cmd.Flags().Changed("vif-replay-timing") {
		viper.Set("sniff.vif_replay_timing", vifReplayTiming)
	}
	if cmd.Flags().Changed("vif-type") {
		viper.Set("sniff.vif_type", vifType)
	}
	if cmd.Flags().Changed("vif-buffer-size") {
		viper.Set("sniff.vif_buffer_size", vifBufferSize)
	}
	if cmd.Flags().Changed("vif-netns") {
		viper.Set("sniff.vif_netns", vifNetNS)
	}
	if cmd.Flags().Changed("vif-drop-privileges") {
		viper.Set("sniff.vif_drop_privileges", vifDropPrivileges)
	}

	if readFile == "" {
		capture.StartLiveSniffer(interfaces, filter, capture.StartSniffer)
	} else {
		capture.StartOfflineSniffer([]string{readFile}, filter, capture.StartSniffer)
	}
}

func init() {
	SniffCmd.AddCommand(voipCmd)
	SniffCmd.AddCommand(dnsCmd)
	SniffCmd.AddCommand(emailCmd)
	SniffCmd.AddCommand(tlsCmd)
	SniffCmd.AddCommand(httpCmd)
	SniffCmd.PersistentFlags().StringVarP(&interfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	SniffCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
	SniffCmd.PersistentFlags().StringVarP(&readFile, "read-file", "r", "", "read from pcap file")
	SniffCmd.PersistentFlags().BoolVarP(&promiscuous, "promiscuous", "p", false, "use promiscuous mode (captures all network traffic - use with caution)")
	SniffCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet mode - don't print packets (better performance)")
	SniffCmd.PersistentFlags().StringVar(&format, "format", "json", "output format: json, text")
	SniffCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "write to pcap file")

	// Virtual Interface Flags (inherited by voip subcommand)
	SniffCmd.PersistentFlags().BoolVarP(&virtualInterface, "virtual-interface", "V", false, "Enable virtual network interface for packet injection")
	SniffCmd.PersistentFlags().StringVar(&virtualInterfaceName, "vif-name", "lc0", "Virtual interface name (default: lc0)")
	SniffCmd.PersistentFlags().DurationVar(&vifStartupDelay, "vif-startup-delay", 3*time.Second, "Delay before packet injection starts (allows tools to attach)")
	SniffCmd.PersistentFlags().BoolVar(&vifReplayTiming, "vif-replay-timing", false, "Respect original packet timing from PCAP (like tcpreplay)")
	SniffCmd.PersistentFlags().StringVar(&vifType, "vif-type", "tap", "Virtual interface type: tap (Layer 2) or tun (Layer 3)")
	SniffCmd.PersistentFlags().IntVar(&vifBufferSize, "vif-buffer-size", 65536, "Injection queue buffer size (packets)")
	SniffCmd.PersistentFlags().StringVar(&vifNetNS, "vif-netns", "", "Network namespace for interface isolation (requires CAP_SYS_ADMIN)")
	SniffCmd.PersistentFlags().StringVar(&vifDropPrivileges, "vif-drop-privileges", "", "Drop privileges to specified user after interface creation (requires running as root)")

	_ = viper.BindPFlag("promiscuous", SniffCmd.PersistentFlags().Lookup("promiscuous"))
	_ = viper.BindPFlag("sniff.quiet", SniffCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("sniff.format", SniffCmd.PersistentFlags().Lookup("format"))

	// Bind virtual interface flags to viper
	_ = viper.BindPFlag("sniff.virtual_interface", SniffCmd.PersistentFlags().Lookup("virtual-interface"))
	_ = viper.BindPFlag("sniff.vif_name", SniffCmd.PersistentFlags().Lookup("vif-name"))
	_ = viper.BindPFlag("sniff.vif_startup_delay", SniffCmd.PersistentFlags().Lookup("vif-startup-delay"))
	_ = viper.BindPFlag("sniff.vif_replay_timing", SniffCmd.PersistentFlags().Lookup("vif-replay-timing"))
	_ = viper.BindPFlag("sniff.vif_type", SniffCmd.PersistentFlags().Lookup("vif-type"))
	_ = viper.BindPFlag("sniff.vif_buffer_size", SniffCmd.PersistentFlags().Lookup("vif-buffer-size"))
	_ = viper.BindPFlag("sniff.vif_netns", SniffCmd.PersistentFlags().Lookup("vif-netns"))
	_ = viper.BindPFlag("sniff.vif_drop_privileges", SniffCmd.PersistentFlags().Lookup("vif-drop-privileges"))
}
