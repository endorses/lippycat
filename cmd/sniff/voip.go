package sniff

import (
	"log"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var voipCmd = &cobra.Command{
	Use:   "voip",
	Short: "Sniff in VOIP mode",
	Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
	Run:   voipHandler,
}

var (
	sipuser   string
	writeVoip bool
)

func voipHandler(cmd *cobra.Command, args []string) {
	expirationDate := time.Date(0o001, 0o1, 0o1, 0o1, 0o1, 0o1, 0o00000001, time.UTC)
	su := sipusers.SipUser{ExpirationDate: expirationDate}

	for _, user := range strings.Split(sipuser, ",") {
		sipusers.AddSipUser(user, &su)
	}

	log.Println("Sniffing Voip")
	viper.Set("writeVoip", writeVoip)

	if readFile == "" {
		voip.StartLiveVoipSniffer(interfaces, filter)
	} else {
		voip.StartOfflineVoipSniffer(readFile, filter)
	}
}

func init() {
	voipCmd.Flags().StringVarP(&sipuser, "sipuser", "u", "", "SIP user to intercept")
	voipCmd.Flags().BoolVarP(&writeVoip, "write-file", "w", false, "write to pcap file")
}
