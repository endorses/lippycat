package sniff

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var voipCmd = &cobra.Command{
	Use:   "voip",
	Short: "Sniff in VOIP mode",
	Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
	Run:   voipHandler,
}

var sipuser string

func voipHandler(cmd *cobra.Command, args []string) {
	for _, user := range strings.Split(sipuser, ",") {
		voip.SIPUsers.AddSIPUser(user)
	}

	fmt.Println("Sniffing Voip")

	// if filter == "" {
	// 	filter = "port 5060"
	// }

	voip.StartVoipSniffer(interfaces, filter)
}

// func containsAny(s string, substrs []string) bool {
// 	for _, u := range substrs {
// 		if strings.Contains(s, u) {
// 			return true
// 		}
// 	}
// 	return false
// }

func init() {
	voipCmd.Flags().StringVarP(&sipuser, "sipuser", "u", "", "SIP user to intercept")
}
