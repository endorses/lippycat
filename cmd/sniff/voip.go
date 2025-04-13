package sniff

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
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
	expirationDate := time.Date(0o001, 0o1, 0o1, 0o1, 0o1, 0o1, 0o00000001, time.UTC)
	su := sipusers.SipUser{ExpirationDate: expirationDate}

	for _, user := range strings.Split(sipuser, ",") {
		sipusers.AddSipUser(user, &su)
		// sipusers.AddSipUser(user, &sipusers.SipUser{ExpirationDate: time.Date(0o001, 0o1, 0o1, 0o1, 0o1, 0o1, 0o00000001, time.UTC)})
	}

	fmt.Println("Sniffing Voip")

	if filter == "" {
		filter = "port 5060"
	}

	if readFile == "" {
		voip.StartLiveVoipSniffer(interfaces, filter)
	} else {
		voip.StartOfflineVoipSniffer(readFile, filter)
	}
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
