//go:build cli || all
// +build cli all

package show

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Show active alerts and alert history",
	Long:  `Display current active alerts and recent alert history for TCP resource monitoring.`,
	Run: func(cmd *cobra.Command, args []string) {
		activeOnly, _ := cmd.Flags().GetBool("active-only")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showAlerts(activeOnly, jsonOutput)
	},
}

func init() {
	alertsCmd.Flags().Bool("active-only", false, "Show only active alerts")
	alertsCmd.Flags().Bool("json", false, "Output in JSON format")
}

func showAlerts(activeOnly, jsonOutput bool) {
	alertManager := voip.GetAlertManager()

	var alerts []voip.Alert
	if activeOnly {
		alerts = alertManager.GetActiveAlerts()
	} else {
		alerts = alertManager.GetAllAlerts()
	}

	if jsonOutput {
		data, err := json.MarshalIndent(alerts, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling alerts: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	if activeOnly {
		fmt.Println("=== Active Alerts ===")
	} else {
		fmt.Println("=== All Alerts ===")
	}

	if len(alerts) == 0 {
		if activeOnly {
			fmt.Println("No active alerts")
		} else {
			fmt.Println("No alerts in history")
		}
		return
	}

	// Sort alerts by timestamp (newest first)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LEVEL\tCOMPONENT\tSTATUS\tTIME\tMESSAGE")
	fmt.Fprintln(w, "-----\t---------\t------\t----\t-------")

	for _, alert := range alerts {
		level := alert.Level.String()
		status := "ACTIVE"
		if alert.Resolved {
			status = "RESOLVED"
		}

		// Add level indicators
		levelIndicator := ""
		switch alert.Level {
		case voip.AlertCritical:
			levelIndicator = "[!]"
		case voip.AlertWarning:
			levelIndicator = "[*]"
		case voip.AlertInfo:
			levelIndicator = "[i]"
		}

		timeStr := alert.Timestamp.Format("15:04:05")
		message := alert.Message
		if len(message) > 50 {
			message = message[:47] + "..."
		}

		fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\t%s\n",
			levelIndicator, level, alert.Component, status, timeStr, message)
	}

	_ = w.Flush() // Best-effort flush for output
	fmt.Println()
}
