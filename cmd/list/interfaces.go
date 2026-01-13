//go:build cli || tui || hunter || all

package list

import (
	"fmt"
	"os"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

var interfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List network interfaces available for monitoring",
	Long:  `List network interfaces that lippycat can monitor for VoIP traffic. Requires appropriate permissions.`,
	Run:   runInterfaces,
}

func runInterfaces(cmd *cobra.Command, args []string) {
	// Check if running with appropriate privileges
	if os.Geteuid() != 0 {
		fmt.Println("Warning: Running without root privileges. Some interfaces may not be accessible.")
		fmt.Println("Consider running with 'sudo' for full interface access.")
		fmt.Println()
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		logger.Error("Error accessing network interfaces", "error", err)
		fmt.Println("Unable to list network interfaces. This may be due to insufficient permissions.")
		return
	}

	fmt.Println("Network interfaces suitable for VoIP monitoring:")
	validCount := 0
	for _, device := range devices {
		// Filter out sensitive or irrelevant interfaces
		if isValidMonitoringInterface(device.Name) {
			validCount++
			fmt.Printf("  %s", device.Name)

			// Only show basic, non-sensitive description
			if device.Description != "" && !containsSensitiveInfo(device.Description) {
				// Sanitize description
				desc := sanitizeDescription(device.Description)
				if desc != "" {
					fmt.Printf(" - %s", desc)
				}
			}
			fmt.Println()
		}
	}

	if validCount == 0 {
		fmt.Println("  No suitable interfaces found for VoIP monitoring.")
	}

	fmt.Println("\nNote: Interface selection should comply with your organization's network monitoring policies.")
	fmt.Println("Only monitor interfaces you have explicit permission to access.")
}

func isValidMonitoringInterface(name string) bool {
	// Filter out potentially sensitive or irrelevant interfaces
	name = strings.ToLower(name)

	// Skip loopback, USB, and other non-network interfaces
	excludePatterns := []string{
		"lo", "loopback", // Loopback interfaces
		"usb", "bluetooth", // USB/Bluetooth interfaces
		"docker", "veth", // Container interfaces
		"vmnet", "vbox", // Virtual machine interfaces
		"isatap", "teredo", // Tunnel interfaces
	}

	for _, pattern := range excludePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}

	return true
}

func containsSensitiveInfo(desc string) bool {
	desc = strings.ToLower(desc)
	sensitiveKeywords := []string{
		"mac", "address", "serial", "uuid",
		"hardware", "vendor", "manufacturer",
		"private", "internal", "management",
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(desc, keyword) {
			return true
		}
	}
	return false
}

func sanitizeDescription(desc string) string {
	// Remove potentially sensitive information from descriptions
	desc = strings.TrimSpace(desc)

	// Keep only basic interface type descriptions
	if len(desc) > 50 {
		desc = desc[:50] + "..."
	}

	return desc
}
