//go:build cli || tui || hunter || all

package list

import (
	"fmt"
	"net"
	"os"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

// InterfaceAddress represents an IP address assigned to an interface (JSON output).
type InterfaceAddress struct {
	IP        string `json:"ip"`
	PrefixLen int    `json:"prefix_len,omitempty"`
}

// InterfaceInfo represents a network interface (JSON output).
type InterfaceInfo struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Addresses   []InterfaceAddress `json:"addresses,omitempty"`
}

// InterfacesOutput represents the JSON output for list interfaces.
type InterfacesOutput struct {
	Interfaces []InterfaceInfo `json:"interfaces"`
	Warning    string          `json:"warning,omitempty"`
}

var (
	interfacesJSON bool
)

var interfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List network interfaces available for monitoring",
	Long:  `List network interfaces that lippycat can monitor for VoIP traffic. Requires appropriate permissions.`,
	Run:   runInterfaces,
}

func init() {
	interfacesCmd.Flags().BoolVar(&interfacesJSON, "json", false, "Output in JSON format")
}

func runInterfaces(cmd *cobra.Command, args []string) {
	if interfacesJSON {
		runInterfacesJSON(cmd)
		return
	}

	// Plain text output (default)
	if os.Geteuid() != 0 {
		fmt.Println("Warning: Running without root privileges. Some interfaces may not be accessible.")
		fmt.Println("Consider running with 'sudo' for full interface access.")
		fmt.Println()
	}

	ifaces, err := capture.ListInterfaces(false) // don't include "any" in plain text
	if err != nil {
		logger.Error("Error accessing network interfaces", "error", err)
		fmt.Println("Unable to list network interfaces. This may be due to insufficient permissions.")
		return
	}

	fmt.Println("Network interfaces suitable for VoIP monitoring:")
	if len(ifaces) == 0 {
		fmt.Println("  No suitable interfaces found for VoIP monitoring.")
	} else {
		for _, iface := range ifaces {
			if iface.Description != "" {
				fmt.Printf("  %s - %s\n", iface.Name, iface.Description)
			} else {
				fmt.Printf("  %s\n", iface.Name)
			}
		}
	}

	fmt.Println("\nNote: Interface selection should comply with your organization's network monitoring policies.")
	fmt.Println("Only monitor interfaces you have explicit permission to access.")
}

func runInterfacesJSON(cmd *cobra.Command) {
	result := InterfacesOutput{}

	if os.Geteuid() != 0 {
		result.Warning = "Running without root privileges. Some interfaces may not be accessible."
	}

	// For JSON output, we need the raw pcap data to include addresses
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logger.Error("Error accessing network interfaces", "error", err)
		outputInterfacesError(cmd, fmt.Errorf("unable to list network interfaces: %w", err))
		return
	}

	// Build a map of filtered interface info for descriptions
	filteredIfaces, _ := capture.ListInterfaces(false)
	descMap := make(map[string]string)
	for _, i := range filteredIfaces {
		descMap[i.Name] = i.Description
	}

	for _, device := range devices {
		// Skip "any" pseudo-device in JSON output
		if device.Name == "any" {
			continue
		}

		if !capture.IsValidMonitoringInterface(device.Name) {
			continue
		}

		info := InterfaceInfo{
			Name:        device.Name,
			Description: descMap[device.Name],
		}

		for _, addr := range device.Addresses {
			if addr.IP != nil {
				ifaceAddr := InterfaceAddress{
					IP: addr.IP.String(),
				}
				if addr.Netmask != nil {
					ones, _ := net.IPMask(addr.Netmask).Size()
					ifaceAddr.PrefixLen = ones
				}
				info.Addresses = append(info.Addresses, ifaceAddr)
			}
		}

		result.Interfaces = append(result.Interfaces, info)
	}

	jsonBytes, err := output.MarshalJSON(result)
	if err != nil {
		outputInterfacesError(cmd, fmt.Errorf("failed to marshal JSON: %w", err))
		return
	}

	cmd.Println(string(jsonBytes))
}

func outputInterfacesError(cmd *cobra.Command, err error) {
	errOutput := struct {
		Error string `json:"error"`
	}{
		Error: err.Error(),
	}
	jsonBytes, _ := output.MarshalJSON(errOutput)
	cmd.PrintErrln(string(jsonBytes))
}
