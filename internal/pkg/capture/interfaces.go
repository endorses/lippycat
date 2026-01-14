// Package capture provides network packet capture functionality.
package capture

import (
	"strings"

	"github.com/google/gopacket/pcap"
)

// InterfaceInfo contains basic interface information for display.
type InterfaceInfo struct {
	Name        string
	Description string
}

// ListInterfaces returns network interfaces suitable for monitoring.
// It filters out sensitive or irrelevant interfaces (loopback, containers, VMs, etc.)
// and sanitizes descriptions to remove potentially sensitive information.
// If includeAny is true, "any" is included at the beginning of the list.
func ListInterfaces(includeAny bool) ([]InterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo

	if includeAny {
		result = append(result, InterfaceInfo{
			Name:        "any",
			Description: "Capture from all interfaces",
		})
	}

	for _, device := range devices {
		// Skip "any" since we handle it specially
		if device.Name == "any" {
			continue
		}

		if !IsValidMonitoringInterface(device.Name) {
			continue
		}

		info := InterfaceInfo{
			Name: device.Name,
		}

		if device.Description != "" && !containsSensitiveInfo(device.Description) {
			info.Description = sanitizeDescription(device.Description)
		} else {
			info.Description = "Network interface"
		}

		result = append(result, info)
	}

	return result, nil
}

// IsValidMonitoringInterface returns true if the interface is suitable for monitoring.
// It filters out loopback, USB, bluetooth, container, VM, and tunnel interfaces.
func IsValidMonitoringInterface(name string) bool {
	name = strings.ToLower(name)

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

// containsSensitiveInfo checks if a description contains sensitive keywords.
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

// sanitizeDescription cleans up interface descriptions for display.
func sanitizeDescription(desc string) string {
	desc = strings.TrimSpace(desc)

	if len(desc) > 50 {
		desc = desc[:50] + "..."
	}

	return desc
}
