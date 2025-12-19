//go:build cli || tui || all
// +build cli tui all

package list

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidMonitoringInterface(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		expected      bool
	}{
		// Valid interfaces
		{
			name:          "Standard ethernet interface",
			interfaceName: "eth0",
			expected:      true,
		},
		{
			name:          "Wireless interface",
			interfaceName: "wlan0",
			expected:      true,
		},
		{
			name:          "Network interface with numbers",
			interfaceName: "enp3s0",
			expected:      true,
		},
		{
			name:          "Bridge interface",
			interfaceName: "br0",
			expected:      true,
		},

		// Excluded interfaces - loopback
		{
			name:          "Loopback interface lowercase",
			interfaceName: "lo",
			expected:      false,
		},
		{
			name:          "Loopback interface uppercase",
			interfaceName: "LO",
			expected:      false,
		},
		{
			name:          "Loopback with numbers",
			interfaceName: "lo0",
			expected:      false,
		},
		{
			name:          "Loopback explicit",
			interfaceName: "loopback",
			expected:      false,
		},

		// Excluded interfaces - USB
		{
			name:          "USB interface",
			interfaceName: "usb0",
			expected:      false,
		},
		{
			name:          "USB with mixed case",
			interfaceName: "USB-ethernet",
			expected:      false,
		},

		// Excluded interfaces - Bluetooth
		{
			name:          "Bluetooth interface",
			interfaceName: "bluetooth0",
			expected:      false,
		},
		{
			name:          "Bluetooth short",
			interfaceName: "bt0",
			expected:      true, // "bt" is not in the exclusion patterns, only "bluetooth"
		},

		// Excluded interfaces - Docker
		{
			name:          "Docker interface",
			interfaceName: "docker0",
			expected:      false,
		},
		{
			name:          "Docker bridge",
			interfaceName: "br-1234567890ab",
			expected:      true, // This should pass as it's just "br" not "docker"
		},
		{
			name:          "Docker veth",
			interfaceName: "veth123abc",
			expected:      false,
		},

		// Excluded interfaces - VM
		{
			name:          "VMware interface",
			interfaceName: "vmnet8",
			expected:      false,
		},
		{
			name:          "VirtualBox interface",
			interfaceName: "vboxnet0",
			expected:      false,
		},

		// Excluded interfaces - Tunnels
		{
			name:          "ISATAP interface",
			interfaceName: "isatap.example.com",
			expected:      false,
		},
		{
			name:          "Teredo interface",
			interfaceName: "teredo",
			expected:      false,
		},

		// Edge cases
		{
			name:          "Empty interface name",
			interfaceName: "",
			expected:      true, // Empty string doesn't match any exclusion patterns
		},
		{
			name:          "Interface with excluded substring",
			interfaceName: "eth-usb-adapter",
			expected:      false, // Contains "usb"
		},
		{
			name:          "Mixed case exclusion test",
			interfaceName: "Docker-Bridge",
			expected:      false, // Contains "docker" (case insensitive)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidMonitoringInterface(tt.interfaceName)
			assert.Equal(t, tt.expected, result, "Interface %s should return %t", tt.interfaceName, tt.expected)
		})
	}
}

func TestContainsSensitiveInfo(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    bool
	}{
		// Sensitive information
		{
			name:        "MAC address reference",
			description: "Interface with MAC 00:11:22:33:44:55",
			expected:    true,
		},
		{
			name:        "Address information",
			description: "Network adapter with address information",
			expected:    true,
		},
		{
			name:        "Serial number",
			description: "USB adapter serial: 12345678",
			expected:    true,
		},
		{
			name:        "UUID reference",
			description: "Device UUID: 550e8400-e29b-41d4-a716-446655440000",
			expected:    true,
		},
		{
			name:        "Hardware information",
			description: "Hardware revision 2.1",
			expected:    true,
		},
		{
			name:        "Vendor information",
			description: "Intel vendor driver",
			expected:    true,
		},
		{
			name:        "Manufacturer details",
			description: "Manufacturer: Realtek",
			expected:    true,
		},
		{
			name:        "Private network info",
			description: "Private management interface",
			expected:    true,
		},
		{
			name:        "Internal reference",
			description: "Internal network controller",
			expected:    true,
		},
		{
			name:        "Management interface",
			description: "Management ethernet port",
			expected:    true,
		},

		// Non-sensitive information
		{
			name:        "Simple ethernet description",
			description: "Ethernet network interface",
			expected:    false,
		},
		{
			name:        "Basic WiFi description",
			description: "Wireless network adapter",
			expected:    false,
		},
		{
			name:        "Generic network description",
			description: "Network connection device",
			expected:    false,
		},
		{
			name:        "Speed information",
			description: "1000 Mbps network adapter",
			expected:    false,
		},
		{
			name:        "Protocol information",
			description: "TCP/IP network interface",
			expected:    false,
		},

		// Edge cases
		{
			name:        "Empty description",
			description: "",
			expected:    false,
		},
		{
			name:        "Mixed case sensitive keywords",
			description: "Device with MAC Address",
			expected:    true, // Case insensitive
		},
		{
			name:        "Partial keyword matches",
			description: "Network broadcaster device", // Contains "address" in "broadcaster"
			expected:    false,                        // "broadcaster" doesn't contain "address" as a substring
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSensitiveInfo(tt.description)
			assert.Equal(t, tt.expected, result, "Description '%s' should return %t", tt.description, tt.expected)
		})
	}
}

func TestSanitizeDescription(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    string
	}{
		{
			name:        "Normal description",
			description: "Ethernet network interface",
			expected:    "Ethernet network interface",
		},
		{
			name:        "Description with leading/trailing whitespace",
			description: "  Wireless adapter  ",
			expected:    "Wireless adapter",
		},
		{
			name:        "Very long description gets truncated",
			description: "This is a very long description that exceeds the 50 character limit and should be truncated with ellipsis",
			expected:    "This is a very long description that exceeds the 5...",
		},
		{
			name:        "Exactly 50 characters",
			description: "This description is exactly fifty characters!!",
			expected:    "This description is exactly fifty characters!!",
		},
		{
			name:        "Description at 51 characters",
			description: "This description is exactly fifty-one characters!XX",   // Add XX to make it 51 chars
			expected:    "This description is exactly fifty-one characters!X...", // 51 chars gets truncated
		},
		{
			name:        "Empty description",
			description: "",
			expected:    "",
		},
		{
			name:        "Whitespace only description",
			description: "   ",
			expected:    "",
		},
		{
			name:        "Short description with whitespace",
			description: " WiFi ",
			expected:    "WiFi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeDescription(tt.description)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 53, "Result should not exceed 53 characters (50 + '...')")
		})
	}
}

func TestInterfaceSecurityFiltering_Integration(t *testing.T) {
	// Test the complete filtering process
	testCases := []struct {
		name          string
		interfaceName string
		description   string
		shouldShow    bool
		expectedDesc  string
	}{
		{
			name:          "Valid interface with safe description",
			interfaceName: "eth0",
			description:   "Ethernet network adapter",
			shouldShow:    true,
			expectedDesc:  "Ethernet network adapter",
		},
		{
			name:          "Valid interface with sensitive description",
			interfaceName: "wlan0",
			description:   "WiFi adapter MAC: 00:11:22:33:44:55",
			shouldShow:    true,
			expectedDesc:  "", // Description should be filtered out
		},
		{
			name:          "Invalid interface (docker)",
			interfaceName: "docker0",
			description:   "Docker network bridge",
			shouldShow:    false,
			expectedDesc:  "",
		},
		{
			name:          "Valid interface with long description",
			interfaceName: "enp3s0",
			description:   "This is a very long network adapter description that will be truncated",
			shouldShow:    true,
			expectedDesc:  "This is a very long network adapter description th...",
		},
		{
			name:          "Loopback interface should be filtered",
			interfaceName: "lo",
			description:   "Loopback interface",
			shouldShow:    false,
			expectedDesc:  "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Test interface filtering
			isValid := isValidMonitoringInterface(tt.interfaceName)
			assert.Equal(t, tt.shouldShow, isValid, "Interface validity should match expected")

			if tt.shouldShow {
				// Test description filtering and sanitization
				isSensitive := containsSensitiveInfo(tt.description)
				var finalDesc string
				if !isSensitive {
					finalDesc = sanitizeDescription(tt.description)
				}
				assert.Equal(t, tt.expectedDesc, finalDesc, "Final description should match expected")
			}
		})
	}
}
