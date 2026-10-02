package capture

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode"

	"github.com/google/gopacket/pcap"
)

// InterfaceAddress is an IP address and its optional network prefix length.
type InterfaceAddress struct {
	IP        string `json:"ip"`
	PrefixLen *int   `json:"prefix_len,omitempty"`
}

// CaptureInterface describes a capture source without testing capture access.
type CaptureInterface struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Type         string             `json:"type"`
	State        string             `json:"state"`
	Addresses    []InterfaceAddress `json:"addresses,omitempty"`
	DefaultRoute bool               `json:"default_route"`
	Hidden       bool               `json:"-"`
}

// InterfaceDiscovery includes nonfatal metadata diagnostics alongside devices.
type InterfaceDiscovery struct {
	Interfaces []CaptureInterface
	Warnings   []string
}

// DiscoverInterfaces enumerates libpcap capture sources once and enriches them
// with OS metadata. Unavailable metadata does not hide an otherwise usable device.
func DiscoverInterfaces() (InterfaceDiscovery, error) {
	return discoverInterfaces(pcap.FindAllDevs, discoverInterfaceMetadata)
}

func discoverInterfaces(findDevices func() ([]pcap.Interface, error), metadata func() (map[string]CaptureInterface, []string)) (InterfaceDiscovery, error) {
	devices, err := findDevices()
	if err != nil {
		return InterfaceDiscovery{}, fmt.Errorf("discover capture interfaces: %w", err)
	}
	byName, warnings := metadata()
	result := InterfaceDiscovery{Interfaces: make([]CaptureInterface, 0, len(devices)), Warnings: warnings}
	for _, device := range devices {
		info, exists := byName[device.Name]
		if !exists {
			info = CaptureInterface{Type: "Unknown", State: "unknown"}
		}
		info.Name = device.Name
		info.Description = cleanInterfaceDescription(device.Description)
		if device.Name == "any" {
			info.Type, info.State = "Aggregate", "unknown"
			info.Description = "Capture from all network interfaces"
		} else if !exists && isSpecialCaptureSource(device.Name) {
			info.Type, info.State, info.Hidden = "Special", "unknown", true
		}
		for _, address := range device.Addresses {
			info.Addresses = appendInterfaceAddress(info.Addresses, address.IP, address.Netmask)
		}
		if info.DefaultRoute {
			info.Hidden = false
		}
		sort.SliceStable(info.Addresses, func(i, j int) bool {
			a, b := net.ParseIP(info.Addresses[i].IP), net.ParseIP(info.Addresses[j].IP)
			if (a.To4() != nil) != (b.To4() != nil) {
				return a.To4() != nil
			}
			return info.Addresses[i].IP < info.Addresses[j].IP
		})
		result.Interfaces = append(result.Interfaces, info)
	}
	sort.SliceStable(result.Interfaces, func(i, j int) bool {
		a, b := result.Interfaces[i], result.Interfaces[j]
		if interfaceSortRank(a) != interfaceSortRank(b) {
			return interfaceSortRank(a) < interfaceSortRank(b)
		}
		return a.Name < b.Name
	})
	return result, nil
}

func cleanInterfaceDescription(description string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, description))
}

func isSpecialCaptureSource(name string) bool {
	switch name {
	case "dbus-system", "dbus-session", "nfqueue", "nflog", "bluetooth-monitor":
		return true
	}
	// These are libpcap capture-source namespaces, not general interface substrings.
	return strings.HasPrefix(name, "usbmon") || strings.HasPrefix(name, "bluetooth")
}

func interfaceSortRank(info CaptureInterface) int {
	if info.DefaultRoute {
		return 0
	}
	if info.Hidden {
		return 6
	}
	switch info.Type {
	case "Ethernet", "Wi-Fi":
		return 1
	case "Tunnel":
		return 2
	case "Loopback":
		return 4
	case "Aggregate":
		return 5
	default:
		return 3
	}
}

func appendInterfaceAddress(addresses []InterfaceAddress, ip net.IP, mask net.IPMask) []InterfaceAddress {
	if ip == nil {
		return addresses
	}
	address := InterfaceAddress{IP: ip.String()}
	if prefix, bits := mask.Size(); bits != 0 {
		address.PrefixLen = &prefix
	}
	for i, existing := range addresses {
		if existing.IP == address.IP {
			if existing.PrefixLen == nil {
				addresses[i].PrefixLen = address.PrefixLen
			}
			return addresses
		}
	}
	return append(addresses, address)
}

func portableInterfaceMetadata() (map[string]CaptureInterface, []string) {
	result := make(map[string]CaptureInterface)
	interfaces, err := net.Interfaces()
	if err != nil {
		return result, []string{fmt.Sprintf("read network interface metadata: %v", err)}
	}
	var warnings []string
	for _, iface := range interfaces {
		info := CaptureInterface{Name: iface.Name, Type: "Unknown", State: "unknown"}
		if iface.Flags&net.FlagUp == 0 {
			info.State = "down"
		} else if iface.Flags&net.FlagRunning != 0 {
			info.State = "up"
		}
		if iface.Flags&net.FlagLoopback != 0 {
			info.Type = "Loopback"
		} else if iface.Flags&net.FlagPointToPoint != 0 {
			info.Type = "Tunnel"
		}
		addresses, err := iface.Addrs()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("read addresses for %s: %v", iface.Name, err))
		}
		for _, address := range addresses {
			if ipNet, ok := address.(*net.IPNet); ok {
				info.Addresses = appendInterfaceAddress(info.Addresses, ipNet.IP, ipNet.Mask)
			}
		}
		result[iface.Name] = info
	}
	return result, warnings
}
