//go:build linux

package capture

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func discoverInterfaceMetadata() (map[string]CaptureInterface, []string) {
	result, warnings := portableInterfaceMetadata()
	links, err := netlink.LinkList()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("read Linux link metadata: %v", err))
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("read default routes: %v", err))
	}
	defaults := defaultRouteInterfaces(routes)
	for _, link := range links {
		attrs := link.Attrs()
		info := result[attrs.Name]
		info.Name = attrs.Name
		physical, wireless := false, false
		for _, attribute := range []string{"device", "wireless", "phy80211"} {
			_, err := os.Stat(filepath.Join("/sys/class/net", attrs.Name, attribute))
			if err == nil {
				if attribute == "device" {
					physical = true
				} else {
					wireless = true
				}
			} else if !os.IsNotExist(err) {
				warnings = append(warnings, fmt.Sprintf("read %s metadata for %s: %v", attribute, attrs.Name, err))
			}
		}
		info.Type, info.Hidden = classifyLinuxInterface(link, physical, wireless)
		info.State = attrs.OperState.String()
		// The kernel often reports UNKNOWN for usable loopback and tunnel links.
		if attrs.Flags&net.FlagUp == 0 {
			info.State = "down"
		} else if attrs.Flags&net.FlagLoopback != 0 && attrs.OperState == netlink.OperUnknown {
			info.State = "up"
		}
		info.DefaultRoute = defaults[attrs.Index]
		result[attrs.Name] = info
	}
	return result, warnings
}

func classifyLinuxInterface(link netlink.Link, physical, wireless bool) (string, bool) {
	attrs := link.Attrs()
	if attrs.Flags&net.FlagLoopback != 0 {
		return "Loopback", false
	}
	if wireless {
		return "Wi-Fi", false
	}
	switch link.Type() {
	case "bridge":
		return "Bridge", true
	case "veth", "netkit", "dummy", "ifb", "macvtap", "ipvtap":
		return "Virtual", true
	case "wireguard", "tun", "ipip", "ip6tnl", "sit", "gre", "gretap", "ip6gre", "ip6gretap", "vti", "vti6", "vxlan", "geneve", "gtp", "xfrm", "bareudp":
		return "Tunnel", false
	case "tuntap":
		if tuntap, ok := link.(*netlink.Tuntap); ok && tuntap.Mode == netlink.TUNTAP_MODE_TAP {
			return "Virtual", true
		}
		return "Tunnel", false
	case "vlan", "macvlan", "ipvlan", "bond", "team", "vrf":
		return "Virtual", false
	}
	if attrs.Flags&net.FlagPointToPoint != 0 {
		return "Tunnel", false
	}
	if physical && attrs.EncapType == "ether" {
		return "Ethernet", false
	}
	return "Unknown", false
}

func defaultRouteInterfaces(routes []netlink.Route) map[int]bool {
	result := make(map[int]bool)
	for _, route := range routes {
		if route.Type != unix.RTN_UNICAST && route.Type != 0 {
			continue
		}
		if route.Dst != nil {
			prefix, bits := route.Dst.Mask.Size()
			if bits == 0 || prefix != 0 || !route.Dst.IP.IsUnspecified() {
				continue
			}
		}
		if route.LinkIndex > 0 {
			result[route.LinkIndex] = true
		}
		for _, nextHop := range route.MultiPath {
			if nextHop != nil && nextHop.LinkIndex > 0 {
				result[nextHop.LinkIndex] = true
			}
		}
	}
	return result
}
