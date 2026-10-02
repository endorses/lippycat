//go:build linux

package capture

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestClassifyLinuxCaptureInterfaces(t *testing.T) {
	tests := []struct {
		name     string
		link     netlink.Link
		physical bool
		wireless bool
		kind     string
		hidden   bool
	}{
		{"USB Ethernet", &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "usb0", EncapType: "ether"}}, true, false, "Ethernet", false},
		{"unknown virtual Ethernet", &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "eth0", EncapType: "ether"}}, false, false, "Unknown", false},
		{"Wi-Fi", &netlink.Device{}, true, true, "Wi-Fi", false},
		{"loopback", &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagLoopback}}, false, false, "Loopback", false},
		{"bridge", &netlink.Bridge{}, false, false, "Bridge", true},
		{"veth", &netlink.Veth{}, false, false, "Virtual", true},
		{"VPN", &netlink.Wireguard{}, false, false, "Tunnel", false},
		{"TUN", &netlink.Tuntap{Mode: netlink.TUNTAP_MODE_TUN}, false, false, "Tunnel", false},
		{"TAP", &netlink.Tuntap{Mode: netlink.TUNTAP_MODE_TAP}, false, false, "Virtual", true},
		{"VLAN", &netlink.Vlan{}, false, false, "Virtual", false},
		{"point to point", &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagPointToPoint}}, false, false, "Tunnel", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, hidden := classifyLinuxInterface(tt.link, tt.physical, tt.wireless)
			assert.Equal(t, tt.kind, kind)
			assert.Equal(t, tt.hidden, hidden)
		})
	}
}

func TestDefaultRouteInterfacesIPv4IPv6AndMultipath(t *testing.T) {
	routes := []netlink.Route{
		{LinkIndex: 1, Dst: nil, Type: unix.RTN_UNICAST},
		{LinkIndex: 2, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
		{LinkIndex: 3, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}},
		{LinkIndex: 4, Dst: &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)}},
		{LinkIndex: 5, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(8, 32)}},
		{LinkIndex: 6, Type: unix.RTN_BLACKHOLE},
		{MultiPath: []*netlink.NexthopInfo{{LinkIndex: 7}, {LinkIndex: 8}}},
		{LinkIndex: 9, Dst: &net.IPNet{IP: net.IPv4zero}},
	}
	assert.Equal(t, map[int]bool{1: true, 2: true, 3: true, 7: true, 8: true}, defaultRouteInterfaces(routes))
}
