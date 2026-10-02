package capture

import (
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverInterfacesMergesCaptureAndOSMetadata(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "dbus-system", Description: "D-Bus\n\x1b[31m source"},
		{Name: "bridge0"}, {Name: "eth0"}, {Name: "lo"}, {Name: "any"},
		{Name: "mystery0"}, {Name: "usb0"}, {Name: "vpn0"},
		{Name: "wlan0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.0.2.1"), Netmask: net.CIDRMask(24, 32)}}},
	}
	metadata := map[string]CaptureInterface{
		"bridge0": {Type: "Bridge", State: "up", Hidden: true, DefaultRoute: true},
		"eth0":    {Type: "Ethernet", State: "up"},
		"lo":      {Type: "Loopback", State: "up"},
		"usb0":    {Type: "Ethernet", State: "up"},
		"vpn0":    {Type: "Tunnel", State: "unknown"},
		"wlan0":   {Type: "Wi-Fi", State: "down", Addresses: []InterfaceAddress{{IP: "192.0.2.1"}}},
	}
	calls := 0
	result, err := discoverInterfaces(func() ([]pcap.Interface, error) {
		calls++
		return devices, nil
	}, func() (map[string]CaptureInterface, []string) {
		return metadata, []string{"route metadata unavailable"}
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, []string{"route metadata unavailable"}, result.Warnings)
	var names []string
	byName := make(map[string]CaptureInterface)
	for _, info := range result.Interfaces {
		names = append(names, info.Name)
		byName[info.Name] = info
	}
	assert.Equal(t, []string{"bridge0", "eth0", "usb0", "wlan0", "vpn0", "mystery0", "lo", "any", "dbus-system"}, names)
	assert.False(t, byName["bridge0"].Hidden, "default route remains visible")
	assert.Equal(t, "down", byName["wlan0"].State)
	require.Len(t, byName["wlan0"].Addresses, 1)
	require.NotNil(t, byName["wlan0"].Addresses[0].PrefixLen)
	assert.Equal(t, 24, *byName["wlan0"].Addresses[0].PrefixLen)
	assert.Equal(t, "Unknown", byName["mystery0"].Type)
	assert.False(t, byName["mystery0"].Hidden)
	assert.Equal(t, "Aggregate", byName["any"].Type)
	assert.True(t, byName["dbus-system"].Hidden)
	assert.NotContains(t, byName["dbus-system"].Description, "\x1b")
	assert.NotContains(t, byName["dbus-system"].Description, "\n")
}

func TestDiscoverInterfacesDoesNotInventAny(t *testing.T) {
	result, err := discoverInterfaces(func() ([]pcap.Interface, error) {
		return []pcap.Interface{{Name: "lo"}}, nil
	}, func() (map[string]CaptureInterface, []string) {
		return nil, nil
	})
	require.NoError(t, err)
	require.Len(t, result.Interfaces, 1)
	assert.Equal(t, "lo", result.Interfaces[0].Name)
}

func TestDiscoverInterfacesEnumerationFailure(t *testing.T) {
	wantErr := errors.New("enumeration failed")
	_, err := discoverInterfaces(func() ([]pcap.Interface, error) {
		return nil, wantErr
	}, func() (map[string]CaptureInterface, []string) {
		t.Fatal("metadata must not be queried after enumeration failed")
		return nil, nil
	})
	assert.ErrorIs(t, err, wantErr)
}

func TestDiscoverInterfacesSpecialSources(t *testing.T) {
	names := []string{"nfqueue", "nflog", "dbus-system", "dbus-session", "usbmon0", "bluetooth-monitor", "usb0", "myloopnetwork", "bluetooth-network"}
	var devices []pcap.Interface
	for _, name := range names {
		devices = append(devices, pcap.Interface{Name: name})
	}
	result, err := discoverInterfaces(func() ([]pcap.Interface, error) {
		return devices, nil
	}, func() (map[string]CaptureInterface, []string) {
		return map[string]CaptureInterface{"bluetooth-network": {Type: "Ethernet", State: "up"}}, nil
	})
	require.NoError(t, err)
	for _, info := range result.Interfaces {
		if info.Name == "usb0" || info.Name == "myloopnetwork" || info.Name == "bluetooth-network" {
			assert.False(t, info.Hidden, info.Name)
		} else {
			assert.Equal(t, "Special", info.Type, info.Name)
			assert.True(t, info.Hidden, info.Name)
		}
	}
}

func TestInterfaceAddressUnknownPrefixAndZeroPrefix(t *testing.T) {
	addresses := appendInterfaceAddress(nil, net.ParseIP("192.0.2.1"), nil)
	require.Len(t, addresses, 1)
	assert.Nil(t, addresses[0].PrefixLen)
	addresses = appendInterfaceAddress(addresses, net.ParseIP("192.0.2.1"), net.CIDRMask(0, 32))
	require.Len(t, addresses, 1)
	require.NotNil(t, addresses[0].PrefixLen)
	assert.Zero(t, *addresses[0].PrefixLen)
	addresses = appendInterfaceAddress(addresses, net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128))
	assert.Equal(t, "2001:db8::1", addresses[1].IP)
	assert.Equal(t, 64, *addresses[1].PrefixLen)
}
