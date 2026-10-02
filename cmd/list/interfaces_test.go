//go:build cli || tui || hunter || all

package list

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func interfaceFixture() capture.InterfaceDiscovery {
	prefix := 24
	return capture.InterfaceDiscovery{Interfaces: []capture.CaptureInterface{
		{Name: "eth0", Type: "Ethernet", State: "up", DefaultRoute: true, Addresses: []capture.InterfaceAddress{{IP: "192.0.2.10", PrefixLen: &prefix}}},
		{Name: "wlan0", Type: "Wi-Fi", State: "down"},
		{Name: "lo", Type: "Loopback", State: "unknown"},
		{Name: "any", Type: "Aggregate", State: "unknown"},
		{Name: "br-test", Type: "Bridge", State: "down", Hidden: true},
		{Name: "dbus-system", Type: "Special", State: "unknown", Description: "D-Bus system bus", Hidden: true},
	}}
}

func executeInterfaces(t *testing.T, args ...string) (string, string, error, []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	var checked []string
	calls := 0
	cmd := newInterfacesCommand(func() (capture.InterfaceDiscovery, error) {
		calls++
		return interfaceFixture(), nil
	}, func(name string) error {
		checked = append(checked, name)
		if name == "wlan0" {
			return errors.New("permission denied")
		}
		return nil
	})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil {
		require.Equal(t, 1, calls, "enumerate once for each successful command")
	}
	return stdout.String(), stderr.String(), err, checked
}

func TestInterfacesDefaultTable(t *testing.T) {
	out, diagnostics, err, checked := executeInterfaces(t)
	require.NoError(t, err)
	assert.Empty(t, diagnostics)
	assert.Empty(t, checked, "ordinary listing must not probe capture access")
	for _, value := range []string{"NAME", "TYPE", "STATE", "ADDRESSES", "NOTES", "eth0", "192.0.2.10/24", "default route", "wlan0", "down", "lo", "any", "2 additional capture devices hidden"} {
		assert.Contains(t, out, value)
	}
	for _, value := range []string{"br-test", "dbus-system", "root", "sudo", "VoIP", "policies"} {
		assert.NotContains(t, out, value)
	}
}

func TestInterfacesNamesAndAll(t *testing.T) {
	out, diagnostics, err, _ := executeInterfaces(t, "--names")
	require.NoError(t, err)
	assert.Empty(t, diagnostics)
	assert.Equal(t, "eth0\nwlan0\nlo\nany\n", out)
	out, _, err, _ = executeInterfaces(t, "--names", "--all")
	require.NoError(t, err)
	assert.Equal(t, "eth0\nwlan0\nlo\nany\nbr-test\ndbus-system\n", out)
}

func TestInterfacesJSONAndChecks(t *testing.T) {
	out, diagnostics, err, checked := executeInterfaces(t, "--json", "--all", "--check")
	require.NoError(t, err)
	assert.Empty(t, diagnostics)
	assert.Equal(t, []string{"eth0", "wlan0", "lo", "any", "br-test"}, checked)
	var result InterfacesOutput
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	require.Len(t, result.Interfaces, 6)
	assert.Zero(t, result.HiddenCount)
	assert.True(t, result.Interfaces[0].DefaultRoute)
	assert.Equal(t, "available", result.Interfaces[0].CaptureAccess)
	assert.Equal(t, "unavailable", result.Interfaces[1].CaptureAccess)
	assert.Equal(t, "permission denied", result.Interfaces[1].CaptureError)
	assert.Equal(t, "skipped", result.Interfaces[5].CaptureAccess)
	assert.NotContains(t, out, `"Hidden"`)

	out, _, err, checked = executeInterfaces(t, "--json")
	require.NoError(t, err)
	assert.Empty(t, checked)
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Len(t, result.Interfaces, 4)
	assert.Equal(t, 2, result.HiddenCount)
	assert.NotContains(t, out, "capture_access")
}

func TestInterfacesCheckTable(t *testing.T) {
	out, _, err, checked := executeInterfaces(t, "--check")
	require.NoError(t, err)
	assert.Equal(t, []string{"eth0", "wlan0", "lo", "any"}, checked)
	assert.Contains(t, out, "CAPTURE")
	assert.Contains(t, out, "unavailable")
	assert.Contains(t, out, "permission denied")
}

func TestInterfacesRejectInvalidArgumentsBeforeDiscovery(t *testing.T) {
	for _, args := range [][]string{{"--names", "--json"}, {"--names", "--check"}, {"eth0"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newInterfacesCommand(func() (capture.InterfaceDiscovery, error) {
				t.Fatal("invalid arguments must not enumerate devices")
				return capture.InterfaceDiscovery{}, nil
			}, nil)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(args)
			require.Error(t, cmd.Execute())
		})
	}
}

func TestInterfacesDiscoveryErrors(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		t.Run(fmt.Sprint(asJSON), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := newInterfacesCommand(func() (capture.InterfaceDiscovery, error) {
				return capture.InterfaceDiscovery{}, errors.New("pcap failed")
			}, nil)
			// Match the production command nesting, including Cobra's error handling.
			root := &cobra.Command{Use: "lc"}
			root.AddCommand(cmd)
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			args := []string{"interfaces"}
			if asJSON {
				args = append(args, "--json")
			}
			root.SetArgs(args)
			require.ErrorContains(t, root.Execute(), "pcap failed")
			assert.Empty(t, stdout.String())
			assert.NotContains(t, stderr.String(), "Usage:")
			if asJSON {
				var result map[string]string
				require.NoError(t, json.Unmarshal(stderr.Bytes(), &result))
				assert.Equal(t, "unable to list network interfaces: pcap failed", result["error"])
			} else {
				assert.Contains(t, stderr.String(), "pcap failed")
			}
		})
	}
}

func TestInterfacesEmptyAndMetadataWarnings(t *testing.T) {
	for _, args := range [][]string{nil, {"--json"}, {"--names"}} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := newInterfacesCommand(func() (capture.InterfaceDiscovery, error) {
				return capture.InterfaceDiscovery{Warnings: []string{"route lookup failed"}}, nil
			}, nil)
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(args)
			require.NoError(t, cmd.Execute())
			if len(args) > 0 && args[0] == "--json" {
				assert.Empty(t, stderr.String())
				assert.Contains(t, stdout.String(), `"interfaces":[]`)
				assert.Contains(t, stdout.String(), `"warnings":["route lookup failed"]`)
			} else {
				assert.Contains(t, stderr.String(), "route lookup failed")
				if len(args) == 0 {
					assert.Contains(t, stdout.String(), "No network capture interfaces found.")
				} else {
					assert.Empty(t, stdout.String())
				}
			}
		})
	}
}

func TestInterfacesTableEscapesControlsAndPreservesZeroPrefix(t *testing.T) {
	prefix := 0
	var out bytes.Buffer
	err := writeInterfacesTable(&out, InterfacesOutput{Interfaces: []InterfaceInfo{{
		CaptureInterface: capture.CaptureInterface{Name: "eth0", Type: "Ethernet", State: "up", Addresses: []capture.InterfaceAddress{{IP: "0.0.0.0", PrefixLen: &prefix}}},
		CaptureAccess:    "unavailable", CaptureError: "bad\nrow\t\x1b[31m\u202e",
	}}}, true)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "0.0.0.0/0")
	assert.Equal(t, 2, strings.Count(out.String(), "\n"))
	assert.NotContains(t, out.String(), "\x1b")
	assert.NotContains(t, out.String(), "\u202e")
}

type failingInterfaceWriter struct{}

func (failingInterfaceWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestInterfacesOutputFailure(t *testing.T) {
	cmd := newInterfacesCommand(func() (capture.InterfaceDiscovery, error) { return interfaceFixture(), nil }, nil)
	cmd.SetOut(failingInterfaceWriter{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})
	require.ErrorContains(t, cmd.Execute(), "broken pipe")
}

func TestInterfacesTableWrapsAddressesWithoutLosingMetadata(t *testing.T) {
	prefix := 64
	addresses := []capture.InterfaceAddress{
		{IP: "2001:db8:1234:5678:abcd:ef01:2345:6789", PrefixLen: &prefix},
		{IP: "2001:db8:1234:5678:abcd:ef01:2345:6790", PrefixLen: &prefix},
	}
	var out bytes.Buffer
	require.NoError(t, writeInterfacesTable(&out, InterfacesOutput{Interfaces: []InterfaceInfo{{
		CaptureInterface: capture.CaptureInterface{Name: "eth0", Type: "Ethernet", State: "up", Addresses: addresses, DefaultRoute: true},
		CaptureAccess:    "available",
	}}}, true))
	assert.Equal(t, 3, strings.Count(out.String(), "\n"), "header, interface, and continuation row")
	for _, address := range addresses {
		assert.Contains(t, out.String(), address.IP+"/64")
	}
	assert.Equal(t, 1, strings.Count(out.String(), "eth0"))
	assert.Contains(t, out.String(), "default route")
	assert.Contains(t, out.String(), "available")
}
