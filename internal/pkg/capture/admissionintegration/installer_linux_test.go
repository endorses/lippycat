//go:build linux

package admissionintegration

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/ebpfadmission"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// This is a real socket/libpcap test, separate from BPF_PROG_TEST_RUN. Explicit
// opt-in makes unavailable privilege/support a failure instead of a false pass.
func TestLiveSocketAdmissionLifecycle(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: requires privileged isolated Linux network; set LIPPYCAT_EBPF_TEST=1")
	}
	ctx := t.Context()
	leftName, rightName := fmt.Sprintf("ea%d", os.Getpid()), fmt.Sprintf("eb%d", os.Getpid())
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: leftName}, PeerName: rightName}))
	left, err := netlink.LinkByName(leftName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, netlink.LinkDel(left)) })
	right, err := netlink.LinkByName(rightName)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(left))
	require.NoError(t, netlink.LinkSetUp(right))
	iface := pcaptypes.CreateLiveInterface(leftName)
	require.NoError(t, iface.(interface{ ConfigureSocketAdmission() error }).ConfigureSocketAdmission())
	require.NoError(t, iface.SetHandle())
	handle, err := iface.Handle()
	require.NoError(t, err)
	t.Cleanup(handle.Close)
	require.Equal(t, layers.LinkTypeEthernet, handle.LinkType())
	sender, err := pcap.OpenLive(rightName, 65535, false, 50*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(sender.Close)
	backend, err := ebpfadmission.NewBackend(ebpfadmission.Options{EndpointCapacity: 8, SelectorCapacity: 8, Domains: 2, EvidenceBytes: 4096})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })
	installer, err := NewInstaller(backend, map[string]mediaadmission.DomainID{"unused": 1}, 2*time.Second)
	require.NoError(t, err)
	frame := func(port uint16, marker string) []byte {
		eth := &layers.Ethernet{SrcMAC: right.Attrs().HardwareAddr, DstMAC: left.Attrs().HardwareAddr, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1").AsSlice(), DstIP: netip.MustParseAddr("192.0.2.2").AsSlice()}
		udp := &layers.UDP{SrcPort: 4000, DstPort: layers.UDPPort(port)}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		payload := append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)))
		return buf.Bytes()
	}
	// Queue a packet while capture still has no socket filter. Prepare must drain
	// it before declaring the handle safe to activate.
	require.NoError(t, sender.WritePacketData(frame(5000, "startup")))
	attachment, err := installer.Prepare(ctx, handle, leftName, "udp and not port 53")
	require.NoError(t, err)
	t.Cleanup(func() { handle.Close(); require.NoError(t, attachment.Close()) })
	shortDrain, cancelDrain := context.WithTimeout(ctx, time.Second)
	cancelDrain()
	require.ErrorIs(t, handle.DrainSocketBuffer(shortDrain), context.Canceled)
	cancelDrain()
	require.GreaterOrEqual(t, attachment.(interface{ StartupDiscards() uint64 }).StartupDiscards(), uint64(1))
	require.NoError(t, attachment.Activate())
	program := attachment.(*preparedFilter).program
	programFD := program.FD()
	readMarker := func(marker string, want bool) {
		t.Helper()
		deadline := time.Now().Add(450 * time.Millisecond)
		found := false
		for time.Now().Before(deadline) {
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			require.NoError(t, err)
			if bytes.Contains(data, []byte(marker)) {
				found = true
				break
			}
		}
		require.Equal(t, want, found, "marker %s", marker)
	}
	readMarker("startup", false)
	require.NoError(t, sender.WritePacketData(frame(5000, "unselected")))
	readMarker("unselected", false)
	endpoint, err := mediaadmission.NewEndpoint(0, netip.MustParseAddr("192.0.2.2"), 5000)
	require.NoError(t, err)
	require.NoError(t, backend.PutEndpoint(ctx, endpoint))
	require.NoError(t, sender.WritePacketData(frame(5000, "selected")))
	readMarker("selected", true)
	require.NoError(t, backend.DeleteEndpoint(ctx, endpoint))
	require.NoError(t, sender.WritePacketData(frame(5000, "removed")))
	readMarker("removed", false)
	require.NoError(t, backend.SetControl(ctx, 0, mediaadmission.Control{Mode: mediaadmission.KernelOpen, Generation: 1}))
	require.NoError(t, sender.WritePacketData(frame(5000, "open")))
	readMarker("open", true)
	require.NoError(t, sender.WritePacketData(frame(53, "restricted")))
	readMarker("restricted", false)
	require.Equal(t, programFD, program.FD(), "endpoint changes must retain the same program")
	require.ErrorContains(t, handle.SetBPFFilter("udp"), "cannot replace")
	stats, err := handle.Stats()
	require.NoError(t, err)
	require.Greater(t, stats.PacketsReceived, 0)
	require.NoError(t, attachment.Close())
	require.ErrorContains(t, attachment.Activate(), "closed")
	handle.Close()

	// Recreate a socket against the same maps. A selected endpoint must survive
	// genuine handle recreation, and the new socket's nondefault snapshot
	// length must truncate accepted packets without changing their wire length.
	require.NoError(t, backend.SetControl(ctx, 0, mediaadmission.Control{Mode: mediaadmission.KernelEnforce, Generation: 2}))
	require.NoError(t, backend.PutEndpoint(ctx, endpoint))
	inactive, err := pcap.NewInactiveHandle(leftName)
	require.NoError(t, err)
	defer inactive.CleanUp()
	require.NoError(t, inactive.SetSnapLen(96))
	require.NoError(t, inactive.SetTimeout(50*time.Millisecond))
	require.NoError(t, inactive.SetImmediateMode(true))
	replacement, err := inactive.Activate()
	require.NoError(t, err)
	t.Cleanup(replacement.Close)
	replacementAttachment, err := installer.Prepare(ctx, replacement, leftName, "udp and not port 53")
	require.NoError(t, err)
	t.Cleanup(func() { replacement.Close(); require.NoError(t, replacementAttachment.Close()) })
	require.NoError(t, replacementAttachment.Activate())
	wire := append(frame(5000, "reattached"), make([]byte, 256)...)
	require.NoError(t, sender.WritePacketData(wire))
	deadline := time.Now().Add(time.Second)
	for {
		data, info, err := replacement.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired && time.Now().Before(deadline) {
			continue
		}
		require.NoError(t, err)
		if !bytes.Contains(data, []byte("reattached")) {
			require.True(t, time.Now().Before(deadline), "replacement did not admit retained endpoint")
			continue
		}
		require.Equal(t, replacement.SnapLen(), len(data))
		require.Equal(t, 96, info.CaptureLength)
		require.Equal(t, len(wire), info.Length)
		break
	}
}

func TestInstallerRejectsInvalidConstruction(t *testing.T) {
	_, err := NewInstaller(nil, nil, time.Second)
	require.Error(t, err)
	_, err = NewInstaller(&ebpfadmission.Backend{}, nil, 0)
	require.Error(t, err)
}

// The timeout is required so a broken startup filter cannot make preparation
// hang forever. This verifies the binding enforces that contract before C access.
func TestDrainRequiresDeadline(t *testing.T) {
	require.ErrorContains(t, (&pcap.Handle{}).DrainSocketBuffer(context.Background()), "bounded context")
}
