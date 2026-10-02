//go:build linux && all

package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var admissionLinkSequence atomic.Uint32

// TestVoIPEBPFCommands exercises real command composition, not a userspace
// substitute for the socket gate. Explicit opt-in means unavailable privilege
// or missing binary is a failure rather than skipped passing evidence.
func TestVoIPEBPFCommands(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf for isolated privileged command tests")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary, "privileged command tests require LIPPYCAT_EBPF_BINARY")
	for _, topology := range []string{"tap", "hunter"} {
		for _, mode := range []string{"enforce", "shadow"} {
			t.Run(topology+"/"+mode, func(t *testing.T) {
				runAdmissionCommandCase(t, binary, topology, mode)
			})
		}
	}
}

func newAdmissionCommandFixture(t *testing.T, binary, topology, mode, settings string, extra ...string) *admissionCommandFixture {
	return newAdmissionCommandFixtureDomains(t, binary, topology, mode, settings, nil, extra...)
}

func newAdmissionCommandFixtureDomains(t *testing.T, binary, topology, mode, settings string, domains []uint32, extra ...string) *admissionCommandFixture {
	t.Helper()
	dir := t.TempDir()
	// Managed filter storage requires a private directory regardless of umask.
	require.NoError(t, os.Chmod(dir, 0700))
	configFile := filepath.Join(dir, "config.yaml")
	filterFile := filepath.Join(dir, "filters.yaml")
	require.NoError(t, os.WriteFile(filterFile, []byte("filters:\n  - id: selected-identity\n    type: sip_user\n    pattern: selected\n    enabled: true\n"), 0600))
	out := filepath.Join(dir, "pcaps")
	require.NoError(t, os.Mkdir(out, 0700))
	captureName, sender := admissionVeth(t)
	interfaces := []string{captureName}
	senders := []func(uint16, uint16, []byte) error{sender}
	if len(domains) > 0 {
		assignments := map[string]uint32{captureName: domains[0]}
		for _, domain := range domains[1:] {
			name, send := admissionVeth(t)
			interfaces = append(interfaces, name)
			senders = append(senders, send)
			assignments[name] = domain
		}
		var config map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(settings), &config))
		if config == nil {
			config = map[string]any{}
		}
		config[topology] = map[string]any{"voip": map[string]any{"rtp_ebpf": map[string]any{"interface_domains": assignments}}}
		contents, err := yaml.Marshal(config)
		require.NoError(t, err)
		settings = string(contents)
	}
	require.NoError(t, os.WriteFile(configFile, []byte(settings), 0600))
	captureName = strings.Join(interfaces, ",")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	common := []string{"--config", configFile}
	var processState *os.ProcessState
	observeExit := func(state *os.ProcessState) { processState = state }
	wireMode := mode
	if mode == "broad" {
		wireMode = "enforce"
		extra = append(extra, "--rtp-ebpf=false")
	}
	var stopCapture, stopProcessor func()
	if topology == "tap" {
		args := append(append([]string{}, common...), "tap", "voip", "--interface", captureName, "--listen", address, "--id", "admission-tap", "--insecure", "--filter-file", filterFile, "--sip-user", "selected", "--per-call-pcap-dir", out, "--rtp-ebpf", "--rtp-ebpf-mode", wireMode, "--sip-port", "5060", "--filter", "udp and not port 53")
		stopCapture = startAdmissionCommandObserved(t, binary, dir, "tap", observeExit, append(args, extra...)...)
	} else {
		args := append(append([]string{}, common...), "process", "--listen", address, "--id", "admission-process", "--insecure", "--filter-file", filterFile, "--per-call-pcap", "--per-call-pcap-dir", out)
		stopProcessor = startAdmissionCommand(t, binary, dir, "processor", args...)
		args = append(append([]string{}, common...), "hunt", "voip", "--interface", captureName, "--processor", address, "--id", "admission-hunter", "--insecure", "--rtp-ebpf", "--rtp-ebpf-mode", wireMode, "--sip-port", "5060", "--filter", "udp and not port 53")
		stopCapture = startAdmissionCommandObserved(t, binary, dir, "hunter", observeExit, append(args, extra...)...)
	}
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	client := management.NewManagementServiceClient(connection)
	status := func() *management.StatusResponse {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		status, err := client.GetHunterStatus(ctx, &management.StatusRequest{})
		if err != nil {
			return nil
		}
		return status
	}
	snapshot := func() *management.MediaAdmissionScope {
		for _, hunter := range status().GetHunters() {
			for _, scope := range hunter.GetStats().GetRtpEbpf().GetScopes() {
				if scope.Domain == 0 {
					return scope
				}
			}
		}
		return nil
	}
	require.Eventually(t, func() bool {
		if mode == "broad" {
			return len(status().GetHunters()) > 0
		}
		scope := snapshot()
		return scope != nil && (scope.State == "enforcing" || scope.State == "shadow")
	}, 20*time.Second, 100*time.Millisecond, "admission readiness/status")
	return &admissionCommandFixture{sender: sender, senders: senders, client: client, snapshot: snapshot, status: status, out: out, processState: &processState, stop: func() {
		stopCapture()
		if stopProcessor != nil {
			stopProcessor()
		}
	}}
}

type admissionCommandFixture struct {
	client       management.ManagementServiceClient
	senders      []func(uint16, uint16, []byte) error
	processState **os.ProcessState
	sender       func(uint16, uint16, []byte) error
	snapshot     func() *management.MediaAdmissionScope
	status       func() *management.StatusResponse
	out          string
	stop         func()
}

func runAdmissionCommandCase(t *testing.T, binary, topology, mode string) {
	f := newAdmissionCommandFixture(t, binary, topology, mode, "{}\n")
	sender, snapshot, out := f.sender, f.snapshot, f.out
	// Use endpoints outside the old automatically generated RTP range. Polling
	// sends SIP retransmissions until confirmed publication, never media history.
	require.Eventually(t, func() bool {
		require.NoError(t, sender(5060, 5060, admissionSIP("selected-call", "selected", 42002)))
		require.NoError(t, sender(5060, 5060, admissionSIP("unselected-call", "unrelated", 43002)))
		scope := snapshot()
		return scope != nil && scope.InstalledEndpoints >= 2 && scope.PendingUpdates == 0
	}, 20*time.Second, 100*time.Millisecond, "selected SDP publication")
	admissionStatus := func() *management.MediaAdmissionStatus {
		for _, hunter := range f.status().GetHunters() {
			if status := hunter.GetStats().GetRtpEbpf(); status.GetEnabled() {
				return status
			}
		}
		return nil
	}
	require.Eventually(t, func() bool { return admissionStatus().GetDiagnosticCalls() > 0 }, 15*time.Second, 100*time.Millisecond, "selected-call diagnostics reach command status")
	before := snapshot()
	require.NotNil(t, before)
	require.Len(t, before.DecisionCounters, 16)
	marker := func(value string) []byte {
		return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(value)...)
	}
	require.NoError(t, sender(42000, 42002, marker("ADMISSION-SELECTED-MEDIA")))
	require.NoError(t, sender(43000, 43002, marker("ADMISSION-UNSELECTED-MEDIA")))
	require.NoError(t, sender(44000, 53, marker("ADMISSION-EXPLICIT-RESTRICTION")))
	require.Eventually(t, func() bool {
		scope := snapshot()
		if scope == nil || len(scope.DecisionCounters) != 16 {
			return false
		}
		// Counters are reasons, not output proof. PCAP assertions below separately
		// verify existing userspace selection in enforce and shadow modes.
		rejection := 0
		if mode == "shadow" {
			rejection = 9
		}
		return scope.DecisionCounters[1] > before.DecisionCounters[1] && scope.DecisionCounters[rejection] > before.DecisionCounters[rejection] && scope.DecisionCounters[12] > before.DecisionCounters[12]
	}, 20*time.Second, 100*time.Millisecond, "kernel selected/unselected/restricted decisions")
	require.Eventually(t, func() bool { return bytes.Contains(readAdmissionPCAPs(t, out), []byte("ADMISSION-SELECTED-MEDIA")) }, 15*time.Second, 100*time.Millisecond, "selected media reaches per-call output")
	require.Eventually(t, func() bool { return admissionStatus().GetAttributedMediaPackets() > 0 }, 15*time.Second, 100*time.Millisecond, "authoritatively attributed media reaches diagnostics")
	f.stop()
	captured := readAdmissionPCAPs(t, out)
	require.Contains(t, string(captured), "ADMISSION-SELECTED-MEDIA")
	require.NotContains(t, string(captured), "ADMISSION-UNSELECTED-MEDIA")
	require.NotContains(t, string(captured), "ADMISSION-EXPLICIT-RESTRICTION")
}

func readAdmissionPCAPs(t *testing.T, root string) []byte {
	t.Helper()
	var data []byte
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".pcap") {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data = append(data, contents...)
		return nil
	}))
	return data
}

func startAdmissionCommand(t *testing.T, binary, dir, name string, args ...string) func() {
	return startAdmissionCommandObserved(t, binary, dir, name, nil, args...)
}

func startAdmissionCommandObserved(t *testing.T, binary, dir, name string, observeExit func(*os.ProcessState), args ...string) func() {
	t.Helper()
	logPath := filepath.Join(dir, name+".log")
	log, err := os.Create(logPath)
	require.NoError(t, err)
	command := exec.Command(binary, args...)
	command.Stdout = log
	command.Stderr = log
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			err := command.Process.Signal(syscall.SIGTERM)
			if err != nil && err != os.ErrProcessDone {
				t.Errorf("stop %s: %v", name, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Logf("%s exited: %v", name, err)
				}
			case <-time.After(15 * time.Second):
				if err := command.Process.Kill(); err != nil {
					t.Errorf("kill %s: %v", name, err)
				}
				<-done
				t.Errorf("%s did not stop after SIGTERM", name)
			}
			if observeExit != nil {
				observeExit(command.ProcessState)
			}
			require.NoError(t, log.Close())
		})
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			contents, err := os.ReadFile(logPath)
			if err != nil {
				t.Log(err)
			} else {
				t.Logf("%s log:\n%s", name, contents)
			}
		}
	})
	return stop
}

func admissionVeth(t *testing.T) (string, func(uint16, uint16, []byte) error) {
	t.Helper()
	seq := admissionLinkSequence.Add(1)
	leftName, rightName := fmt.Sprintf("lc_ea%d", seq), fmt.Sprintf("lc_eb%d", seq)
	require.NoError(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: leftName}, PeerName: rightName}))
	left, err := netlink.LinkByName(leftName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, netlink.LinkDel(left)) })
	right, err := netlink.LinkByName(rightName)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(left))
	require.NoError(t, netlink.LinkSetUp(right))
	handle, err := pcap.OpenLive(rightName, 65535, false, 50*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(handle.Close)
	send := func(src, dst uint16, payload []byte) error {
		eth := &layers.Ethernet{SrcMAC: right.Attrs().HardwareAddr, DstMAC: left.Attrs().HardwareAddr, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
		udp := &layers.UDP{SrcPort: layers.UDPPort(src), DstPort: layers.UDPPort(dst)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			return err
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
			return err
		}
		return handle.WritePacketData(buffer.Bytes())
	}
	return leftName, send
}

func admissionSIP(callID, user string, port uint16) []byte {
	sdp := fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=test\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\n", port)
	return []byte(fmt.Sprintf("INVITE sip:receiver@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-%s\r\nFrom: <sip:%s@example.test>;tag=origin\r\nTo: <sip:receiver@example.test>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", callID, user, callID, len(sdp), sdp))
}
