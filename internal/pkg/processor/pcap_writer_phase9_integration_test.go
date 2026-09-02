//go:build processor || tap || all

package processor

import (
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase9IdleFinalizationCleansEndpointAndSuppressesResurrection(t *testing.T) {
	manager := newPhase8Manager(t, nil)
	voip := voipprocessor.New(voipprocessor.Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(voip.Close)
	monitor := NewCallCompletionMonitor(nil, nil, manager)
	monitor.SetVoIPPortCleaner(voip)

	const (
		callID   = "idle-end-to-end"
		endpoint = "192.0.2.20:12000"
	)
	voip.AssociateEndpoint(callID, endpoint)
	require.Equal(t, []string{callID}, voip.CallIDsForEndpoint(endpoint))
	require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("original"), layers.LinkTypeEthernet, false))

	manager.mu.RLock()
	writer := manager.writers[callID]
	manager.mu.RUnlock()
	require.NotNil(t, writer)
	writer.mu.Lock()
	writer.lastWrite = time.Now().Add(-time.Hour)
	writer.mu.Unlock()

	require.Equal(t, 1, manager.SweepIdle(time.Minute))
	assert.True(t, manager.IsFinalized(callID), "idle finalization must record a tombstone")
	assert.Empty(t, voip.CallIDsForEndpoint(endpoint), "idle finalization must remove media endpoint mappings")
	assert.Equal(t, uint64(1), manager.Telemetry().IdleFinalizations)

	err := manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, true)
	assert.True(t, IsCallFinalized(err), "a late packet must not resurrect an idle-finalized writer")
	manager.mu.RLock()
	_, live := manager.writers[callID]
	manager.mu.RUnlock()
	assert.False(t, live)
}

func TestPhase9CompletedEndpointCanBeReusedOnlyByGenuinelyNewCall(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled:      true,
		OutputDir:    dir,
		FilePattern:  "{callid}.pcap",
		SyncInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	voip := voipprocessor.New(voipprocessor.Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(voip.Close)
	monitor := NewCallCompletionMonitor(nil, nil, manager)
	monitor.SetVoIPPortCleaner(voip)

	const (
		oldCallID = "completed-old-call"
		newCallID = "genuinely-new-call"
		endpoint  = "192.0.2.30:13000"
	)
	oldPacket := phase9RTPPacket(t, net.ParseIP("198.51.100.1"), net.ParseIP("192.0.2.30"), 24000, 13000)
	voip.AssociateEndpoint(oldCallID, endpoint)
	require.NoError(t, manager.WritePacket(oldCallID, "alice", "bob", time.Now(), oldPacket.Data(), layers.LinkTypeEthernet, true))
	result, err := manager.FinalizeCall(oldCallID, CallFinalizationProtocolComplete)
	require.NoError(t, err)
	require.True(t, result.Finalized)
	require.Empty(t, voip.CallIDsForEndpoint(endpoint))

	oldPath := filepath.Join(dir, oldCallID+"_rtp.pcap")
	oldBytes, err := os.ReadFile(oldPath)
	require.NoError(t, err)
	oldHash := sha256.Sum256(oldBytes)

	voip.AssociateEndpoint(newCallID, endpoint)
	require.Equal(t, []string{newCallID}, voip.CallIDsForEndpoint(endpoint))
	newPacket := phase9RTPPacket(t, net.ParseIP("198.51.100.2"), net.ParseIP("192.0.2.30"), 24002, 13000)
	resolved := voip.Process(newPacket)
	require.NotNil(t, resolved)
	assert.Equal(t, newCallID, resolved.CallID)
	assert.Equal(t, []string{newCallID}, resolved.CallIDs)

	require.NoError(t, manager.WritePacket(resolved.CallID, "carol", "dave", time.Now(), newPacket.Data(), layers.LinkTypeEthernet, true))
	require.NoError(t, manager.CloseCallWriter(newCallID))
	after, err := os.ReadFile(oldPath)
	require.NoError(t, err)
	assert.Equal(t, oldBytes, after, "traffic for the new call must not mutate the old artifact")
	assert.Equal(t, oldHash, sha256.Sum256(after))
	_, err = os.Stat(filepath.Join(dir, newCallID+"_rtp.pcap"))
	assert.NoError(t, err, "endpoint reuse must write a distinct new-call artifact")
}

func phase9RTPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp,
		gopacket.Payload([]byte{0x80, 0x00, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 1})))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
