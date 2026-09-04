//go:build processor || tap || all

package processor

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type phase9IdentityFilter struct{ identity []byte }

func (f phase9IdentityFilter) MatchPacket(packet gopacket.Packet) bool {
	matched, _ := f.MatchPacketWithIDs(packet)
	return matched
}

func (f phase9IdentityFilter) MatchPacketWithIDs(packet gopacket.Packet) (bool, []string) {
	matched := bytes.Contains(packet.ApplicationLayer().Payload(), f.identity)
	if !matched {
		return false, nil
	}
	return true, []string{"identity-filter"}
}

func (f phase9IdentityFilter) MatchPacketLevelWithIDs(packet gopacket.Packet) (bool, []string) {
	return f.MatchPacketWithIDs(packet)
}

func TestPhase9FilteredInviteAndInheritedByeFinalizeSessionOutput(t *testing.T) {
	const (
		callID   = "filtered-phase9-call"
		identity = "+00000000000@ims.example"
		endpoint = "192.0.2.55:16000"
	)
	dir := t.TempDir()
	var completions atomic.Int32
	completed := make(chan struct{})
	var completeOnce sync.Once
	p, err := New(Config{
		ProcessorID: "phase9-e2e",
		ListenAddr:  "127.0.0.1:0",
		MaxHunters:  1,
		PcapWriterConfig: &PcapWriterConfig{
			Enabled:      true,
			OutputDir:    dir,
			FilePattern:  "{callid}.pcap",
			SyncInterval: time.Hour,
			OnCallComplete: func(CallMetadata) {
				completions.Add(1)
				completeOnce.Do(func() { close(completed) })
			},
		},
		CallCompletionMonitorConfig: &CallCompletionMonitorConfig{
			GracePeriod:    time.Nanosecond,
			CheckInterval:  time.Millisecond,
			RTPWaitTimeout: time.Millisecond,
			ClosedCallTTL:  time.Hour,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })

	injections := make(chan source.InjectedPacket, 2)
	cfg := source.DefaultLocalSourceConfig()
	cfg.BatchSize = 1
	cfg.BatchTimeout = time.Millisecond
	local := source.NewLocalSource(cfg)
	registry := voipprocessor.New(voipprocessor.Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(registry.Close)
	adapter := voipprocessor.NewSourceAdapter(registry)
	local.SetVoIPProcessor(adapter)
	local.SetApplicationFilter(phase9IdentityFilter{identity: []byte(identity)})
	local.SetTCPInjectionChannel(injections)
	p.SetPacketSource(local)
	p.sessionOutputManager.SetVoIPPortCleaner(adapter)
	p.sessionOutputManager.Start()

	ctx, cancel := context.WithCancel(context.Background())
	sourceDone := make(chan error, 1)
	go func() { sourceDone <- local.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-sourceDone)
	})
	require.Eventually(t, local.IsStarted, time.Second, time.Millisecond)

	invite := phase9TCPSIPPacket(t, "INVITE sip:bob@example.test SIP/2.0\r\n"+
		"From: <sip:"+identity+">;tag=a\r\nTo: <sip:bob@example.test>\r\n"+
		"Call-ID: "+callID+"\r\nCSeq: 1 INVITE\r\nP-Asserted-Identity: <sip:"+identity+">\r\n"+
		"Content-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 192.0.2.55\r\nm=audio 16000 RTP/AVP 0\r\n")
	inviteMetadata := registry.ProcessReassembledSIP(invite.Packet)
	require.NotNil(t, inviteMetadata)
	require.Equal(t, []string{callID}, registry.CallIDsForEndpoint(endpoint))
	injections <- source.InjectedPacket{PacketInfo: invite, Metadata: inviteMetadata}
	inviteBatch := <-local.Batches()
	inviteProto, err := inviteBatch.ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, []string{"identity-filter"}, inviteProto.Packets[0].MatchedFilterIds)
	p.processBatch(inviteBatch)

	bye := phase9TCPSIPPacket(t, "BYE sip:alice@example.test SIP/2.0\r\n"+
		"From: <sip:bob@example.test>;tag=b\r\nTo: <sip:alice@example.test>;tag=a\r\n"+
		"Call-ID: "+callID+"\r\nCSeq: 2 BYE\r\n\r\n")
	byeMetadata := registry.ProcessReassembledSIP(bye.Packet)
	require.NotNil(t, byeMetadata)
	assert.False(t, phase9IdentityFilter{identity: []byte(identity)}.MatchPacket(bye.Packet), "BYE must rely on inherited call selection")
	injections <- source.InjectedPacket{PacketInfo: bye, Metadata: byeMetadata, AfterProcess: func() { registry.CompleteCall(callID) }}
	byeBatch := <-local.Batches()
	byeProto, err := byeBatch.ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, []string{"identity-filter"}, byeProto.Packets[0].MatchedFilterIds,
		"identity-less BYE must inherit the INVITE's selected filter")
	p.processBatch(byeBatch)

	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("filtered BYE did not complete the per-call output lifecycle")
	}
	require.Eventually(t, func() bool { return len(registry.CallIDsForEndpoint(endpoint)) == 0 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(1), completions.Load())
	telemetry := p.sessionOutputManager.Telemetry()
	assert.Zero(t, telemetry.ActiveWriters)
	assert.Equal(t, uint64(1), telemetry.Tombstones)
	assert.Equal(t, uint64(1), telemetry.ProtocolFinalizations, "the writer must finalize exactly once")

	path := filepath.Join(dir, callID+"_sip.pcap")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(24), "INVITE and inherited BYE must reach the session artifact")
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, int32(1), completions.Load(), "terminal lifecycle and monitor polling must not duplicate the hook")
}

func phase9TCPSIPPacket(t *testing.T, payload string) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload([]byte(payload))))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "phase9-test"}
}
