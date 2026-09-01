package source

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// phase4BenchmarkFilter models a populated identity-filter set while recording
// the LocalSource routing boundary. Full matching scans the synthetic identities;
// packet-level matching only checks the protocol-neutral IP condition.
type phase4BenchmarkFilter struct {
	identities       [][]byte
	sipOnlyFull      bool
	matcherCalls     atomic.Uint64
	identityWork     atomic.Uint64
	packetLevelCalls atomic.Uint64
}

func newPhase4BenchmarkFilter() *phase4BenchmarkFilter {
	identities := make([][]byte, 500)
	for i := range identities {
		identities[i] = []byte(fmt.Sprintf("synthetic-user-%03d@example.invalid", i))
	}
	return &phase4BenchmarkFilter{identities: identities}
}

func (f *phase4BenchmarkFilter) MatchPacket(packet gopacket.Packet) bool {
	matched, _ := f.MatchPacketWithIDs(packet)
	return matched
}

func (f *phase4BenchmarkFilter) MatchPacketWithIDs(packet gopacket.Packet) (bool, []string) {
	f.matcherCalls.Add(1)
	if f.sipOnlyFull && !hasCredibleSIPStartLine(packet) {
		return false, nil
	}
	f.identityWork.Add(1)
	payload := phase0PacketPayload(packet)
	for i, identity := range f.identities {
		if bytes.Contains(payload, identity) {
			return true, []string{fmt.Sprintf("identity-%03d", i)}
		}
	}
	if f.sipOnlyFull {
		// Let the VoIP processor learn unmatched SDP calls without supplying an
		// inherited filter ID to LocalSource.
		return true, nil
	}
	return false, nil
}

func (f *phase4BenchmarkFilter) MatchPacketLevelWithIDs(packet gopacket.Packet) (bool, []string) {
	f.packetLevelCalls.Add(1)
	if network := packet.NetworkLayer(); network != nil {
		src, _ := network.NetworkFlow().Endpoints()
		if bytes.Equal(src.Raw(), net.IPv4(192, 0, 2, 30).To4()) {
			return true, []string{"direct-ip"}
		}
	}
	return false, nil
}

// BenchmarkLocalSourceMixedVoIP exercises detection, VoIP call association,
// direct and inherited selection, packet conversion, normalization, and batch
// production. It intentionally excludes capture-device I/O and downstream
// processor sinks. The 100-packet cycle is 92 percent classified RTP and
// includes selected and unselected calls plus direct packet-level matches.
func BenchmarkLocalSourceMixedVoIP(b *testing.B) {
	filter := newPhase4BenchmarkFilter()
	processorFilter := newPhase4BenchmarkFilter()
	processorFilter.sipOnlyFull = true
	packets := phase4MixedVoIPPackets(b)

	cfg := DefaultLocalSourceConfig()
	cfg.BatchSize = 256
	cfg.BatchTimeout = time.Hour
	cfg.BatchBuffer = 4
	s := NewLocalSource(cfg)
	procCfg := voipprocessor.DefaultConfig()
	procCfg.ApplicationFilter = processorFilter
	procCfg.NeedFilterIDs = true
	proc := voipprocessor.New(procCfg)
	b.Cleanup(proc.Close)
	s.voipProcessor = voipprocessor.NewSourceAdapter(proc)
	s.appFilter = filter
	s.ctx = context.Background()

	input := make(chan capture.PacketInfo, 1024)
	done := make(chan struct{})
	go func() {
		s.batchingWorkerWithInjection(input, false)
		close(done)
	}()
	drained := make(chan struct{})
	go func() {
		for batch := range s.Batches() {
			batch.RunAfterProcess()
		}
		close(drained)
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input <- packets[i%len(packets)]
	}
	close(input)
	<-done
	b.StopTimer()
	s.sendBatch()
	close(s.batches)
	<-drained

	elapsed := b.Elapsed().Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "packets/s")
	}
	full := filter.matcherCalls.Load()
	media := filter.packetLevelCalls.Load()
	processorMatcher := processorFilter.matcherCalls.Load()
	processorIdentityWork := processorFilter.identityWork.Load()
	b.ReportMetric(float64(full)/float64(b.N), "full_calls/op")
	b.ReportMetric(float64(media)/float64(b.N), "packet_level_calls/op")
	b.ReportMetric(float64(processorMatcher)/float64(b.N), "processor_matcher_calls/op")
	b.ReportMetric(float64(processorIdentityWork)/float64(b.N), "processor_identity_work/op")
	expectedMedia := uint64(b.N / len(packets) * 92)
	expectedProcessorMatcher := uint64(b.N / len(packets) * 8)
	remainder := b.N % len(packets)
	if remainder > 3 {
		expectedMedia += uint64(min(remainder, 95) - 3)
	}
	expectedProcessorMatcher += uint64(min(remainder, 3))
	if remainder > 95 {
		expectedProcessorMatcher += uint64(remainder - 95)
	}
	if full != 0 || media != expectedMedia {
		b.Fatalf("LocalSource matcher routing: full=%d packet-level=%d, want full=0 packet-level=%d", full, media, expectedMedia)
	}
	if processorMatcher != expectedProcessorMatcher || processorIdentityWork != expectedProcessorMatcher {
		b.Fatalf("processor SIP matcher routing: calls=%d identity_work=%d, want %d", processorMatcher, processorIdentityWork, expectedProcessorMatcher)
	}
}

func phase4MixedVoIPPackets(tb testing.TB) []capture.PacketInfo {
	tb.Helper()
	packets := make([]capture.PacketInfo, 0, 100)
	packets = append(packets,
		phase4UDPPacket(tb, "192.0.2.10", 5060, 5060, phase4SIPInvite("selected", "synthetic-user-000@example.invalid", "192.0.2.10", 20000)),
		phase4UDPPacket(tb, "192.0.2.11", 5060, 5060, phase4SIPInvite("unselected", "unmatched@example.invalid", "192.0.2.11", 21000)),
		phase4UDPPacket(tb, "192.0.2.30", 5060, 5060, phase4SIPInvite("direct-only", "direct@example.invalid", "192.0.2.30", 22000)),
	)
	for i := 0; i < 92; i++ {
		srcIP, srcPort, dstPort, ssrc := "192.0.2.10", layers.UDPPort(20000), layers.UDPPort(30000), byte(0x10)
		switch {
		case i >= 79:
			srcIP, srcPort, dstPort, ssrc = "192.0.2.30", 22000, 32000, 0x30
		case i >= 50:
			srcIP, srcPort, dstPort, ssrc = "192.0.2.11", 21000, 31000, 0x20
		}
		payload := append([]byte(nil), phase0RTPPayload()...)
		payload[3] = byte(i)
		payload[11] = ssrc
		packets = append(packets, phase4UDPPacket(tb, srcIP, srcPort, dstPort, payload))
	}
	for i := 0; i < 5; i++ {
		payload := []byte(fmt.Sprintf("OPTIONS sip:service@example.invalid SIP/2.0\r\nFrom: <sip:control-%d@example.invalid>\r\nTo: <sip:service@example.invalid>\r\nCall-ID: control-%d@example.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", i, i))
		packets = append(packets, phase4UDPPacket(tb, "192.0.2.20", 5060, 5060, payload))
	}
	return packets
}

func phase4SIPInvite(callID, identity, mediaIP string, mediaPort int) []byte {
	return []byte(fmt.Sprintf("INVITE sip:service@example.invalid SIP/2.0\r\nFrom: <sip:%s>\r\nTo: <sip:service@example.invalid>\r\nCall-ID: %s@example.invalid\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\nv=0\r\no=- 1 1 IN IP4 %s\r\ns=Synthetic call\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio %d RTP/AVP 0\r\n", identity, callID, mediaIP, mediaIP, mediaPort))
}

func phase4UDPPacket(tb testing.TB, srcIP string, srcPort, dstPort layers.UDPPort, payload []byte) capture.PacketInfo {
	tb.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.IPv4(198, 51, 100, 20)}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		tb.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		tb.Fatal(err)
	}
	return capture.PacketInfo{Packet: gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default), LinkType: layers.LinkTypeEthernet, Interface: "synthetic0"}
}
