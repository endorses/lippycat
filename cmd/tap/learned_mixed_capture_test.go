//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// The stream keeps libpcap's actual preceding filter installed while test-owned
// packets are generated. Its independent descriptor is closed by libpcap.
type mixedTapInterface struct {
	reader *os.File
	handle *pcap.Handle
}

func (i *mixedTapInterface) Name() string { return "capture0" }
func (i *mixedTapInterface) SetHandle() error {
	var err error
	i.handle, err = pcap.OpenOffline(fmt.Sprintf("/dev/fd/%d", i.reader.Fd()))
	return err
}
func (i *mixedTapInterface) Handle() (*pcap.Handle, error) { return i.handle, nil }

type mixedTapMonitor struct {
	grpc.ServerStream
	ctx     context.Context
	ready   chan struct{}
	once    sync.Once
	packets chan *data.CapturedPacket
}

func (s *mixedTapMonitor) Context() context.Context {
	s.once.Do(func() { close(s.ready) })
	return s.ctx
}
func (s *mixedTapMonitor) Send(batch *data.PacketBatch) error {
	for _, packet := range batch.Packets {
		select {
		case s.packets <- proto.Clone(packet).(*data.CapturedPacket):
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
	return nil
}

func mixedTapUDP(t *testing.T, sourcePort, destinationPort uint16, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	return buffer.Bytes()
}

func TestMixedLearnedAdaptersUseActualVoIPTapCaptureAndOutput(t *testing.T) {
	adapter := core.Adapter{ID: "diagnostic", Version: 1, Validate: func(b core.Binding) error {
		if string(b.Context) != "diagnostic.v1" {
			return core.ErrInvalid
		}
		return nil
	}, Authorize: func(b core.Binding) error {
		if len(b.Intents) != 1 || b.Intents[0].ID != "diagnostic-request" {
			return core.ErrAuthority
		}
		return nil
	}}
	dir := filepath.Join(t.TempDir(), "managed")
	require.NoError(t, os.Mkdir(dir, 0700))
	p, err := processor.New(processor.Config{ProcessorID: "tap", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(dir, "filters.yaml"), LearnedAdapters: []core.Adapter{adapter}, MediaRules: processor.MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []processor.MediaSourceMapping{{HunterID: "tap-local", Interface: "capture0", Domain: 1, HunterDomain: 1}}}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	_, err = p.UpdateFilter(t.Context(), &management.Filter{Id: "selected-call", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	now := time.Now()
	diagnostic := core.Binding{ID: "diagnostic", Session: p.LearnedRulesSession(), Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: "device-inspection", Incarnation: "one"}, AttributionContext: "diagnostic", Intents: []core.IntentRef{{ID: "diagnostic-request", Revision: 1}}, Context: []byte("diagnostic.v1"), Scope: []core.Scope{{HunterID: "tap-local", Domain: 1}}, NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	for _, port := range []uint16{40000, 42000} {
		diagnostic.Selectors = append(diagnostic.Selectors, core.Selector{Domain: 1, Address: netip.MustParseAddr("192.0.2.1"), Port: port, Protocol: core.UDP})
	}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{diagnostic}))
	rules, err := newTapMediaRules(p, p.MediaRuleConfiguration(), map[string]mediaadmission.DomainID{"capture0": 1}, nil)
	require.NoError(t, err)
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	fixture := &mixedTapInterface{reader: reader}
	frames := pcapgo.NewWriterNanos(writer)
	require.NoError(t, frames.WriteFileHeader(65535, layers.LinkTypeRaw))
	local := source.NewLocalSource(source.LocalSourceConfig{ProcessorID: "tap", Interfaces: []string{"capture0"}, ProtocolMode: "voip", BatchSize: 1, BatchTimeout: time.Millisecond, BufferSize: 16, CaptureInterfaces: func() []pcaptypes.PcapInterface { return []pcaptypes.PcapInterface{fixture} }})
	// This is the same trusted own-transport update performed by tap composition.
	require.NoError(t, local.SetTransportBPFFilter("not (tcp and host 127.0.0.1 and port 55555)"))
	require.NoError(t, local.SetCapturePolicies(voip.CapturePolicies{Signalling: voip.SignallingAll, Media: voip.MediaProcessor}, rules))
	require.NoError(t, configureTapLearnedRuntime(p, local, rules))
	p.SetPacketSource(local)
	ctx, cancel := context.WithCancel(t.Context())
	monitor := &mixedTapMonitor{ctx: ctx, ready: make(chan struct{}), packets: make(chan *data.CapturedPacket, 16)}
	monitorDone := make(chan error, 1)
	go func() { monitorDone <- p.SubscribePackets(&data.SubscribeRequest{ClientId: "mixed-local"}, monitor) }()
	<-monitor.ready
	ruleDone := make(chan error, 1)
	go func() { ruleDone <- rules.Run(ctx) }()
	processorDone := make(chan error, 1)
	go func() { processorDone <- p.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, writer.Close())
		require.NoError(t, <-processorDone)
		require.ErrorIs(t, <-ruleDone, context.Canceled)
		require.NoError(t, <-monitorDone)
		require.NoError(t, reader.Close())
	})
	require.Eventually(t, local.IsStarted, 5*time.Second, time.Millisecond)
	write := func(raw []byte) {
		require.NoError(t, frames.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	sdp := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n"
	invite := []byte(fmt.Sprintf("INVITE sip:bob@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-mixed\r\nFrom: <sip:alice@example.invalid>;tag=alice\r\nTo: <sip:bob@example.invalid>\r\nCall-ID: mixed-call@example.invalid\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(sdp), sdp))
	write(mixedTapUDP(t, 5060, 5060, invite))
	rtp := mixedTapUDP(t, 40000, 50000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2})
	require.Eventually(t, func() bool {
		_, ok := rules.ResolveMedia(gopacket.NewPacket(rtp, layers.LinkTypeRaw, gopacket.Default), "capture0")
		return ok
	}, 5*time.Second, time.Millisecond)
	write(rtp)
	write(mixedTapUDP(t, 42000, 50000, []byte("diagnostic payload")))
	var media, plain *data.CapturedPacket
	deadline := time.After(5 * time.Second)
	for media == nil || plain == nil {
		select {
		case packet := <-monitor.packets:
			decoded := gopacket.NewPacket(packet.Data, layers.LinkType(packet.LinkType), gopacket.Default)
			udp, ok := decoded.TransportLayer().(*layers.UDP)
			if !ok {
				continue
			}
			switch udp.SrcPort {
			case 40000:
				media = packet
			case 42000:
				plain = packet
			}
		case <-deadline:
			t.Fatal("mixed local capture did not reach ordinary monitoring output")
		}
	}
	require.Empty(t, media.CaptureSelectionProof)
	require.Len(t, media.LearnedCaptureEvidence.Candidates, 2)
	require.Equal(t, "mixed-call@example.invalid", media.Metadata.GetSip().GetCallId())
	require.Equal(t, []string{"selected-call"}, media.InheritedMatchedFilterIds)
	require.Len(t, plain.LearnedCaptureEvidence.Candidates, 1)
	require.Equal(t, "diagnostic", plain.LearnedCaptureEvidence.Candidates[0].AdapterId)
	require.Empty(t, plain.Metadata.GetSip().GetCallId(), "diagnostic capture must not invent a call")
	require.Empty(t, plain.InheritedMatchedFilterIds)
	require.Empty(t, plain.MatchedFilterIds, "diagnostic intent is not a filter ID")
}
