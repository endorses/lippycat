//go:build all

package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"crypto/tls"
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	edge "github.com/endorses/lippycat/internal/pkg/hunter"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type diagnosticContext struct {
	Request    string `json:"request"`
	Activation uint64 `json:"activation"`
}

func diagnosticCaptureAdapter(id string) core.Adapter {
	return core.Adapter{ID: id, Version: 1, Validate: func(binding core.Binding) error {
		var context diagnosticContext
		if json.Unmarshal(binding.Context, &context) != nil || context.Request == "" || context.Activation == 0 {
			return core.ErrInvalid
		}
		canonical, err := json.Marshal(context)
		if err != nil || !bytes.Equal(canonical, binding.Context) || binding.Subject.ID != context.Request || binding.Subject.Incarnation != strconv.FormatUint(context.Activation, 10) || len(binding.Intents) != 1 || binding.Intents[0].ID != "diagnostic/"+context.Request {
			return core.ErrInvalid
		}
		return nil
	}, Authorize: func(binding core.Binding) error {
		if binding.Intents[0].Revision != 1 {
			return core.ErrInvalid
		}
		return nil
	}}
}

func diagnosticEngine(t *testing.T, sourceID string) core.Config {
	t.Helper()
	registry, err := core.NewRegistry(diagnosticCaptureAdapter("diagnostic"), diagnosticCaptureAdapter("service"))
	require.NoError(t, err)
	return core.Config{ProcessorID: "central", HunterID: sourceID, Domains: []core.DomainID{7}, MaxRules: 8, MaxBytes: 1 << 20, MaxEndpoints: 16, MaxEndpointsPerRule: 4, MaxSubscribers: 4, SubscriptionBuffer: 8, MaxLifetime: time.Minute, Registry: registry}
}

func diagnosticBinding(t *testing.T, adapter, id, sourceID string, selectors ...core.Selector) core.Binding {
	t.Helper()
	context, err := json.Marshal(diagnosticContext{Request: id, Activation: 1})
	require.NoError(t, err)
	now := time.Now()
	return core.Binding{ID: adapter + "/" + id, Revision: 1, AdapterID: adapter, ContextVersion: 1, Subject: core.Subject{ID: id, Incarnation: "1"}, AttributionContext: adapter + "/requests", Intents: []core.IntentRef{{ID: "diagnostic/" + id, Revision: 1}}, Scope: []core.Scope{{HunterID: sourceID, Domain: 7}}, Selectors: selectors, Context: context, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Second)}
}

func diagnosticFrame(t *testing.T, ipv6, tcp bool, sourcePort, destinationPort uint16, marker byte) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	protocol := layers.IPProtocolUDP
	if tcp {
		protocol = layers.IPProtocolTCP
	}
	var network gopacket.NetworkLayer
	var serialized gopacket.SerializableLayer
	if ipv6 {
		ethernet.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"), NextHeader: protocol}
		network, serialized = ip, ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), Protocol: protocol}
		network, serialized = ip, ip
	}
	var transport gopacket.SerializableLayer
	if tcp {
		p := &layers.TCP{SrcPort: layers.TCPPort(sourcePort), DstPort: layers.TCPPort(destinationPort), ACK: true, PSH: true, Seq: 1, Window: 4096}
		require.NoError(t, p.SetNetworkLayerForChecksum(network))
		transport = p
	} else {
		p := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
		require.NoError(t, p.SetNetworkLayerForChecksum(network))
		transport = p
	}
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, serialized, transport, gopacket.Payload([]byte{marker, 'd', 'i', 'a', 'g'})))
	return b.Bytes()
}

// gatedLearnedInterface uses a generated PCAP through an actual libpcap handle;
// capture installs its real preceding BPF before the producer sees any packets.
type gatedLearnedInterface struct {
	ready  <-chan struct{}
	path   string
	mu     sync.Mutex
	handle *pcap.Handle
	open   func() (*pcap.Handle, error)
}

func (i *gatedLearnedInterface) Name() string { return "capture0" }
func (i *gatedLearnedInterface) SetHandle() error {
	<-i.ready
	var handle *pcap.Handle
	var err error
	if i.open != nil {
		handle, err = i.open()
	} else {
		handle, err = pcap.OpenOffline(i.path)
	}
	i.mu.Lock()
	i.handle = handle
	i.mu.Unlock()
	return err
}
func (i *gatedLearnedInterface) Handle() (*pcap.Handle, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.handle, nil
}

func diagnosticPCAP(t *testing.T, frames ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "generated.pcap")
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, raw := range frames {
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	require.NoError(t, file.Close())
	return path
}

func readDiagnosticPCAP(t *testing.T, path string) [][]byte {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var frames [][]byte
	for {
		raw, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		frames = append(frames, raw)
	}
	return frames
}

func TestDiagnosticAdapterActualRemoteHunterAndOrdinaryOutput(t *testing.T) {
	pki := newRelayTestPKI(t)
	_, certificate, key := pki.identity(t, "central")
	_, edgeCertificate, edgeKey := pki.identity(t, "edge")
	output := filepath.Join(t.TempDir(), "received.pcap")
	engine := diagnosticEngine(t, "")
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", WriteFile: output, TLSEnabled: true, TLSClientAuth: true, TLSCertFile: certificate, TLSKeyFile: key, TLSCAFile: pki.caFile, LearnedRules: &LearnedRulesConfig{Engine: engine, Sources: []LearnedSourceMapping{{SourceID: "edge", Interface: "capture0", Domain: 7}}}})
	require.NoError(t, err)
	udp := core.Selector{Domain: 7, Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP, Direction: core.Destination}
	tcp := core.Selector{Domain: 7, Address: netip.MustParseAddr("2001:db8::2"), Port: 45001, Protocol: core.TCP, Direction: core.Destination}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{diagnosticBinding(t, "diagnostic", "request-a", "edge", udp, tcp)}))
	require.NoError(t, p.PublishLearnedBindings("service", []core.Binding{diagnosticBinding(t, "service", "service-b", "edge", udp)}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	pair, err := tls.LoadX509KeyPair(edgeCertificate, edgeKey)
	require.NoError(t, err)
	connection, err := grpc.NewClient(p.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool, ServerName: "central"})))
	require.NoError(t, err)
	defer func() { require.NoError(t, connection.Close()) }()
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	defer stopMonitor()
	monitor, err := data.NewDataServiceClient(connection).SubscribePackets(monitorCtx, &data.SubscribeRequest{ClientId: "diagnostic-test"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return p.subscriberManager.Count() == 1 }, 5*time.Second, time.Millisecond)
	sourceRuntime, err := core.NewRuntime(diagnosticEngine(t, "edge"), map[string]core.DomainID{"capture0": 7}, 8, nil)
	require.NoError(t, err)
	ready := make(chan struct{})
	var releaseOnce sync.Once
	releaseCapture := func() { releaseOnce.Do(func() { close(ready) }) }
	first, second := diagnosticFrame(t, false, false, 40000, 45000, 1), diagnosticFrame(t, true, true, 40000, 45001, 2)
	input := diagnosticPCAP(t, first, second, diagnosticFrame(t, false, false, 45000, 40000, 3), diagnosticFrame(t, false, true, 40000, 45000, 4))
	h, err := edge.New(edge.Config{HunterID: "edge", ProcessorAddr: p.ListenAddr(), LearnedRuntime: sourceRuntime, TLSEnabled: true, TLSCertFile: edgeCertificate, TLSKeyFile: edgeKey, TLSCAFile: pki.caFile, TLSServerNameOverride: "central", NoFilterPolicy: "deny", BatchSize: 1, BatchTimeout: 10 * time.Millisecond, BufferSize: 16, CaptureInterfaces: func() []pcaptypes.PcapInterface {
		return []pcaptypes.PcapInterface{&gatedLearnedInterface{ready: ready, path: input}}
	}})
	require.NoError(t, err)
	hctx, hcancel := context.WithCancel(ctx)
	hdone := make(chan error, 1)
	go func() { hdone <- h.Start(hctx) }()
	t.Cleanup(func() { releaseCapture(); hcancel(); require.NoError(t, <-hdone); require.NoError(t, h.Close()) })
	require.Eventually(t, func() bool {
		application := p.LearnedRuleApplication("edge")
		return application != nil && application.Synchronized && application.ActiveBindings == 2
	}, 5*time.Second, time.Millisecond)
	releaseCapture()
	var received []*data.CapturedPacket
	for len(received) < 2 {
		batch, err := monitor.Recv()
		require.NoError(t, err)
		received = append(received, batch.Packets...)
	}
	require.Len(t, received[0].LearnedCaptureEvidence.Candidates, 2)
	require.Len(t, received[1].LearnedCaptureEvidence.Candidates, 1)
	for _, packet := range received {
		require.Empty(t, packet.CaptureSelectionProof)
		require.Empty(t, packet.InheritedMatchedFilterIds)
		require.Empty(t, packet.MatchedFilterIds)
		if packet.Metadata != nil {
			require.Nil(t, packet.Metadata.Sip)
		}
	}
	require.Equal(t, first, received[0].Data)
	require.Equal(t, second, received[1].Data)
	require.Eventually(t, func() bool { return p.GetStats().TotalPacketsReceived == 2 }, time.Second, time.Millisecond)
	hcancel()
	require.NoError(t, <-hdone)
	hdone <- nil
	stopMonitor()
	cancel()
	require.NoError(t, <-done)
	done <- nil
	frames := readDiagnosticPCAP(t, output)
	require.Equal(t, [][]byte{first, second}, frames)
}

type denyDiagnosticFilter struct{}

func (denyDiagnosticFilter) MatchPacket(gopacket.Packet) bool                    { return false }
func (denyDiagnosticFilter) MatchPacketWithIDs(gopacket.Packet) (bool, []string) { return false, nil }
func (denyDiagnosticFilter) MatchPacketLevelWithIDs(gopacket.Packet) (bool, []string) {
	return false, nil
}

func TestDiagnosticAdapterActualLocalTapAndOrdinaryOutput(t *testing.T) {
	pki := newRelayTestPKI(t)
	_, certificate, key := pki.identity(t, "central")
	pair, _, _ := pki.identity(t, "monitor")
	output := filepath.Join(t.TempDir(), "local-output.pcap")
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", WriteFile: output, TLSEnabled: true, TLSClientAuth: true, TLSCertFile: certificate, TLSKeyFile: key, TLSCAFile: pki.caFile, LearnedRules: &LearnedRulesConfig{Engine: diagnosticEngine(t, ""), Sources: []LearnedSourceMapping{{SourceID: "central-local", Interface: "capture0", Domain: 7}}}})
	require.NoError(t, err)
	udp := core.Selector{Domain: 7, Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP, Direction: core.Destination}
	tcp := core.Selector{Domain: 7, Address: netip.MustParseAddr("2001:db8::2"), Port: 45001, Protocol: core.TCP, Direction: core.Destination}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{diagnosticBinding(t, "diagnostic", "local-request", "central-local", udp, tcp)}))
	require.NoError(t, p.PublishLearnedBindings("service", []core.Binding{diagnosticBinding(t, "service", "local-service", "central-local", udp)}))
	runtime, err := core.NewRuntime(diagnosticEngine(t, "central-local"), map[string]core.DomainID{"capture0": 7}, 8, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, runtime.Store.Close()) }()
	subscription, err := p.SubscribeLocalLearnedRules()
	require.NoError(t, err)
	localControl, err := captureadapter.StartLocalSubscription(t.Context(), runtime, subscription)
	require.NoError(t, err)
	defer func() { require.NoError(t, localControl.Close()) }()
	first, second := diagnosticFrame(t, false, false, 40000, 45000, 11), diagnosticFrame(t, true, true, 40000, 45001, 12)
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	stream := pcapgo.NewWriter(writer)
	require.NoError(t, stream.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, raw := range [][]byte{first, second, diagnosticFrame(t, false, true, 40000, 45000, 13)} {
		require.NoError(t, stream.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	var closeWriter sync.Once
	finishInput := func() { closeWriter.Do(func() { require.NoError(t, writer.Close()) }) }
	t.Cleanup(func() {
		err := reader.Close()
		if err != nil && !errors.Is(err, syscall.EBADF) && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close transferred pcap reader: %v", err)
		}
	})
	ready := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ready) }) }
	local := source.NewLocalSource(source.LocalSourceConfig{ProcessorID: "central", ProtocolMode: "generic", Interfaces: []string{"capture0"}, BatchSize: 1, BatchTimeout: 10 * time.Millisecond, CaptureInterfaces: func() []pcaptypes.PcapInterface {
		return []pcaptypes.PcapInterface{&gatedLearnedInterface{ready: ready, open: func() (*pcap.Handle, error) { return pcap.OpenOfflineFile(reader) }}}
	}})
	local.SetApplicationFilter(denyDiagnosticFilter{})
	require.NoError(t, local.SetLearnedRuntime(runtime, nil))
	p.SetPacketSource(local)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()
	t.Cleanup(func() { release(); cancel(); finishInput(); require.NoError(t, <-done) })
	require.Eventually(t, func() bool { return p.ListenAddr() != "" }, 5*time.Second, time.Millisecond)
	connection, err := grpc.NewClient(p.ListenAddr(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool, ServerName: "central"})))
	require.NoError(t, err)
	defer func() { require.NoError(t, connection.Close()) }()
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	defer stopMonitor()
	monitor, err := data.NewDataServiceClient(connection).SubscribePackets(monitorCtx, &data.SubscribeRequest{ClientId: "local-diagnostic-test"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return p.subscriberManager.Count() == 1 }, 5*time.Second, time.Millisecond)
	release()
	var received []*data.CapturedPacket
	for len(received) < 2 {
		batch, err := monitor.Recv()
		require.NoError(t, err)
		require.Equal(t, "central-local", batch.HunterId)
		received = append(received, batch.Packets...)
	}
	require.Equal(t, "generic", local.GetProtocolMode())
	byData := make(map[string]*data.CapturedPacket)
	for _, packet := range received {
		byData[string(packet.Data)] = packet
	}
	require.NotNil(t, byData[string(first)])
	require.NotNil(t, byData[string(second)])
	require.Len(t, byData[string(first)].LearnedCaptureEvidence.Candidates, 2)
	require.Len(t, byData[string(second)].LearnedCaptureEvidence.Candidates, 1)
	for _, packet := range received {
		require.Empty(t, packet.InheritedMatchedFilterIds)
		require.Empty(t, packet.CaptureSelectionProof)
		if packet.Metadata != nil {
			require.Nil(t, packet.Metadata.Sip)
		}
	}
	require.ElementsMatch(t, [][]byte{first, second}, [][]byte{received[0].Data, received[1].Data})
	require.NoError(t, localControl.Close())
	stopMonitor()
	cancel()
	finishInput()
	require.NoError(t, <-done)
	done <- nil
	require.ElementsMatch(t, [][]byte{first, second}, readDiagnosticPCAP(t, output))
}

func TestLearnedPublicationRejectsUnknownSourceDomainPlacement(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", LearnedRules: &LearnedRulesConfig{Engine: diagnosticEngine(t, ""), Sources: []LearnedSourceMapping{{SourceID: "edge", Interface: "capture0", Domain: 7}}}})
	require.NoError(t, err)
	endpoint := core.Selector{Domain: 7, Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP}
	binding := diagnosticBinding(t, "diagnostic", "request", "unmapped", endpoint)
	require.ErrorIs(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}), core.ErrScope)
	require.Zero(t, p.LearnedRulesStatus().Rules)
	binding.Scope[0].HunterID = "edge"
	binding.Scope[0].Domain = 8
	binding.Selectors[0].Domain = 8
	require.ErrorIs(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}), core.ErrScope)
	require.Zero(t, p.LearnedRulesStatus().Rules)
	binding.Scope[0].Domain = 7
	binding.Selectors[0].Domain = 7
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}))
	require.Equal(t, 1, p.LearnedRulesStatus().Rules)
}

func TestUnresolvedVoIPCandidateCannotBorrowDiagnosticAttribution(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", LearnedRules: &LearnedRulesConfig{Engine: diagnosticEngine(t, ""), Sources: []LearnedSourceMapping{{SourceID: "edge", Interface: "capture0", Domain: 7}}}})
	require.NoError(t, err)
	endpoint := core.Selector{Domain: 7, Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{diagnosticBinding(t, "diagnostic", "request", "edge", endpoint)}))
	runtime, err := core.NewRuntime(diagnosticEngine(t, "edge"), map[string]core.DomainID{"capture0": 7}, 8, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, runtime.Store.Close()) }()
	subscription, err := p.SubscribeLocalLearnedRules()
	require.NoError(t, err)
	local, err := captureadapter.StartLocalSubscription(t.Context(), runtime, subscription)
	require.NoError(t, err)
	defer func() { require.NoError(t, local.Close()) }()
	frame := diagnosticFrame(t, false, false, 40000, 45000, 22)
	packet, err := grpcadapter.FromCapturedPacket(&data.CapturedPacket{Data: frame, TimestampNs: time.Now().UnixNano(), CaptureLength: uint32(len(frame)), OriginalLength: uint32(len(frame)), LinkType: uint32(layers.LinkTypeEthernet), InterfaceName: "capture0"}, pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: "edge"})
	require.NoError(t, err)
	selected, err := captureadapter.Select(runtime, packet)
	require.NoError(t, err)
	require.True(t, selected)
	unresolved := core.Binding{ID: "missing-voip-binding", Revision: 1, Session: p.LearnedRulesSession(), AdapterID: "voip", ContextVersion: 1, Subject: core.Subject{ID: "forged-call", Incarnation: "old-lifetime"}, AttributionContext: "voip-media"}
	packet.LearnedCaptureEvidence.Candidates = append(packet.LearnedCaptureEvidence.Candidates, wire.Candidate(unresolved))
	captured := proto.Clone(packet.LearnedCaptureEvidence)
	packet.InheritedMatchedFilterIDs = []string{"stale-inherited"}
	packet.MatchedFilterIDs = []string{"stale-inherited"}
	packet.Metadata, err = grpcadapter.MetadataFromProto(&data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "forged-call"}, Rtp: &data.RTPMetadata{Ssrc: 42}})
	require.NoError(t, err)
	batch := &source.PacketBatch{SourceID: "edge", MediaSourceTrusted: true, Envelopes: []*pipeline.PacketEnvelope{packet}}
	p.validateLearnedBatch(batch)
	require.Len(t, batch.Envelopes, 1, "independent diagnostic capture remains eligible")
	require.True(t, packet.CallLifecycleRejected)
	require.Empty(t, packet.InheritedMatchedFilterIDs)
	require.Empty(t, packet.MatchedFilterIDs)
	require.True(t, proto.Equal(captured, packet.LearnedCaptureEvidence), "unresolved references remain immutable forensic evidence")
	raw, err := grpcadapter.ToCapturedPacket(packet)
	require.NoError(t, err)
	require.Nil(t, raw.Metadata.Sip, "diagnostic permission cannot validate claimed call identity")
	// The same evidence without current independent intent cannot select capture.
	require.NoError(t, p.PublishLearnedBindings("diagnostic", nil))
	p.validateLearnedBatch(batch)
	require.Empty(t, batch.Envelopes)
}

func TestGenericAndLocalSubscriptionSweepExpiredBindings(t *testing.T) {
	engine := diagnosticEngine(t, "")
	engine.MaxLifetime = 30 * time.Millisecond
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", LearnedRules: &LearnedRulesConfig{Engine: engine, Sources: []LearnedSourceMapping{{SourceID: "central-local", Interface: "capture0", Domain: 7}}}})
	require.NoError(t, err)
	endpoint := core.Selector{Domain: 7, Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP}
	binding := diagnosticBinding(t, "diagnostic", "short-request", "central-local", endpoint)
	binding.NotBefore = time.Now().Add(-time.Millisecond)
	binding.ExpiresAt = time.Now().Add(15 * time.Millisecond)
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}))
	sourceConfig := engine
	sourceConfig.HunterID = "central-local"
	runtime, err := core.NewRuntime(sourceConfig, map[string]core.DomainID{"capture0": 7}, 8, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, runtime.Store.Close()) }()
	subscription, err := p.SubscribeLocalLearnedRules()
	require.NoError(t, err)
	local, err := captureadapter.StartLocalSubscription(t.Context(), runtime, subscription)
	require.NoError(t, err)
	defer func() { require.NoError(t, local.Close()) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.startLearnedControl(ctx)
	require.Eventually(t, func() bool { return p.LearnedRulesStatus().Rules == 0 && runtime.Store.Status().Rules == 0 }, time.Second, time.Millisecond)
	require.EqualValues(t, 1, p.LearnedRulesStatus().Expired)
}

func TestLearnedVoIPIngressResolvesAllOwnersInActualSourceRealm(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", ProcessorID: "central", MediaRules: MediaRulesConfig{
		Settings: mediarules.Settings{Enabled: true},
		Sources: []MediaSourceMapping{
			{HunterID: "hunter-a", Interface: "capture0", Domain: 10, HunterDomain: 1},
			{HunterID: "hunter-b", Interface: "capture0", Domain: 20, HunterDomain: 1},
		},
	}})
	require.NoError(t, err)
	_, err = p.updateManagedFilter(&management.Filter{Id: "selected-alice", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	learnCall := func(node, callID string) {
		for _, payload := range [][]byte{
			centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-"+callID, 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n"),
			centralMessage("SIP/2.0 200 OK", "bob-tag", "z9hG4bK-"+callID, 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 50000 RTP/AVP 0\r\n"),
		} {
			payload = []byte(strings.ReplaceAll(string(payload), "continuity@example.invalid", callID))
			p.processMediaControl(&source.PacketBatch{SourceID: node, MediaSourceTrusted: true, Envelopes: []*pipeline.PacketEnvelope{centralEnvelope(t, node, payload, false)}})
		}
	}
	learnCall("hunter-a", "call-a")
	learnCall("hunter-b", "call-b")
	require.Len(t, p.mediaControl.tracker.Snapshot(), 2, "separate central observation realms keep independent calls")
	output := p.subscriberManager.Add("source-scoped-output")
	defer p.subscriberManager.Remove("source-scoped-output")
	packetFor := func(node, callID string) *pipeline.PacketEnvelope {
		packet := centralEnvelope(t, node, []byte{0x80, 0, 0, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 2, 3}, true)
		packet.Source.ObservationDomain, packet.Source.ObservationDomainKnown = 1, true
		for _, binding := range p.learnedRuleStore().ActiveRules() {
			if binding.Subject.ID == callID && p.learnedRuleStore().InScopeForSource(binding, node, 1) {
				packet.LearnedCaptureEvidence = &learnedevidence.LearnedCaptureEvidence{Version: wire.EvidenceVersion, Candidates: []*learnedevidence.LearnedCandidate{wire.Candidate(binding)}}
				break
			}
		}
		require.NotNil(t, packet.LearnedCaptureEvidence)
		return packet
	}
	for _, expected := range []struct{ node, callID string }{{"hunter-a", "call-a"}, {"hunter-b", "call-b"}} {
		packet := packetFor(expected.node, expected.callID)
		centralObserve(p, packet, true)
		require.False(t, packet.CallLifecycleRejected)
		require.Equal(t, []string{"selected-alice"}, packet.InheritedMatchedFilterIDs)
		select {
		case batch := <-output:
			require.Len(t, batch.Packets, 1)
			require.Equal(t, expected.node, batch.HunterId)
			require.Equal(t, expected.callID, batch.Packets[0].Metadata.Sip.CallId)
			require.Equal(t, packet.Data, batch.Packets[0].Data)
		case <-time.After(time.Second):
			t.Fatal("source-scoped typed ingress did not reach ordinary output")
		}
	}
	learnCall("hunter-a", "another-call-a")
	// Evidence intentionally contains only the original call. Every authoritative
	// eligible owner must still participate in attribution, preventing a subset
	// of supplied references from concealing actual ambiguity at source A.
	ambiguous := packetFor("hunter-a", "call-a")
	centralObserve(p, ambiguous, true)
	require.True(t, ambiguous.CallLifecycleRejected)
	require.Empty(t, ambiguous.InheritedMatchedFilterIDs)
	select {
	case batch := <-output:
		require.Len(t, batch.Packets, 1)
		if batch.Packets[0].Metadata != nil {
			require.Nil(t, batch.Packets[0].Metadata.Sip)
		}
		require.NotNil(t, batch.Packets[0].LearnedCaptureEvidence, "ambiguous capture remains forensic raw output")
	case <-time.After(time.Second):
		t.Fatal("ambiguous forensic capture did not reach ordinary output")
	}
}
