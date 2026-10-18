//go:build all

package hunter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/hunter/packetforwarding"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// The receiver runs real source registration, mTLS, custody and signed receipts.
// Its processing worker is deliberately not started: encrypted accepted batches
// remain inspectable in the durable custody store after the source shuts down.
type capturePolicyReceiver struct {
	management.UnimplementedFilterPolicyServiceServer
	mu      sync.Mutex
	current *management.SignedPolicySnapshot
	updates chan *management.SignedPolicySnapshot
}

func (s *capturePolicyReceiver) GetSnapshot(context.Context, *management.PolicySnapshotRequest) (*management.SignedPolicySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.Clone(s.current).(*management.SignedPolicySnapshot), nil
}
func (s *capturePolicyReceiver) SubscribeSnapshots(_ *management.PolicySnapshotRequest, stream grpc.ServerStreamingServer[management.SignedPolicySnapshot]) error {
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case next := <-s.updates:
			if err := stream.Send(next); err != nil {
				return err
			}
		}
	}
}
func (s *capturePolicyReceiver) publish(next *management.SignedPolicySnapshot) {
	s.mu.Lock()
	s.current = next
	s.mu.Unlock()
	s.updates <- next
}

type heldSIPHandler struct {
	handler *voip.HunterForwardHandler
	entered chan pipeline.SourceProvenance
	release chan struct{}
	done    chan struct{}
}

func (h *heldSIPHandler) HandleSIPMessage(message []byte, callID, src, dst string, nf, tf gopacket.Flow) bool {
	return h.handler.HandleSIPMessage(message, callID, src, dst, nf, tf)
}
func (h *heldSIPHandler) HandleParsedSIPMessageFromSource(message []byte, event sip.Event, src, dst string, nf, tf gopacket.Flow, source pipeline.SourceProvenance) bool {
	if event.CallID == "held-tcp" {
		h.entered <- source
		<-h.release
		defer close(h.done)
	}
	return h.handler.HandleParsedSIPMessageFromSource(message, event, src, dst, nf, tf, source)
}

type reliableVoIPBoundaryFixture struct {
	h            *Hunter
	buffers      *voip.BufferManager
	tracker      *voip.CallTracker
	held         *heldSIPHandler
	policy       *capturePolicyReceiver
	verifier     *filterpolicy.Verifier
	signer       crypto.Signer
	policyConfig filterpolicy.Config
	store        packetreceipt.StoreConfig
	origin       string
	cancel       context.CancelFunc
	stopped      bool
	done         chan error
	server       *grpc.Server
	receiver     *processor.Processor
}

func captureBoundaryKey(t *testing.T, dir, id string) securestore.KeyConfig {
	t.Helper()
	key := make([]byte, securestore.KeyBytes)
	_, err := rand.Read(key)
	require.NoError(t, err)
	file := filepath.Join(dir, id+".key")
	require.NoError(t, os.WriteFile(file, key, 0600))
	clear(key)
	return securestore.KeyConfig{Active: securestore.KeyRef{ID: id, File: file}}
}
func (f *reliableVoIPBoundaryFixture) signed(t *testing.T, revision, filterRevision uint64, pattern string, until time.Time) *management.SignedPolicySnapshot {
	t.Helper()
	signed, err := f.verifier.SignSnapshot(f.signer, &management.PolicySnapshot{ProtocolVersion: 1, Domain: f.policyConfig.Domain, AuthorityId: f.policyConfig.AuthorityID, OwnerKind: "li", Revision: revision, Filters: []*management.Filter{{Id: "li-original-task-0", Type: management.FilterType_FILTER_SIP_USER, Pattern: pattern, Enabled: true, Revision: filterRevision}}, CaptureAuthority: []byte("original-task-authorization"), ValidFromNs: time.Now().Add(-time.Minute).UnixNano(), ValidUntilNs: until.UnixNano(), AllowOfflineCapture: true, SourceIds: []string{"edge"}})
	require.NoError(t, err)
	return signed
}
func newReliableVoIPBoundaryFixture(t *testing.T, configure ...func(*reliableVoIPBoundaryFixture, *grpc.Server, *Config)) *reliableVoIPBoundaryFixture {
	t.Helper()
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	policyConfig, signer := policyfixture.Config(t)
	policyConfig.Owner = "li"
	policyConfig = policyfixture.Encrypted(t, policyConfig)
	verifier, err := filterpolicy.NewVerifier(policyConfig)
	require.NoError(t, err)
	f := &reliableVoIPBoundaryFixture{verifier: verifier, signer: signer, policyConfig: policyConfig}
	f.policy = &capturePolicyReceiver{current: f.signed(t, 1, 1, "alice", time.Now().Add(time.Minute)), updates: make(chan *management.SignedPolicySnapshot, 4)}
	keyDir := t.TempDir()
	f.origin = filepath.Join(t.TempDir(), "origin")
	delivery := packetforwarding.Config{DeliveryProfile: "reliable", AckScope: "receiver", DestinationID: "receiver", TrustedCert: certificate, Spool: packetforwarding.SpoolConfig{Directory: f.origin, Protection: "encrypted", Keys: captureBoundaryKey(t, keyDir, "origin"), MaxBytes: 1 << 20, MaxRecords: 32}}
	spoolConfig, err := delivery.SpoolConfig("edge")
	require.NoError(t, err)
	require.NoError(t, packetspool.Initialize(spoolConfig))
	f.store = packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "receiver", Protection: "encrypted", Keys: captureBoundaryKey(t, keyDir, "custody"), MaxBytes: 1 << 20, MaxRecordBytes: 16384, MaxSessions: 4, MaxRecords: 32, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(f.store))
	f.receiver, err = processor.New(processor.Config{ProcessorID: "receiver", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(t.TempDir(), "filters", "filters.yaml"), TLSEnabled: true, TLSClientAuth: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, PacketCustody: processor.PacketCustodyConfig{Enabled: true, Store: f.store, AuthorityID: "receiver", SigningCertificate: certificate, SigningKey: key}})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.server = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterManagementServiceServer(f.server, f.receiver)
	data.RegisterReliablePacketServiceServer(f.server, f.receiver)
	management.RegisterFilterPolicyServiceServer(f.server, f.policy)
	serverDone := make(chan error, 1)
	policyConfig.SigningKeyFile = ""
	hunterConfig := Config{HunterID: "edge", Processors: []failover.Endpoint{{Address: listener.Addr().String()}}, Failover: failover.Config{AttemptTimeout: time.Second, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}, BufferSize: 32, BatchSize: 1, BatchTimeout: 10 * time.Millisecond, TLSEnabled: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, NoFilterPolicy: "deny", ForwardMode: "packets", VoIPMode: true, VoIPSignallingPolicy: "matched", VoIPMediaPolicy: "local", SupportedFilterTypes: []string{"sip_user"}, FilterPolicy: policyConfig, Packets: delivery}
	for _, setup := range configure {
		setup(f, f.server, &hunterConfig)
	}
	f.h, err = New(hunterConfig)
	require.NoError(t, err)
	go func() { serverDone <- f.server.Serve(listener) }()
	cfg := voip.DefaultConfig()
	f.tracker = voip.NewCallTrackerWithConfig(cfg)
	f.buffers = voip.NewBufferManager(time.Minute, 100)
	handler := voip.NewHunterForwardHandler(f.tracker, f.h, f.buffers)
	f.held = &heldSIPHandler{handler: handler, entered: make(chan pipeline.SourceProvenance, 1), release: make(chan struct{}), done: make(chan struct{})}
	factoryCtx, stopFactory := context.WithCancel(context.Background())
	factory := voip.NewSipStreamFactoryWithConfig(factoryCtx, f.held, *cfg, f.tracker.IsCallActive)
	assembler := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	vp := voip.NewVoIPPacketProcessor(f.tracker, f.h, f.buffers)
	vp.SetTCPHandler(handler)
	vp.SetAssembler(assembler)
	require.NoError(t, vp.SetCapturePolicies(voip.CapturePolicies{Signalling: voip.SignallingPolicy(f.h.config.VoIPSignallingPolicy), Media: voip.MediaPolicy(f.h.config.VoIPMediaPolicy)}, f.h.VoIPMediaResolver()))
	f.h.SetPacketProcessor(vp)
	require.NoError(t, f.h.captureManager.PrepareBuffer())
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.done = make(chan error, 1)
	go func() { f.done <- f.h.Start(ctx) }()
	t.Cleanup(func() {
		if !f.stopped {
			f.cancel()
			require.NoError(t, <-f.done)
		}
		select {
		case <-f.held.release:
		default:
			close(f.held.release)
		}
		stopFactory()
		require.NoError(t, assembler.Close())
		require.NoError(t, factory.Shutdown())
		vp.Close()
		f.buffers.Close()
		f.tracker.Shutdown()
		require.NoError(t, f.h.Close())
		f.server.Stop()
		require.NoError(t, <-serverDone)
		require.NoError(t, f.receiver.Shutdown())
	})
	require.Eventually(t, func() bool { return f.h.filterManager.PolicyRevision() == 1 }, 5*time.Second, 5*time.Millisecond)
	return f
}
func (f *reliableVoIPBoundaryFixture) send(t *testing.T, packet capture.PacketInfo) {
	t.Helper()
	require.True(t, f.h.captureManager.GetPacketBuffer().Send(packet))
}
func (f *reliableVoIPBoundaryFixture) waitAck(t *testing.T, sequence uint64) {
	t.Helper()
	require.Eventually(t, func() bool {
		s := f.h.packetSpool.Status()
		return s.PendingRecords == 0 && s.AckedSequence == sequence
	}, 5*time.Second, 5*time.Millisecond)
}
func boundarySIP(callID string, sdp bool) []byte {
	body := ""
	content := ""
	if sdp {
		body = "v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\ns=call\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 45000 RTP/AVP 0\r\n"
		content = "Content-Type: application/sdp\r\n"
	}
	return []byte(fmt.Sprintf("INVITE sip:bob@example.test SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-%s\r\nFrom: <sip:alice@example.test>;tag=alice-tag\r\nTo: <sip:bob@example.test>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n%sContent-Length: %d\r\n\r\n%s", callID, callID, content, len(body), body))
}
func boundaryPacket(t *testing.T, payload []byte, tcp bool, srcPort uint16) capture.PacketInfo {
	return boundaryTransportPacket(t, payload, tcp, srcPort, 5060)
}
func boundaryTransportPacket(t *testing.T, payload []byte, tcp bool, srcPort, dstPort uint16) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), Protocol: layers.IPProtocolUDP}
	var transport gopacket.SerializableLayer
	if tcp {
		ip.Protocol = layers.IPProtocolTCP
		p := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: 1, ACK: true, PSH: true, Window: 65535}
		require.NoError(t, p.SetNetworkLayerForChecksum(ip))
		transport = p
	} else {
		p := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
		require.NoError(t, p.SetNetworkLayerForChecksum(ip))
		transport = p
	}
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(b.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b.Bytes()), Length: len(b.Bytes())}
	return capture.PacketInfo{Packet: packet, Interface: "protected-interface", LinkType: layers.LinkTypeEthernet}
}
func assertEncryptedCaptureFiles(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		require.False(t, bytes.Contains(b, []byte("alice@example.test")), "capture plaintext in %s", path)
		return nil
	}))
}

func TestLIOwnedReliableVoIPCaptureExpiresBeforeBufferedRelease(t *testing.T) {
	f := newReliableVoIPBoundaryFixture(t)
	original := boundaryPacket(t, boundarySIP("accepted-udp", true), false, 5060)
	f.send(t, original)
	f.waitAck(t, 1)
	f.send(t, boundaryPacket(t, boundarySIP("accepted-tcp", true), true, 5070))
	f.waitAck(t, 2)
	// A short signed renewal creates the actual authorization expiry exercised by
	// the fixture. The filter and selected task are unchanged by this renewal.
	renewal := f.signed(t, 2, 1, "alice", time.Now().Add(1500*time.Millisecond))
	f.policy.publish(renewal)
	require.Eventually(t, func() bool { return f.h.filterManager.PolicyRevision() == 2 }, 5*time.Second, 5*time.Millisecond)
	f.send(t, boundaryPacket(t, boundarySIP("buffered-udp", false), false, 5060))
	require.Eventually(t, func() bool { return f.buffers.GetBufferCount() > 0 }, time.Second, 5*time.Millisecond)
	f.send(t, boundaryPacket(t, boundarySIP("held-tcp", true), true, 5080))
	select {
	case source := <-f.held.entered:
		require.NotZero(t, source.CapturePolicyGeneration)
		require.Equal(t, "protected-interface", source.InterfaceName)
	case <-time.After(5 * time.Second):
		t.Fatal("TCP framing did not deliver held message")
	}
	require.Eventually(t, func() bool { return !f.h.filterManager.CaptureAllowed(time.Now()) }, 5*time.Second, 5*time.Millisecond)
	close(f.held.release)
	select {
	case <-f.held.done:
	case <-time.After(time.Second):
		t.Fatal("expired TCP handler did not return")
	}
	require.False(t, f.buffers.IsCallMatched("held-tcp"), "expired asynchronous SIP must not mutate sticky selection")
	released := 0
	f.buffers.CheckFilterWithCallback("buffered-udp", func(*voip.CallMetadata) bool { return true }, func(_ string, packets []gopacket.Packet, _ *voip.CallMetadata, iface string, link layers.LinkType) {
		for _, p := range packets {
			released++
			require.ErrorContains(t, f.h.ForwardPacketWithFilterProvenance(p, nil, iface, link, []string{"li-original-task-0"}, nil), "capture authority")
		}
	})
	require.Equal(t, 1, released)
	// Fresh packets and delayed callbacks are both fail closed after the lease.
	f.send(t, boundaryPacket(t, boundarySIP("after-expiry", true), false, 5060))
	f.cancel()
	require.NoError(t, <-f.done)
	f.stopped = true
	require.Equal(t, uint64(2), f.h.packetSpool.Status().LastSequence)
	require.NoError(t, f.h.Close())
	f.server.Stop()
	require.NoError(t, f.receiver.Shutdown())
	custody, err := packetreceipt.Open(f.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	for _, entry := range pending {
		require.Equal(t, "edge", entry.Batch.HunterId)
		require.Len(t, entry.Batch.Packets, 1)
		require.Equal(t, "protected-interface", entry.Batch.Packets[0].InterfaceName)
		require.NotEmpty(t, entry.Batch.SignedCapturePolicy)
		var token management.SignedPolicySnapshot
		require.NoError(t, proto.Unmarshal(entry.Batch.SignedCapturePolicy, &token))
		require.Equal(t, uint64(1), token.Snapshot.Revision)
		require.NotContains(t, string(entry.Batch.Packets[0].Data), "held-tcp")
		require.NotContains(t, string(entry.Batch.Packets[0].Data), "buffered-udp")
	}
	assertEncryptedCaptureFiles(t, f.origin)
	assertEncryptedCaptureFiles(t, f.store.Directory)
}

func TestLIOwnedReliableVoIPFilterReplacementCannotAdoptOldCall(t *testing.T) {
	f := newReliableVoIPBoundaryFixture(t)
	f.send(t, boundaryPacket(t, boundarySIP("old-alice-call", true), false, 5060))
	f.waitAck(t, 1)
	media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4}
	f.send(t, boundaryTransportPacket(t, media, false, 45000, 40000))
	f.waitAck(t, 2)
	f.send(t, boundaryPacket(t, boundarySIP("held-tcp", true), true, 5080))
	select {
	case <-f.held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("TCP framing did not deliver held message")
	}
	// The ID is deliberately reused; its changed semantic revision revokes the
	// former identity proof even though the signed capture lease remains valid.
	replacement := f.signed(t, 2, 2, "mallory", time.Now().Add(time.Minute))
	f.policy.publish(replacement)
	require.Eventually(t, func() bool { return f.h.filterManager.PolicyRevision() == 2 }, 5*time.Second, 5*time.Millisecond)
	close(f.held.release)
	select {
	case <-f.held.done:
	case <-time.After(time.Second):
		t.Fatal("stale TCP handler did not return")
	}
	require.False(t, f.buffers.IsCallMatched("held-tcp"), "old source generation must not establish fresh local selection")
	f.send(t, boundaryTransportPacket(t, media, false, 45000, 40000))
	require.Eventually(t, func() bool { return f.h.captureManager.GetPacketBuffer().Snapshot().TotalLength() == 0 }, time.Second, 5*time.Millisecond)
	require.NoError(t, f.h.packetProducer.WithCaptureBoundary(func() error { return nil }))
	require.Equal(t, uint64(2), f.h.packetSpool.Status().LastSequence, "a fresh capture stamp cannot adopt obsolete same-ID selection")
	current := bytes.ReplaceAll(boundarySIP("new-mallory-call", true), []byte("alice"), []byte("mallory"))
	f.send(t, boundaryPacket(t, current, false, 5060))
	f.waitAck(t, 3)
	f.cancel()
	require.NoError(t, <-f.done)
	f.stopped = true
	require.NoError(t, f.h.Close())
	f.server.Stop()
	require.NoError(t, f.receiver.Shutdown())
	custody, err := packetreceipt.Open(f.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 3)
	revisions := map[uint64]int{}
	for _, entry := range pending {
		var token management.SignedPolicySnapshot
		require.NoError(t, proto.Unmarshal(entry.Batch.SignedCapturePolicy, &token))
		revisions[token.Snapshot.Revision]++
		for _, packet := range entry.Batch.Packets {
			require.NotContains(t, string(packet.Data), "held-tcp")
			if token.Snapshot.Revision == 2 {
				require.True(t, strings.Contains(string(packet.Data), "mallory@example.test"), "replacement may contain only current selected identity")
			}
		}
	}
	require.Equal(t, map[uint64]int{1: 2, 2: 1}, revisions)
}

// Exercise the normal UDP SDP-release callback as well as the explicit delayed
// callback used in the expiry fixture. A policy renewal cannot relabel an older
// buffered INVITE with the new policy merely because its filter still matches.
func TestLIOwnedReliableVoIPUDPReleasePreservesOriginalPolicyBoundary(t *testing.T) {
	f := newReliableVoIPBoundaryFixture(t)
	f.send(t, boundaryPacket(t, boundarySIP("buffered-renewal", false), false, 5060))
	require.Eventually(t, func() bool { return f.buffers.GetBufferCount() == 1 }, time.Second, 5*time.Millisecond)
	require.Zero(t, f.h.packetSpool.Status().LastSequence)
	renewal := f.signed(t, 2, 1, "alice", time.Now().Add(time.Minute))
	f.policy.publish(renewal)
	require.Eventually(t, func() bool { return f.h.filterManager.PolicyRevision() == 2 }, 5*time.Second, 5*time.Millisecond)
	response := bytes.Replace(boundarySIP("buffered-renewal", true), []byte("INVITE sip:bob@example.test SIP/2.0"), []byte("SIP/2.0 200 OK"), 1)
	response = bytes.Replace(response, []byte("To: <sip:bob@example.test>"), []byte("To: <sip:bob@example.test>;tag=bob-tag"), 1)
	f.send(t, boundaryPacket(t, response, false, 5060))
	f.waitAck(t, 1)
	f.cancel()
	require.NoError(t, <-f.done)
	f.stopped = true
	require.NoError(t, f.h.Close())
	f.server.Stop()
	require.NoError(t, f.receiver.Shutdown())
	custody, err := packetreceipt.Open(f.store)
	require.NoError(t, err)
	defer func() { require.NoError(t, custody.Close()) }()
	pending, err := custody.Pending(32)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Len(t, pending[0].Batch.Packets, 1)
	packet := gopacket.NewPacket(pending[0].Batch.Packets[0].Data, layers.LinkTypeEthernet, gopacket.Default)
	require.True(t, bytes.HasPrefix(packet.TransportLayer().LayerPayload(), []byte("SIP/2.0 200 OK")), "the original buffered INVITE must not inherit the renewed capture generation")
	var token management.SignedPolicySnapshot
	require.NoError(t, proto.Unmarshal(pending[0].Batch.SignedCapturePolicy, &token))
	require.Equal(t, uint64(2), token.Snapshot.Revision)
}
