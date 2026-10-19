//go:build (processor || tap || all) && li && linux

package processor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	evidencepb "github.com/endorses/lippycat/api/gen/learnedevidence"
	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// This vertical test uses the protected task owner restored from actual X1 ADMF
// XML, trusted tap-local SIP, the production scoped rule publisher, original
// signed raw ingress, ordinary processor batching and the mutual-TLS MDF reader.
// No manually signed media rule or packet metadata supplies the selected call.
func TestCentralTaskCaptureSourceContinuity(t *testing.T) {
	for _, typed := range []bool{false, true} {
		for _, dedup := range []bool{false, true} {
			t.Run(fmt.Sprintf("typed-%t/dedup-%t", typed, dedup), func(t *testing.T) { centralTaskCaptureSourceContinuity(t, dedup, typed) })
		}
	}
}

func centralTaskCaptureSourceContinuity(t *testing.T, dedup, typed bool) {
	f := newPersistentProcessorFixture(t)
	f.taskDeliveryType, f.destinationDeliveryType = "X2andX3", "X2andX3"
	f.config.LITaskFilterDistributionScope = "local_only"
	f.config.LIDeliveryCaptureSourceMetadata = true
	f.config.PacketDedup = packetdedup.Settings{Enabled: dedup, Window: 50 * time.Millisecond}
	f.config.MediaRules = MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, TrailingGrace: 100 * time.Millisecond, Sources: []MediaSourceMapping{{HunterID: "tap-local", Interface: "capture0", Domain: 7, HunterDomain: 9}, {HunterID: "hunter-a", Interface: "capture0", Domain: 7, HunterDomain: 1}, {HunterID: "hunter-b", Interface: "capture0", Domain: 7, HunterDomain: 2}}}
	f.config.LIHandover = li.HandoverConfig{Enabled: true, LeaseDuration: 2 * time.Second, SourceIDs: []string{"hunter-a", "hunter-b"}}
	policy, _ := policyfixture.Config(t)
	policy.Owner = "li"
	policy.Startup = "local"
	policy = policyfixture.Encrypted(t, policy)
	f.config.FilterPolicy = policy
	f.config.TLSEnabled, f.config.TLSClientAuth = true, true
	f.config.TLSCertFile, f.config.TLSKeyFile, f.config.TLSCAFile = "../../../test/testcerts/li/mdf-server-cert.pem", "../../../test/testcerts/li/mdf-server-key.pem", "../../../test/testcerts/li/ca-cert.pem"
	products := f.listenMDF(t)
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	require.NoError(t, p.startSharedPolicy(context.Background()))
	require.NoError(t, p.publishLIHandoverPolicy(time.Now()))
	signed := p.sharedPolicy.state.Latest()
	require.NotNil(t, signed)
	require.EqualValues(t, 2, signed.Snapshot.ProtocolVersion)
	require.Empty(t, signed.Snapshot.Filters)
	require.Len(t, signed.Snapshot.SelectionGrants, 1)
	policyBytes, err := proto.Marshal(signed)
	require.NoError(t, err)
	require.False(t, bytes.Contains(policyBytes, []byte("alice")), "hunter policy must not expose task target or guessable selector digest")
	require.Empty(t, p.filterManager.GetForHunter("hunter-a"))
	require.Empty(t, p.filterManager.GetForHunter("hunter-b"))
	early := centralEnvelope(t, "hunter-a", []byte{0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 42}, true)
	early.Source.ObservationDomainKnown = true
	early.Source.ObservationDomain = 1
	earlyRaw, err := grpcadapter.ToCapturedPacket(early)
	require.NoError(t, err)
	require.ErrorIs(t, p.validateLICapturePolicy(&data.PacketBatch{HunterId: "hunter-a", SignedCapturePolicy: policyBytes, Packets: []*data.CapturedPacket{earlyRaw}}), li.ErrCaptureAuthority, "media observed before selection has no exact rule authority")
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-selection", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	invite = bytes.ReplaceAll(invite, []byte("alice-tag"), []byte("dialog-left"))
	local := centralEnvelope(t, "tap-local", invite, false)
	local.Source.Kind = pipeline.SourceLiveCapture
	local.Source.ObservationDomainKnown = true
	local.Source.ObservationDomain = 9
	signallingObserved := local.CaptureTime
	centralObserve(p, local, true)
	selectionCompleted := time.Now()
	require.NotEmpty(t, p.mediaControl.store.Snapshot().Rules, "actual local task selection must publish capture rules")
	answer := centralMessage("SIP/2.0 200 OK", "bob-tag", "z9hG4bK-selection", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 50000 RTP/AVP 0\r\n")
	answer = bytes.ReplaceAll(answer, []byte("alice-tag"), []byte("dialog-left"))
	localAnswer := centralEnvelope(t, "tap-local", answer, false)
	localAnswer.Source.Kind = pipeline.SourceLiveCapture
	localAnswer.Source.ObservationDomainKnown = true
	localAnswer.Source.ObservationDomain = 9
	centralObserve(p, localAnswer, true)
	update := centralMessage("UPDATE sip:bob@example.invalid SIP/2.0", "bob-tag", "z9hG4bK-update", 2, "UPDATE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	update = bytes.ReplaceAll(update, []byte("alice-tag"), []byte("dialog-left"))
	update = bytes.ReplaceAll(update, []byte("SIP/2.0/UDP"), []byte("SIP/2.0/TCP"))
	localUpdate := centralTaskTCPEnvelope(t, update)
	beforeUpdate := p.mediaControl.tracker.Snapshot()[0].Info.Lifetime
	centralObserve(p, localUpdate, true)
	require.False(t, localUpdate.CallLifecycleRejected)
	require.Equal(t, beforeUpdate, p.mediaControl.tracker.Snapshot()[0].Info.Lifetime, "authorized framed TCP UPDATE keeps the selected call incarnation")
	var rules []*management.MediaRule
	for _, r := range p.mediaControl.store.Snapshot().Rules {
		encoded := wire.EncodeRule(r)
		require.NoError(t, p.sharedPolicy.state.Verifier().VerifyMediaRule(encoded))
		serialized, err := proto.Marshal(encoded)
		require.NoError(t, err)
		require.False(t, bytes.Contains(serialized, []byte("alice")))
		require.Empty(t, encoded.Call.FilterIds)
		rules = append(rules, encoded)
	}
	require.Len(t, rules, 2, "one signed scoped rule for each authorized remote capture source")
	peers := centralTaskRuleSubscribersWithProtocol(t, p, []string{"hunter-a", "hunter-b"}, typed)
	rulesInstalled := time.Now()
	firstAdmitted := time.Time{}
	ruleFor := func(node string) *management.MediaRule {
		installed := peers[node].store.ActiveRules()
		require.Len(t, installed, 1, "late subscriber receives exactly its scoped call without observing SIP")
		rule := wire.EncodeRule(installed[0])
		require.NoError(t, p.sharedPolicy.state.Verifier().VerifyMediaRule(rule))
		require.Equal(t, node, rule.Scopes[0].HunterId)
		return rule
	}
	lifetime := p.mediaControl.tracker.Snapshot()[0].Info.Lifetime
	var batches []*data.PacketBatch
	type expectedMedia struct {
		node     string
		sequence uint16
	}
	var expected []expectedMedia
	var pairCapture time.Time
	overlapStarted := time.Now()
	for index, node := range []string{"hunter-a", "hunter-b", "hunter-b", "hunter-a", "hunter-a", "hunter-b"} {
		sequence := uint16(index/2 + 1)
		if index == 2 || index == 5 {
			time.Sleep(p.config.PacketDedup.Window + time.Millisecond)
		}
		payload := []byte{0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 42, 0, 1, 2, 3}
		binary.BigEndian.PutUint16(payload[2:4], sequence)
		envelope := centralEnvelope(t, node, payload, true)
		envelope.Source.ObservationDomainKnown = true
		if node == "hunter-a" {
			envelope.Source.ObservationDomain = 1
		} else {
			envelope.Source.ObservationDomain = 2
		}
		if index%2 == 0 {
			pairCapture = envelope.CaptureTime
		} else {
			envelope.CaptureTime = pairCapture
		}
		if !dedup || index%2 == 0 || index == 5 {
			expected = append(expected, expectedMedia{node, sequence})
		}
		proof, err := proto.Marshal(ruleFor(node))
		require.NoError(t, err)
		if typed {
			installed := peers[node].store.Core().ActiveRules()
			require.Len(t, installed, 1)
			candidate := learnedwire.Candidate(installed[0])
			require.Equal(t, proof, candidate.GetLegacyMediaRule(), "generic control preserves exact signed artifact")
			envelope.LearnedCaptureEvidence = &evidencepb.LearnedCaptureEvidence{Version: 1, Candidates: []*evidencepb.LearnedCandidate{candidate}}
		} else {
			envelope.CaptureSelectionProof = proof
		}
		// Only public opaque selection evidence arrives from the capture source.
		envelope.InheritedMatchedFilterIDs = []string{signed.Snapshot.SelectionGrants[0].Id}
		envelope.MatchedFilterIDs = append([]string(nil), envelope.InheritedMatchedFilterIDs...)
		raw, err := grpcadapter.ToCapturedPacket(envelope)
		require.NoError(t, err)
		if typed {
			require.Empty(t, raw.CaptureSelectionProof)
			require.NotNil(t, raw.LearnedCaptureEvidence)
		} else {
			require.Nil(t, raw.LearnedCaptureEvidence)
		}
		batch := &data.PacketBatch{HunterId: node, SignedCapturePolicy: policyBytes, Packets: []*data.CapturedPacket{raw}}
		require.NoError(t, p.validateLICapturePolicy(batch))
		normalized, err := source.FromProtoBatchE(batch)
		require.NoError(t, err)
		normalized.MediaSourceTrusted = true
		p.processBatch(normalized)
		if firstAdmitted.IsZero() {
			firstAdmitted = time.Now()
		}
		require.Equal(t, lifetime, p.mediaControl.tracker.Snapshot()[0].Info.Lifetime)
		accepted, err := normalized.ToProtoBatchE()
		require.NoError(t, err)
		batches = append(batches, accepted)
	}
	overlapCompleted := time.Now()
	// Expiry stops fresh capture, while already retained signed capture facts
	// remain eligible under the still-current task and call authorization.
	time.Sleep(time.Until(time.Unix(0, signed.Snapshot.ValidUntilNs)) + time.Millisecond)
	for _, batch := range batches {
		require.NoError(t, p.validateLICapturePolicy(batch), "capture lease expiry alone cannot discard retained evidence")
	}
	expired := proto.Clone(batches[0]).(*data.PacketBatch)
	expired.Packets[0].TimestampNs = time.Now().UnixNano()
	require.ErrorIs(t, p.validateLICapturePolicy(expired), li.ErrCaptureAuthority, "disconnected old rule cannot authorize fresh capture")
	// A retained accepted packet keeps its original proof/source and current
	// delivery checks after the comparison window and capture lease expire. It
	// cannot bootstrap a new current capture rule during historical replay.
	replay, err := source.FromProtoBatchE(proto.Clone(batches[0]).(*data.PacketBatch))
	require.NoError(t, err)
	replay.MediaSourceTrusted = true
	replay.HistoricalReplay = true
	p.processBatch(replay)
	expected = append(expected, expectedMedia{"hunter-a", 1})
	require.Empty(t, p.mediaControl.store.Snapshot().Rules, "historical replay cannot renew expired capture rules")
	// Selected-dialog completion is observed locally under its independent SIP
	// authority. Renewal does not extend media beyond the call's trailing grace.
	require.NoError(t, p.publishLIHandoverPolicy(time.Now()))
	bye := centralMessage("BYE sip:bob@example.invalid SIP/2.0", "bob-tag", "z9hG4bK-bye", 3, "BYE", "")
	bye = bytes.ReplaceAll(bye, []byte("alice-tag"), []byte("dialog-left"))
	localBye := centralEnvelope(t, "tap-local", bye, false)
	localBye.Source.Kind = pipeline.SourceLiveCapture
	localBye.Source.ObservationDomainKnown = true
	localBye.Source.ObservationDomain = 9
	centralObserve(p, localBye, true)
	require.False(t, localBye.CallLifecycleRejected)
	completing := p.mediaControl.tracker.Snapshot()
	require.Len(t, completing, 1)
	require.True(t, completing[0].Completing)
	deadline := completing[0].CompletionDeadline
	for _, rule := range p.mediaControl.store.Snapshot().Rules {
		require.False(t, rule.ExpiresAt.After(deadline))
	}
	// Drain ordinary reorder work under the real call completion barrier.
	completed := p.callLifecycle.Finalize("continuity@example.invalid", CallFinalizationProtocolComplete)
	require.True(t, completed.Finalized)
	require.NoError(t, completed.Err)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	var mediaProducts []*x2x3.PDU
	for len(mediaProducts) < len(expected) {
		product := receiveProduct(t, products)
		capture, available, err := x2x3.DecodeCaptureSource(product)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, p.config.ProcessorID, string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
		if product.Header.Type == x2x3.PDUTypeX3 {
			mediaProducts = append(mediaProducts, product)
		} else {
			require.Equal(t, "tap-local", capture.NodeID())
		}
	}
	for index, product := range mediaProducts {
		capture, available, err := x2x3.DecodeCaptureSource(product)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, expected[index].node, capture.NodeID())
		require.Equal(t, "capture0", capture.Interface())
		domain, known := capture.ObservationDomain()
		require.True(t, known)
		expectedDomain := uint32(1)
		if expected[index].node == "hunter-b" {
			expectedDomain = 2
		}
		require.Equal(t, expectedDomain, domain)
		decoded := gopacket.NewPacket(product.Payload, layers.LinkTypeRaw, gopacket.Default)
		udp, ok := decoded.TransportLayer().(*layers.UDP)
		require.True(t, ok)
		require.Equal(t, expected[index].sequence, binary.BigEndian.Uint16(udp.Payload[2:4]))
		require.EqualValues(t, index, binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
	}
	time.Sleep(time.Until(deadline) + time.Millisecond)
	p.mediaControl.tracker.Sweep()
	require.NoError(t, p.reconcileMediaSelection())
	require.Empty(t, p.mediaControl.store.Snapshot().Rules, "BYE retires call media rules after configured trailing grace")
	targetRevision := mediarules.Revision(p.mediaControl.store.Status().Sequence)
	for _, peer := range peers {
		for peer.store.Status().Revision < targetRevision {
			centralReceiveRuleSnapshot(t, peer)
		}
		require.Empty(t, peer.store.ActiveRules(), "actual subscribers receive current withdrawal")
	}
	require.NoError(t, p.liManager.DeactivateTask(f.xid))
	require.NoError(t, p.publishLIHandoverPolicy(time.Now()))
	require.NoError(t, p.reconcileMediaSelection())
	require.Empty(t, p.sharedPolicy.state.Latest().Snapshot.SelectionGrants)
	require.Empty(t, p.mediaControl.store.Snapshot().Rules)
	for _, batch := range batches {
		require.ErrorIs(t, p.validateLICapturePolicy(batch), li.ErrCaptureAuthority, "retained signed proof cannot restore revoked task")
	}
	t.Logf("observed_to_selection=%s selection_to_remote_install=%s remote_install_to_first_admission=%s early_media_without_rule=1", selectionCompleted.Sub(signallingObserved), rulesInstalled.Sub(selectionCompleted), firstAdmitted.Sub(rulesInstalled))
	if dedup {
		stats := p.packetDuplicates.Stats()
		require.Positive(t, stats.Duplicates)
		require.Positive(t, stats.OutsideWindow)
		t.Logf("overlap=%s window=%s detector=%+v", overlapCompleted.Sub(overlapStarted), p.config.PacketDedup.Window, stats)
	}
	t.Logf("task=%s call=%s sources=%s,%s rules=%d raw=%d admitted=%d historical_replayed=1 delivered=%d", f.xid, "continuity@example.invalid", "hunter-a", "hunter-b", len(rules), len(batches), len(batches), len(mediaProducts))
}

// centralRulePeer exercises the actual versioned stream codec and atomic receiver
// used by hunters. Its transport verifies the configured CA and DNS-bound source.
type centralRulePeer struct {
	store           *mediarules.Store
	receiver        *wire.Receiver
	stream          management.MediaControlService_SubscribeMediaRulesClient
	genericReceiver *learnedwire.Receiver
	genericStream   learnedpb.LearnedControlService_SubscribeLearnedRulesClient
}

func centralTaskRuleSubscribers(t *testing.T, p *Processor, nodes []string) map[string]*centralRulePeer {
	t.Helper()
	return centralTaskRuleSubscribersWithProtocol(t, p, nodes, false)
}
func centralTaskRuleSubscribersWithProtocol(t *testing.T, p *Processor, nodes []string, typed bool) map[string]*centralRulePeer {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
	require.NoError(t, err)
	caPair, err := tls.LoadX509KeyPair("../../../test/testcerts/li/ca-cert.pem", "../../../test/testcerts/li/ca-key.pem")
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterMediaControlServiceServer(server, p.mediaControl.service)
	learnedpb.RegisterLearnedControlServiceServer(server, p.mediaControl.genericService)
	management.RegisterManagementServiceServer(server, p)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done) })
	peers := make(map[string]*centralRulePeer)
	cfg := p.config.MediaRules
	limits := wire.Limits{MaxMessageBytes: cfg.MaxMessageBytes, MaxSnapshotBytes: cfg.MaxSnapshotBytes, MaxRules: cfg.MaxRules}
	for index, node := range nodes {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index + 1)), DNSNames: []string{node}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPair.PrivateKey)
		require.NoError(t, err)
		client, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, RootCAs: roots, ServerName: "localhost"})))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, client.Close()) })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		registration, err := management.NewManagementServiceClient(client).RegisterHunter(ctx, &management.HunterRegistration{HunterId: node})
		require.NoError(t, err)
		require.True(t, registration.Accepted)
		var domains []mediaadmission.DomainID
		for _, mapping := range cfg.Sources {
			if mapping.HunterID == node {
				domains = append(domains, mapping.HunterDomain)
			}
		}
		store, err := mediarules.New(cfg.StoreConfig(p.config.ProcessorID, node, domains, nil))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, store.Close()) })
		peer := &centralRulePeer{store: store}
		if typed {
			adapter := voiprules.Adapter()
			capability := &learnedpb.LearnedCapability{AdapterId: adapter.ID, ContextVersion: adapter.Version, EndpointSelectorVersions: []uint32{1}, EvidenceVersions: []uint32{1}, SupportedProtocols: []uint32{17}}
			for _, q := range adapter.Qualifiers {
				capability.Qualifiers = append(capability.Qualifiers, &learnedpb.LearnedQualifier{Id: q.ID, Version: q.Version})
			}
			caps := []*learnedpb.LearnedCapability{capability}
			peer.genericStream, err = learnedpb.NewLearnedControlServiceClient(client).SubscribeLearnedRules(ctx, &learnedpb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: node, ProcessorId: p.config.ProcessorID, Capabilities: caps})
			require.NoError(t, err)
			peer.genericReceiver, err = learnedwire.NewReceiver(store.Core(), p.config.ProcessorID, learnedwire.Limits{MaxMessageBytes: limits.MaxMessageBytes, MaxSnapshotBytes: limits.MaxSnapshotBytes, MaxRules: limits.MaxRules}, caps)
			require.NoError(t, err)
		} else {
			peer.stream, err = management.NewMediaControlServiceClient(client).SubscribeMediaRules(ctx, &management.MediaRuleRequest{ProtocolVersion: wire.GrantVersion, HunterId: node, ProcessorId: p.config.ProcessorID})
			require.NoError(t, err)
			peer.receiver, err = wire.NewReceiver(store, p.config.ProcessorID, limits)
			require.NoError(t, err)
		}
		centralReceiveRuleSnapshot(t, peer)
		peers[node] = peer
	}
	return peers
}

func centralReceiveRuleSnapshot(t *testing.T, peer *centralRulePeer) {
	t.Helper()
	for {
		if peer.genericStream != nil {
			update, err := peer.genericStream.Recv()
			require.NoError(t, err)
			require.EqualValues(t, learnedwire.Version, update.ProtocolVersion)
			require.NoError(t, peer.genericReceiver.Apply(update))
			if update.SnapshotEnd {
				return
			}
			continue
		}
		update, err := peer.stream.Recv()
		require.NoError(t, err)
		require.EqualValues(t, wire.GrantVersion, update.ProtocolVersion)
		require.NoError(t, peer.receiver.Apply(update))
		if update.SnapshotEnd {
			return
		}
	}
}

// A complete, framed TCP message uses the ordinary normalized transport path;
// stream segmentation/reassembly remains owned by the capture ingress assembler.
func centralTaskTCPEnvelope(t *testing.T, payload []byte) *pipeline.PacketEnvelope {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	raw := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(raw, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
	return &pipeline.PacketEnvelope{Data: raw.Bytes(), LinkType: layers.LinkTypeRaw, CaptureTime: time.Now(), CaptureLength: len(raw.Bytes()), OriginalLength: len(raw.Bytes()), Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, NodeID: "tap-local", InterfaceName: "capture0", ObservationDomainKnown: true, ObservationDomain: 9}}
}

// An independently authorized ordinary capture source supplies SIP to a separate
// processor. This exercises the non-LI observation path; a media-only LI grant
// deliberately does not stand in for signalling authorization.
func TestProcessorAuthorizedSIPObservationWithoutLIGrant(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", ProcessorID: "ordinary-controller", TLSEnabled: true, TLSClientAuth: true, TLSCertFile: "../../../test/testcerts/li/mdf-server-cert.pem", TLSKeyFile: "../../../test/testcerts/li/mdf-server-key.pem", TLSCAFile: "../../../test/testcerts/li/ca-cert.pem", MediaRules: MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []MediaSourceMapping{{HunterID: "hunter-a", Interface: "capture0", Domain: 7, HunterDomain: 1}, {HunterID: "hunter-b", Interface: "capture0", Domain: 7, HunterDomain: 2}}}})
	require.NoError(t, err)
	require.False(t, p.config.LIHandover.Enabled)
	_, err = p.updateManagedFilter(&management.Filter{Id: "private-observer-selection", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	peers := centralTaskRuleSubscribers(t, p, []string{"hunter-a", "hunter-b"})
	require.Empty(t, peers["hunter-b"].store.ActiveRules())
	early := centralEnvelope(t, "hunter-a", []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42}, true)
	early.Source.ObservationDomainKnown = true
	early.Source.ObservationDomain = 1
	centralObserve(p, early, true)
	require.Empty(t, p.mediaControl.tracker.Snapshot(), "early ordinary media does not invent a selected call")
	observed := time.Now()
	invite := centralEnvelope(t, "hunter-a", centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-ordinary", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n"), false)
	invite.Source.ObservationDomainKnown = true
	invite.Source.ObservationDomain = 1
	centralObserve(p, invite, true)
	require.Equal(t, pipeline.SourceGRPC, invite.Source.Kind)
	require.NotEmpty(t, p.mediaControl.tracker.Snapshot())
	revision := mediarules.Revision(p.mediaControl.store.Status().Sequence)
	for _, peer := range peers {
		centralReceiveRuleRevision(t, peer, revision)
	}
	installed := time.Now()
	rules := peers["hunter-b"].store.ActiveRules()
	require.Len(t, rules, 1)
	require.Empty(t, rules[0].Call.SelectionGrants)
	require.Empty(t, rules[0].CaptureSignature)
	answer := centralTaskTCPEnvelope(t, centralMessage("SIP/2.0 200 OK", "bob-tag", "z9hG4bK-ordinary", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 50000 RTP/AVP 0\r\n"))
	answer.Source.Kind = pipeline.SourceGRPC
	answer.Source.NodeID = "hunter-a"
	answer.Source.ObservationDomain = 1
	lifetime := p.mediaControl.tracker.Snapshot()[0].Info.Lifetime
	centralObserve(p, answer, true)
	revision = mediarules.Revision(p.mediaControl.store.Status().Sequence)
	for _, peer := range peers {
		centralReceiveRuleRevision(t, peer, revision)
	}
	media := centralEnvelope(t, "hunter-b", []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42}, true)
	media.Source.ObservationDomainKnown = true
	media.Source.ObservationDomain = 2
	centralObserve(p, media, true)
	require.Equal(t, []string{"private-observer-selection"}, media.InheritedMatchedFilterIDs)
	require.Equal(t, lifetime, p.mediaControl.tracker.Snapshot()[0].Info.Lifetime)
	require.Empty(t, p.filterManager.GetForHunter("hunter-b"))
	require.Empty(t, media.CaptureSelectionProof, "ordinary capture has its independently authorized observation path")
	t.Logf("ordinary_source_observation_to_remote_install=%s remote_install_to_media=%s", installed.Sub(observed), time.Since(installed))
}

func centralReceiveRuleRevision(t *testing.T, peer *centralRulePeer, revision mediarules.Revision) {
	t.Helper()
	for peer.store.Status().Revision < revision {
		update, err := peer.stream.Recv()
		require.NoError(t, err)
		require.NoError(t, peer.receiver.Apply(update))
	}
}
