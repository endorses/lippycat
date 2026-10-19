//go:build all && li && linux

package processor

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Real protected task selection and signed media grants share the actual local
// producer with an independent diagnostic relationship. No task or signature is
// supplied by the diagnostic adapter.
func TestProtectedMixedLocalLearnedCaptureReachesX3(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	localID := f.config.ProcessorID + "-local"
	f.config.LITaskFilterDistributionScope = "local_only"
	f.config.LIDeliveryCaptureSourceMetadata = true
	f.config.MediaRules = MediaRulesConfig{Settings: mediarules.Settings{Enabled: true}, Sources: []MediaSourceMapping{{HunterID: localID, Interface: "capture0", Domain: 7, HunterDomain: 9}}}
	f.config.LearnedAdapters = []core.Adapter{diagnosticCaptureAdapter("diagnostic")}
	f.config.LIHandover = li.HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{localID}}
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
	selected := p.sharedPolicy.state.Latest()
	require.NotNil(t, selected)
	require.Len(t, selected.Snapshot.SelectionGrants, 1)
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-local-typed", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	observed := centralEnvelope(t, localID, invite, false)
	observed.Source.Kind = pipeline.SourceLiveCapture
	observed.Source.ObservationDomainKnown = true
	observed.Source.ObservationDomain = 9
	centralObserve(p, observed, true)
	require.NotEmpty(t, p.mediaControl.store.Snapshot().Rules)
	media := centralEnvelope(t, localID, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42, 1, 2, 3, 4}, true)
	facts, ok := core.PacketFacts(media.Packet(), 9)
	require.True(t, ok)
	binding := diagnosticBinding(t, "diagnostic", "independent-request", localID, core.Selector{Domain: 9, Address: facts.Destination.Address, Port: facts.Destination.Port, Protocol: core.UDP, Direction: core.Destination})
	binding.Scope[0].Domain = 9
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}))
	cfg := p.MediaRuleConfiguration()
	legacy := cfg.StoreConfig(p.config.ProcessorID, localID, []mediaadmission.DomainID{9}, nil)
	engine, err := mediarules.EngineConfig(legacy, p.LearnedRuleAdapters()...)
	require.NoError(t, err)
	engine.SupportedProtocols = []core.Protocol{core.UDP}
	runtime, err := core.NewRuntime(engine, map[string]core.DomainID{"capture0": 9}, 64, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, runtime.Store.Close()) }()
	subscription, err := p.SubscribeLocalLearnedRules()
	require.NoError(t, err)
	localControl, err := captureadapter.StartLocalSubscription(t.Context(), runtime, subscription)
	require.NoError(t, err)
	defer func() { require.NoError(t, localControl.Close()) }()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	stream := pcapgo.NewWriter(writer)
	require.NoError(t, stream.WriteFileHeader(65535, layers.LinkTypeRaw))
	require.NoError(t, stream.WritePacket(gopacket.CaptureInfo{Timestamp: media.CaptureTime, CaptureLength: len(media.Data), Length: len(media.Data)}, media.Data))
	var closeWriter sync.Once
	finishInput := func() { closeWriter.Do(func() { require.NoError(t, writer.Close()) }) }
	defer func() {
		err := reader.Close()
		if err != nil && !errors.Is(err, syscall.EBADF) && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close pcap reader: %v", err)
		}
	}()
	ready := make(chan struct{})
	close(ready)
	local := source.NewLocalSource(source.LocalSourceConfig{ProcessorID: p.config.ProcessorID, ProtocolMode: "voip", Interfaces: []string{"capture0"}, BatchSize: 1, BatchTimeout: 10 * time.Millisecond, CaptureInterfaces: func() []pcaptypes.PcapInterface {
		return []pcaptypes.PcapInterface{&gatedLearnedInterface{ready: ready, open: func() (*pcap.Handle, error) { return pcap.OpenOfflineFile(reader) }}}
	}})
	local.SetApplicationFilter(denyDiagnosticFilter{})
	validator := func(packet *pipeline.PacketEnvelope) bool {
		for _, candidate := range packet.LearnedCaptureEvidence.Candidates {
			if len(candidate.GetLegacyMediaRule()) == 0 {
				continue
			}
			_, rule, err := voiprules.BindingFromLegacyCandidate(candidate)
			if err != nil || !p.ValidateLocalMediaRule(rule, localID, packet.Source.ObservationDomain, packet.Packet(), packet.CaptureTime) {
				return false
			}
		}
		return true
	}
	require.NoError(t, local.SetLearnedRuntime(runtime, validator, p.LearnedCapturePolicySnapshot))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- local.Start(ctx) }()
	defer func() { cancel(); finishInput(); require.NoError(t, <-done) }()
	var captured *source.PacketBatch
	select {
	case captured = <-local.Batches():
	case <-time.After(5 * time.Second):
		t.Fatal("protected learned local packet was not admitted")
	}
	require.Len(t, captured.Envelopes, 1)
	require.Len(t, captured.Envelopes[0].LearnedCaptureEvidence.Candidates, 2)
	require.Empty(t, captured.Envelopes[0].CaptureSelectionProof)
	require.NotEmpty(t, captured.SignedCapturePolicy)
	signed, err := p.LearnedCapturePolicySnapshot()
	require.NoError(t, err)
	require.Equal(t, signed, captured.SignedCapturePolicy)
	raw, err := captured.ToProtoBatchE()
	require.NoError(t, err)
	require.NoError(t, p.validateLICapturePolicy(raw))
	original := append([]byte(nil), raw.Packets[0].LearnedCaptureEvidence.Candidates[0].GetLegacyMediaRule()...)
	if len(original) == 0 {
		original = append([]byte(nil), raw.Packets[0].LearnedCaptureEvidence.Candidates[1].GetLegacyMediaRule()...)
	}
	require.NotEmpty(t, original)
	p.processBatch(captured)
	finalized := p.callLifecycle.Finalize("continuity@example.invalid", CallFinalizationProtocolComplete)
	require.True(t, finalized.Finalized)
	require.NoError(t, finalized.Err)
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	product := receiveProduct(t, products)
	require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
	capture, available, err := x2x3.DecodeCaptureSource(product)
	require.NoError(t, err)
	require.True(t, available)
	require.Equal(t, localID, capture.NodeID())
	require.Equal(t, "capture0", capture.Interface())
	domain, known := capture.ObservationDomain()
	require.True(t, known)
	require.EqualValues(t, 9, domain)
	require.Equal(t, media.Data, product.Payload)
	require.Len(t, captured.Envelopes, 1)
	replayed, err := captured.ToProtoBatchE()
	require.NoError(t, err)
	var proof []byte
	for _, candidate := range replayed.Packets[0].LearnedCaptureEvidence.Candidates {
		if len(candidate.GetLegacyMediaRule()) > 0 {
			proof = candidate.GetLegacyMediaRule()
		}
	}
	require.Equal(t, original, proof)
	require.NoError(t, localControl.Close())
}
