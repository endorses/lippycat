package source

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestAllLocalAppendPathsKeepExactCapturePolicyGroups(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{BatchSize: 10, BatchTimeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	input := make(chan capture.PacketInfo, 1)
	injected := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injected)
	done := make(chan struct{})
	go func() { s.batchingWorker(input); close(done) }()
	defer func() { cancel(); <-done }()
	first := convertPacketInfo(buildTCPPacket(t, 1))
	policy := []byte("signed-policy-a")
	s.appendPolicyPacket(&policyCapture{packet: first, signedCapturePolicy: policy}, nil)
	policy[0] = 'x'
	input <- buildTCPPacket(t, 2)
	one := <-s.Batches()
	require.Equal(t, []byte("signed-policy-a"), one.SignedCapturePolicy)
	require.Len(t, one.Envelopes, 1)
	require.Eventually(t, func() bool { s.batchMu.Lock(); defer s.batchMu.Unlock(); return len(s.currentBatch) == 1 }, time.Second, time.Millisecond)
	var completed atomic.Bool
	injected <- InjectedPacket{PacketInfo: buildTCPPacket(t, 3), AfterProcess: func() { completed.Store(true) }}
	require.Eventually(t, func() bool { s.batchMu.Lock(); defer s.batchMu.Unlock(); return len(s.currentBatch) == 2 }, time.Second, time.Millisecond)
	s.appendPolicyPacket(&policyCapture{packet: convertPacketInfo(buildTCPPacket(t, 4)), signedCapturePolicy: []byte("signed-policy-b")}, nil)
	ordinary := <-s.Batches()
	require.Empty(t, ordinary.SignedCapturePolicy)
	require.Len(t, ordinary.Envelopes, 2)
	require.False(t, completed.Load())
	require.Empty(t, one.AfterProcess)
	ordinary.RunAfterProcess()
	require.True(t, completed.Load())
	s.sendBatch()
	last := <-s.Batches()
	require.Equal(t, []byte("signed-policy-b"), last.SignedCapturePolicy)
	require.Len(t, last.Envelopes, 1)
	require.Empty(t, last.AfterProcess)
}

type overflowTrapResolver struct {
	sourcePolicyResolver
	calls atomic.Uint64
}

func (r *overflowTrapResolver) ResolveMedia(packet gopacket.Packet, iface string) (capturepolicy.RemoteCallAssociation, bool) {
	r.calls.Add(1)
	return r.sourcePolicyResolver.ResolveMedia(packet, iface)
}

func TestLearnedOverflowNeverFallsBackToLegacyLocalOwnership(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "independent-direct"}[direct], func(t *testing.T) {
			registry, err := core.NewRegistry(core.Adapter{ID: "diagnostic", Version: 1, Validate: func(core.Binding) error { return nil }, Authorize: func(core.Binding) error { return nil }})
			require.NoError(t, err)
			cfg := core.Config{ProcessorID: "central", HunterID: "tap-local", Domains: []core.DomainID{0}, MaxRules: 4, MaxBytes: 8192, MaxEndpoints: 4, MaxEndpointsPerRule: 1, MaxSubscribers: 2, SubscriptionBuffer: 2, MaxLifetime: time.Minute, Registry: registry, SupportedProtocols: []core.Protocol{core.UDP}}
			runtime, err := core.NewRuntime(cfg, map[string]core.DomainID{"media": 0}, 1, nil)
			require.NoError(t, err)
			defer func() { require.NoError(t, runtime.Store.Close()) }()
			session := core.Session{ProcessorID: "central", Generation: 1}
			control, err := runtime.Store.StartSession("central", session)
			require.NoError(t, err)
			now := time.Now()
			var bindings []core.Binding
			for _, id := range []string{"a", "b"} {
				bindings = append(bindings, core.Binding{ID: id, Session: session, Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: id, Incarnation: "one"}, AttributionContext: "diagnostic", Intents: []core.IntentRef{{ID: id, Revision: 1}}, Scope: []core.Scope{{HunterID: "tap-local", Domain: 0}}, Selectors: []core.Selector{{Address: netip.MustParseAddr("192.0.2.2"), Port: 45000, Protocol: core.UDP}}, Context: []byte("diagnostic/v1"), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Second)})
			}
			require.NoError(t, runtime.Store.ApplySnapshot(control, 1, bindings))
			s := NewLocalSource(LocalSourceConfig{ProcessorID: "tap", ProtocolMode: "voip", Interfaces: []string{"media"}, BatchSize: 1, BatchTimeout: time.Hour})
			s.SetApplicationFilter(&sourcePolicyFilter{direct: direct})
			trap := &overflowTrapResolver{sourcePolicyResolver: sourcePolicyResolver{active: true, proof: capturepolicy.RemoteCallAssociation{CallID: "legacy-subset", InheritedFilterIDs: []string{"forbidden-inherited"}}}}
			require.NoError(t, s.SetCapturePolicies(capturepolicy.CapturePolicies{Signalling: capturepolicy.SignallingNone, Media: capturepolicy.MediaProcessor}, trap))
			require.NoError(t, s.SetLearnedRuntime(runtime, nil))
			ctx, cancel := context.WithCancel(context.Background())
			s.ctx = ctx
			input := make(chan capture.PacketInfo, 1)
			done := make(chan struct{})
			go func() { s.batchingWorker(input); close(done) }()
			defer func() { cancel(); <-done }()
			packet := sourcePolicyPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42, 1, 2, 3, 4}, 45000)
			// The shared signalling fixture uses source port 5060, which makes
			// gopacket try to decode this short RTP payload as truncated SIP.
			ip := packet.Packet.NetworkLayer().(*layers.IPv4)
			udp := packet.Packet.TransportLayer().(*layers.UDP)
			udp.SrcPort = 40000
			require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
			buffer := gopacket.NewSerializeBuffer()
			require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(udp.Payload)))
			packet.Packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
			packet.Packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
			observed, err := s.normalizeLocalPacket(convertPacketInfo(packet))
			require.NoError(t, err)
			_, complete := core.PacketFacts(observed.Packet(), 0)
			require.True(t, complete, "overflow fixture must contain a complete transport header")
			input <- packet
			require.Eventually(t, func() bool { return runtime.Store.Status().CandidateOverflows > 0 }, time.Second, time.Millisecond)
			if direct {
				batch := <-s.Batches()
				require.Len(t, batch.Envelopes, 1)
				envelope := batch.Envelopes[0]
				require.Nil(t, envelope.LearnedCaptureEvidence)
				require.Empty(t, envelope.CaptureSelectionProof)
				require.Empty(t, envelope.InheritedMatchedFilterIDs)
				require.Equal(t, []string{"local"}, envelope.DirectMatchedFilterIDs)
			} else {
				require.Empty(t, s.Batches())
			}
			require.Zero(t, trap.calls.Load(), "overflow must not consult a legacy resolver to recover a partial owner")
			require.True(t, runtime.Store.Status().Ready)
		})
	}
}
