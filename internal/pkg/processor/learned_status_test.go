//go:build processor || tap || all

package processor

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func statusDiagnosticAdapter() core.Adapter {
	validate := func(binding core.Binding) error {
		if !bytes.Equal(binding.Context, []byte("diagnostic.v1")) {
			return core.ErrInvalid
		}
		return nil
	}
	return core.Adapter{ID: "diagnostic", Version: 1, Validate: validate, Authorize: validate}
}
func mixedStatusProcessor(t *testing.T) (*Processor, core.Binding) {
	t.Helper()
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", ProcessorID: "status", LearnedAdapters: []core.Adapter{statusDiagnosticAdapter()}, MediaRules: MediaRulesConfig{Settings: mediarules.Settings{Enabled: true, MaxRules: 2}, Sources: []MediaSourceMapping{{HunterID: "hunter-a", Interface: "capture0", Domain: 7, HunterDomain: 1}}}})
	require.NoError(t, err)
	_, err = p.updateManagedFilter(&management.Filter{Id: "selected", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	centralObserve(p, centralEnvelope(t, "hunter-a", centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-status", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n"), false), true)
	require.Equal(t, 1, p.mediaControl.store.Status().Rules)
	now := time.Now()
	binding := core.Binding{ID: "diagnostic", Session: p.LearnedRulesSession(), Revision: 1, AdapterID: "diagnostic", ContextVersion: 1, Subject: core.Subject{ID: "PRIVATE-SUBJECT", Incarnation: "one"}, AttributionContext: "diagnostic", Intents: []core.IntentRef{{ID: "PRIVATE-INTENT", Revision: 1}}, Scope: []core.Scope{{HunterID: "hunter-a", Domain: 1}}, Selectors: []core.Selector{{Domain: 1, Address: netip.MustParseAddr("192.0.2.1"), Port: 40000, Protocol: core.UDP}}, Context: []byte("diagnostic.v1"), NotBefore: now, ExpiresAt: now.Add(time.Minute)}
	require.NoError(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding}))
	return p, binding
}
func TestGenericStatusKeepsVoIPViewAndExposesBoundedResourceOutcomes(t *testing.T) {
	p, binding := mixedStatusProcessor(t)
	packet := core.Packet{Domain: 1, Protocol: core.UDP, Source: core.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 40000}, Destination: core.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 50000}, Payload: []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	require.True(t, p.learnedRuleStore().Match(packet, 1).Overflow)
	second := core.CloneBinding(binding)
	second.ID = "another"
	require.ErrorIs(t, p.PublishLearnedBindings("diagnostic", []core.Binding{binding, second}), core.ErrCapacity)
	response, err := p.GetHunterStatus(t.Context(), &management.StatusRequest{})
	require.NoError(t, err)
	require.EqualValues(t, 1, response.ProcessorStats.MediaRules.Rules)
	learned := response.ProcessorStats.LearnedRules
	require.EqualValues(t, 2, learned.Bindings)
	require.EqualValues(t, 1, learned.CandidateOverflows)
	require.EqualValues(t, 1, learned.CapacityRejections)
	require.Len(t, learned.Capabilities, 2)
	require.Equal(t, "diagnostic", learned.Capabilities[0].AdapterId)
	require.Equal(t, "voip", learned.Capabilities[1].AdapterId)
	require.False(t, learned.ApplicationReported, "a publisher cannot invent source installation acknowledgments")
	encoded, err := proto.Marshal(response)
	require.NoError(t, err)
	var received management.StatusResponse
	require.NoError(t, proto.Unmarshal(encoded, &received))
	body, err := statusclient.StatusResponseToJSON(&received, false)
	require.NoError(t, err)
	require.Contains(t, string(body), `"learned_rules"`)
	require.Contains(t, string(body), `"candidate_overflows":1`)
	require.NotContains(t, string(body), "PRIVATE-SUBJECT")
	require.NotContains(t, string(body), "PRIVATE-INTENT")
	require.NotContains(t, string(body), "192.0.2.1")
}

type statusLearnedStream struct {
	grpc.ServerStream
	ctx     context.Context
	updates chan *learnedpb.LearnedRuleUpdate
}

func (s *statusLearnedStream) Context() context.Context { return s.ctx }
func (s *statusLearnedStream) Send(update *learnedpb.LearnedRuleUpdate) error {
	select {
	case s.updates <- update:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func TestGenericSourceStatusUsesEffectivePerAdapterApplication(t *testing.T) {
	p, _ := mixedStatusProcessor(t)
	store := p.learnedRuleStore()
	service, err := learnedwire.NewService(store, learnedwire.Limits{MaxMessageBytes: 1 << 20, MaxSnapshotBytes: 32 << 20, MaxRules: 2}, 2, func(context.Context, string) error { return nil })
	require.NoError(t, err)
	p.mediaControl.genericService = service
	caps := []*learnedpb.LearnedCapability{}
	for _, adapter := range store.Configuration().Registry.Adapters() {
		c := &learnedpb.LearnedCapability{AdapterId: adapter.ID, ContextVersion: adapter.Version, EndpointSelectorVersions: []uint32{1}, EvidenceVersions: []uint32{1}}
		for _, q := range adapter.Qualifiers {
			c.Qualifiers = append(c.Qualifiers, &learnedpb.LearnedQualifier{Id: q.ID, Version: q.Version})
		}
		caps = append(caps, c)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := &statusLearnedStream{ctx: ctx, updates: make(chan *learnedpb.LearnedRuleUpdate, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeLearnedRules(&learnedpb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: "hunter-a", ProcessorId: "status", Capabilities: caps}, stream)
	}()
	update := <-stream.updates
	pending := p.remoteLearnedRuleStatus("hunter-a")
	require.False(t, pending.Ready)
	require.False(t, pending.ApplicationReported)
	require.Equal(t, update.Revision, pending.DesiredRevision)
	report := &learnedpb.LearnedRuleApplication{HunterId: "hunter-a", SubscriptionId: update.SubscriptionId, Session: update.Session, AppliedRevision: update.Revision, Synchronized: true, ActiveBindings: 2, ActiveSelectors: 2, CandidateOverflows: 3, CapacityRejections: 4, RetainedBytes: 1234, AdapterApplications: []*learnedpb.LearnedAdapterApplication{{AdapterId: "diagnostic", ContextVersion: 1, ActiveBindings: 1, ActiveSelectors: 1}, {AdapterId: "voip", ContextVersion: 1, ActiveBindings: 1, ActiveSelectors: 1}}}
	_, err = service.ReportLearnedRuleStatus(t.Context(), report)
	require.NoError(t, err)
	current := p.remoteLearnedRuleStatus("hunter-a")
	require.True(t, current.Ready)
	require.True(t, current.ApplicationReported)
	require.Equal(t, update.Revision, current.EffectiveRevision)
	require.EqualValues(t, 2, current.Bindings)
	require.EqualValues(t, 3, current.CandidateOverflows)
	require.EqualValues(t, 4, current.CapacityRejections)
	require.EqualValues(t, 1234, current.Bytes)
	media := p.remoteMediaRuleStatus("hunter-a")
	require.EqualValues(t, 1, media.Rules)
	require.EqualValues(t, 1, media.Endpoints)
	bad := proto.Clone(report).(*learnedpb.LearnedRuleApplication)
	bad.AdapterApplications[0].AdapterId = "PRIVATE-INVENTED-LABEL"
	_, err = service.ReportLearnedRuleStatus(t.Context(), bad)
	require.Error(t, err)
	cancel()
	require.Error(t, <-done)
}
