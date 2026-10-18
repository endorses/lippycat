package wire

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type ruleStream struct {
	grpc.ServerStream
	ctx     context.Context
	updates chan *management.MediaRuleUpdate
}

func (s *ruleStream) Context() context.Context { return s.ctx }
func (s *ruleStream) Send(update *management.MediaRuleUpdate) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.updates <- proto.Clone(update).(*management.MediaRuleUpdate):
		return nil
	}
}

func takeUpdate(t *testing.T, stream *ruleStream) *management.MediaRuleUpdate {
	t.Helper()
	select {
	case update := <-stream.updates:
		return update
	case <-time.After(5 * time.Second):
		t.Fatal("media-rule stream did not produce its committed update")
		return nil
	}
}

func TestServiceScopesInitialSnapshotAndPublishesWithdrawals(t *testing.T) {
	publisher, err := mediarules.New(mediarules.Config{ProcessorID: "processor", MaxRules: 16, MaxBytes: 32768,
		MaxEndpoints: 32, MaxEndpointsPerRule: 4, MaxSubscribers: 2, SubscriptionBuffer: 4, MaxLifetime: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, publisher.Close()) })
	rule := testRule(0)
	other := testRule(1)
	other.Scope[0].HunterID = "other-hunter"
	control, err := publisher.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []mediarules.Rule{rule, other}))
	authorize := func(_ context.Context, hunter string) error {
		if hunter != "hunter" {
			return status.Error(codes.PermissionDenied, "wrong authenticated source")
		}
		return nil
	}
	service, err := NewService(publisher, testLimits, 2, authorize)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &ruleStream{ctx: ctx, updates: make(chan *management.MediaRuleUpdate, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: Version, HunterId: "hunter", ProcessorId: "processor"}, stream)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("media subscription did not stop")
		}
	})
	receiver, err := NewReceiver(testStore(t), "processor", testLimits)
	require.NoError(t, err)
	initial := takeUpdate(t, stream)
	require.True(t, initial.SnapshotBegin)
	require.True(t, initial.SnapshotEnd)
	require.Len(t, initial.Rules, 1)
	require.Equal(t, rule.ID, initial.Rules[0].Id)
	require.NoError(t, receiver.Apply(initial))

	require.NoError(t, publisher.ApplyDelta(control, 2, nil, []string{rule.ID}))
	withdrawal := takeUpdate(t, stream)
	require.Equal(t, []string{rule.ID}, withdrawal.RemovedIds)
	require.Empty(t, withdrawal.Rules)
	require.NoError(t, receiver.Apply(withdrawal))
	require.Empty(t, receiver.store.ActiveRules())

	_, err = service.ReportMediaRuleStatus(ctx, &management.MediaRuleApplication{HunterId: "other-hunter", Session: EncodeSession(rule.Session), AppliedRevision: withdrawal.Revision})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	application := &management.MediaRuleApplication{HunterId: "hunter", Session: EncodeSession(rule.Session), AppliedRevision: withdrawal.Revision, Synchronized: true}
	receipt, err := service.ReportMediaRuleStatus(ctx, application)
	require.NoError(t, err)
	require.True(t, receipt.Accepted)
	application.Error = "changed by caller"
	require.Empty(t, service.Application("hunter").Error)
	application.AppliedRevision = initial.Revision
	_, err = service.ReportMediaRuleStatus(ctx, application)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServiceRequiresAuthenticatedSourceBeforeSubscription(t *testing.T) {
	store := testStore(t)
	service, err := NewService(store, testLimits, 1, func(context.Context, string) error {
		return status.Error(codes.Unauthenticated, "source certificate mismatch")
	})
	require.NoError(t, err)
	stream := &ruleStream{ctx: context.Background(), updates: make(chan *management.MediaRuleUpdate, 1)}
	err = service.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: Version, HunterId: "forged-hunter", ProcessorId: "processor"}, stream)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Zero(t, store.Status().Subscribers)
	_, err = service.ReportMediaRuleStatus(context.Background(), &management.MediaRuleApplication{HunterId: "forged-hunter"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestServiceRefusesGrantRulesToVersionOneWithoutSendingData(t *testing.T) {
	publisher := testStore(t)
	rule := testRule(0)
	rule.Call.CapturePolicyRevision = 1
	rule.Call.SelectionGrants = []mediarules.SelectionRef{{ID: "opaque", Revision: 1}}
	rule.CaptureSignature = []byte("proof")
	control, err := publisher.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	service, err := NewService(publisher, Limits{MaxMessageBytes: 4096, MaxSnapshotBytes: 8192, MaxRules: 16}, 2, func(context.Context, string) error { return nil })
	require.NoError(t, err)
	stream := &ruleStream{ctx: context.Background(), updates: make(chan *management.MediaRuleUpdate, 4)}
	err = service.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: Version, HunterId: "hunter", ProcessorId: "processor"}, stream)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Empty(t, stream.updates)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream.ctx = ctx
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: GrantVersion, HunterId: "hunter", ProcessorId: "processor"}, stream)
	}()
	update := takeUpdate(t, stream)
	require.EqualValues(t, GrantVersion, update.ProtocolVersion)
	require.Equal(t, EncodeRule(rule), update.Rules[0])
	limits := Limits{MaxMessageBytes: 4096, MaxSnapshotBytes: 8192, MaxRules: 16}
	receiver, err := NewReceiver(testStore(t), "processor", limits)
	require.NoError(t, err)
	require.NoError(t, receiver.Apply(update))
	ordinary := testRule(1)
	ordinary.Revision = 2
	require.NoError(t, publisher.ApplyDelta(control, 2, []mediarules.Rule{ordinary}, nil))
	update = takeUpdate(t, stream)
	require.True(t, update.SnapshotBegin)
	require.True(t, update.SnapshotEnd)
	require.NoError(t, receiver.Apply(update))
	require.Equal(t, rule.CaptureSignature, receiver.store.ActiveRules()[0].CaptureSignature, "stream sequencing preserves signed rule revision and proof")
	require.NoError(t, publisher.ApplyDelta(control, 3, nil, []string{rule.ID}))
	update = takeUpdate(t, stream)
	require.True(t, update.SnapshotBegin)
	require.NoError(t, receiver.Apply(update))
	require.Len(t, receiver.store.ActiveRules(), 1)
	require.Empty(t, receiver.store.ActiveRules()[0].Call.SelectionGrants)
	cancel()
	require.Error(t, <-done)
}
