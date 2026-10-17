package wire

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func applicationService(t *testing.T, maxApplications int) *Service {
	t.Helper()
	store, err := mediarules.New(mediarules.Config{ProcessorID: "processor", MaxRules: 2, MaxBytes: 4096, MaxEndpoints: 4, MaxEndpointsPerRule: 2, MaxSubscribers: 2, SubscriptionBuffer: 4, MaxLifetime: time.Minute})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	session := mediarules.Session{ProcessorID: "processor", Generation: 1}
	control, err := store.StartSession("processor", session)
	require.NoError(t, err)
	require.NoError(t, store.ApplySnapshot(control, 1, nil))
	service, err := NewService(store, testLimits, maxApplications, func(_ context.Context, hunterID string) error {
		if hunterID != "a" && hunterID != "b" {
			return status.Error(codes.PermissionDenied, "wrong authenticated hunter")
		}
		return nil
	})
	require.NoError(t, err)
	return service
}

type liveApplication struct {
	cancel   context.CancelFunc
	done     chan error
	revision uint64
	session  *management.MediaRuleSession
	stopped  bool
}

func subscribeApplication(t *testing.T, s *Service, hunterID string) *liveApplication {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &ruleStream{ctx: ctx, updates: make(chan *management.MediaRuleUpdate, 4)}
	live := &liveApplication{cancel: cancel, done: make(chan error, 1)}
	go func() {
		live.done <- s.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: Version, HunterId: hunterID, ProcessorId: "processor"}, stream)
	}()
	t.Cleanup(func() { live.stop(t) })
	update := takeUpdate(t, stream)
	require.True(t, update.SnapshotEnd)
	live.revision, live.session = update.Revision, update.Session
	return live
}
func (l *liveApplication) stop(t *testing.T) {
	t.Helper()
	if l.stopped {
		return
	}
	l.cancel()
	select {
	case <-l.done:
		l.stopped = true
	case <-time.After(5 * time.Second):
		t.Fatal("media-rule subscription did not stop")
	}
}
func reportApplication(t *testing.T, s *Service, hunterID string, live *liveApplication, message string) {
	t.Helper()
	receipt, err := s.ReportMediaRuleStatus(context.Background(), &management.MediaRuleApplication{HunterId: hunterID, Session: live.session, AppliedRevision: live.revision, Synchronized: true, Error: message})
	require.NoError(t, err)
	require.True(t, receipt.Accepted)
}

func TestApplicationCapacityReusedAfterHunterDisconnect(t *testing.T) {
	service := applicationService(t, 1)
	first := subscribeApplication(t, service, "a")
	reportApplication(t, service, "a", first, "first hunter")
	require.NotNil(t, service.Application("a"))
	first.stop(t)
	require.Nil(t, service.Application("a"))
	require.Zero(t, service.store.Status().Subscribers)
	second := subscribeApplication(t, service, "b")
	reportApplication(t, service, "b", second, "replacement hunter")
	require.Equal(t, "replacement hunter", service.Application("b").Error)
}

func TestOlderSameHunterSubscriptionCannotDeleteReplacementStatus(t *testing.T) {
	service := applicationService(t, 1)
	first := subscribeApplication(t, service, "a")
	reportApplication(t, service, "a", first, "old connection")
	second := subscribeApplication(t, service, "a")
	reportApplication(t, service, "a", second, "replacement connection")
	first.stop(t)
	require.Equal(t, "replacement connection", service.Application("a").Error)
	reportApplication(t, service, "a", second, "still connected")
	require.Equal(t, "still connected", service.Application("a").Error)
	second.stop(t)
	require.Nil(t, service.Application("a"))
	require.Zero(t, service.store.Status().Subscribers)
	next := subscribeApplication(t, service, "b")
	reportApplication(t, service, "b", next, "slot reused after final close")
}

func TestReportsCannotReserveStatusForUnsubscribedHunters(t *testing.T) {
	service := applicationService(t, 1)
	current := service.store.Status()
	report := &management.MediaRuleApplication{HunterId: "forged", Session: EncodeSession(current.Session), AppliedRevision: current.Sequence, Synchronized: true}
	_, err := service.ReportMediaRuleStatus(context.Background(), report)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, service.Application("forged"))
	report.HunterId = "a"
	_, err = service.ReportMediaRuleStatus(context.Background(), report)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Nil(t, service.Application("a"))
	live := subscribeApplication(t, service, "b")
	reportApplication(t, service, "b", live, "authorized live hunter")
	rejected := &ruleStream{ctx: context.Background(), updates: make(chan *management.MediaRuleUpdate, 1)}
	err = service.SubscribeMediaRules(&management.MediaRuleRequest{ProtocolVersion: Version, HunterId: "a", ProcessorId: "processor"}, rejected)
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "distinct live hunters must retain the configured status bound")
	require.Equal(t, 1, service.store.Status().Subscribers, "rejected status reservation must release its store subscriber")
	report.HunterId = "a"
	_, err = service.ReportMediaRuleStatus(context.Background(), report)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "authorized live hunter", service.Application("b").Error)
	live.stop(t)
	_, err = service.ReportMediaRuleStatus(context.Background(), &management.MediaRuleApplication{HunterId: "b", Session: live.session, AppliedRevision: live.revision})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Nil(t, service.Application("b"))
}
