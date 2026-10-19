//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func mediaRuleTLSConnection(t *testing.T, service management.MediaControlServiceServer, generic ...learnedpb.LearnedControlServiceServer) *grpc.ClientConn {
	t.Helper()
	pair, _, _, roots := rawIntegrationCertificate(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	if service != nil {
		management.RegisterMediaControlServiceServer(server, service)
	}
	if len(generic) > 0 && generic[0] != nil {
		learnedpb.RegisterLearnedControlServiceServer(server, generic[0])
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-serveDone) })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: "receiver"})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return conn
}
func TestHunterLiveMediaRulesVerifiedSnapshotUpdateWithdrawalAndReconnect(t *testing.T) {
	h := mediaRuleHunterFixture(t)
	runtime := h.mediaRules
	settings, err := (mediarules.Settings{}).Normalize()
	require.NoError(t, err)
	publisher, err := mediarules.New(settings.StoreConfig("receiver", "", nil, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, publisher.Close()) })
	rule := currentMediaRule()
	control, err := publisher.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	service, err := wire.NewService(publisher, wire.Limits{MaxMessageBytes: settings.MaxMessageBytes, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxRules: settings.MaxRules}, 10, func(ctx context.Context, hunterID string) error {
		remote, ok := peer.FromContext(ctx)
		if !ok || hunterID != "edge" {
			return fmt.Errorf("unexpected source")
		}
		return verifiedMediaIssuer(remote, "edge")
	})
	require.NoError(t, err)
	conn := mediaRuleTLSConnection(t, service)
	lifetime, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	setup, stopSetup := context.WithTimeout(lifetime, 2*time.Second)
	run, err := runtime.open(lifetime, setup, conn)
	require.NoError(t, err)
	stopSetup()
	require.True(t, runtime.ready())
	record := service.Application("edge")
	require.NotNil(t, record)
	require.True(t, record.Synchronized)
	require.Equal(t, uint32(1), record.ActiveRules)
	done := make(chan error, 1)
	go func() { done <- run() }()
	packet := mediaRuleTestPacket(t)
	_, matched := runtime.ResolveMedia(packet, "first")
	require.True(t, matched)
	require.NoError(t, publisher.ApplyDelta(control, 2, nil, []string{rule.ID}))
	require.Eventually(t, func() bool { _, matched := runtime.ResolveMedia(packet, "first"); return !matched }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return service.Application("edge").ActiveRules == 0 }, time.Second, time.Millisecond)
	cancel()
	require.Error(t, <-done)
	// A successor requires a complete fresh snapshot and cannot reuse its
	// predecessor's receiver even when the publisher generation is unchanged.
	require.NoError(t, runtime.invalidate())
	require.False(t, runtime.ready())
	rule.Revision = 3
	require.NoError(t, publisher.ApplyDelta(control, 3, []mediarules.Rule{rule}, nil))
	secondLifetime, secondCancel := context.WithCancel(t.Context())
	defer secondCancel()
	secondSetup, secondStop := context.WithTimeout(secondLifetime, 2*time.Second)
	secondRun, err := runtime.open(secondLifetime, secondSetup, conn)
	require.NoError(t, err)
	secondStop()
	_, matched = runtime.ResolveMedia(packet, "first")
	require.True(t, matched)
	secondDone := make(chan error, 1)
	go func() { secondDone <- secondRun() }()
	secondCancel()
	require.Error(t, <-secondDone)
}

type stalledMediaSnapshot struct {
	management.UnimplementedMediaControlServiceServer
}

func (stalledMediaSnapshot) SubscribeMediaRules(req *management.MediaRuleRequest, stream management.MediaControlService_SubscribeMediaRulesServer) error {
	if err := stream.Send(&management.MediaRuleUpdate{ProtocolVersion: wire.Version, Session: &management.MediaRuleSession{ProcessorId: req.ProcessorId, Generation: 1}, Revision: 1, SnapshotBegin: true}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
func TestHunterLiveMediaRulesRejectsUnsupportedOrIncompletePeer(t *testing.T) {
	for _, tt := range []struct {
		name    string
		service management.MediaControlServiceServer
	}{
		{"unsupported", nil}, {"incomplete snapshot", stalledMediaSnapshot{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := mediaRuleHunterFixture(t).mediaRules
			conn := mediaRuleTLSConnection(t, tt.service)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			run, err := runtime.open(t.Context(), ctx, conn)
			require.Error(t, err)
			require.Nil(t, run)
			require.False(t, runtime.ready())
		})
	}
}
func TestHunterLiveMediaRulesRejectsIssuerOutsideVerifiedSAN(t *testing.T) {
	runtime := mediaRuleHunterFixture(t).mediaRules
	runtime.settings.ProcessorID = "forged-issuer"
	conn := mediaRuleTLSConnection(t, stalledMediaSnapshot{})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	run, err := runtime.open(t.Context(), ctx, conn)
	require.ErrorContains(t, err, "media-rule processor identity")
	require.Nil(t, run)
	require.False(t, runtime.ready())
}

type otherProcessorMediaSnapshot struct {
	management.UnimplementedMediaControlServiceServer
}

func (otherProcessorMediaSnapshot) SubscribeMediaRules(_ *management.MediaRuleRequest, stream management.MediaControlService_SubscribeMediaRulesServer) error {
	return stream.Send(&management.MediaRuleUpdate{ProtocolVersion: wire.GrantVersion, Session: &management.MediaRuleSession{ProcessorId: "other-processor", Generation: 2}, Revision: 1, SnapshotBegin: true, SnapshotEnd: true})
}
func TestHunterMediaReplacementCannotInheritAnotherProcessorSession(t *testing.T) {
	runtime := mediaRuleHunterFixture(t).mediaRules
	rule := currentMediaRule()
	control, err := runtime.store.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, runtime.store.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	_, ok := runtime.ResolveMedia(mediaRuleTestPacket(t), "first")
	require.True(t, ok)
	conn := mediaRuleTLSConnection(t, otherProcessorMediaSnapshot{})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	run, err := runtime.open(t.Context(), ctx, conn)
	require.ErrorIs(t, err, mediarules.ErrAuthority)
	require.Nil(t, run)
	require.False(t, runtime.ready(), "a replacement control session must synchronize under the configured authenticated issuer")
	_, ok = runtime.ResolveMedia(mediaRuleTestPacket(t), "first")
	require.False(t, ok, "previous rule cannot be inherited by an unrecognized processor session")
}

func TestHunterPrefersAuthenticatedGenericControlWithImmutableVoIPRules(t *testing.T) {
	runtime := mediaRuleHunterFixture(t).mediaRules
	settings, err := (mediarules.Settings{}).Normalize()
	require.NoError(t, err)
	publisher, err := mediarules.New(settings.StoreConfig("receiver", "", nil, nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, publisher.Close()) })
	rule := currentMediaRule()
	rule.NotBefore = rule.NotBefore.Round(0)
	rule.ExpiresAt = rule.ExpiresAt.Round(0)
	rule.Scope = append(rule.Scope, mediarules.Scope{HunterID: "another", Domain: 1})
	remote := rule.Endpoints[0]
	remote.Key.Domain = 1
	rule.Endpoints = append(rule.Endpoints, remote)
	control, err := publisher.StartSession("receiver", rule.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []mediarules.Rule{rule}))
	authorize := func(ctx context.Context, hunterID string) error {
		remote, ok := peer.FromContext(ctx)
		if !ok || hunterID != "edge" {
			return status.Error(codes.PermissionDenied, "untrusted source")
		}
		return verifiedMediaIssuer(remote, "edge")
	}
	limits := learnedwire.Limits{MaxMessageBytes: settings.MaxMessageBytes, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxRules: settings.MaxRules}
	generic, err := learnedwire.NewService(publisher.Core(), limits, 10, authorize)
	require.NoError(t, err)
	legacy, err := wire.NewService(publisher, wire.Limits{MaxMessageBytes: settings.MaxMessageBytes, MaxSnapshotBytes: settings.MaxSnapshotBytes, MaxRules: settings.MaxRules}, 10, authorize)
	require.NoError(t, err)
	conn := mediaRuleTLSConnection(t, legacy, generic)
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	setup, stop := context.WithTimeout(lifetime, 2*time.Second)
	run, err := runtime.open(lifetime, setup, conn)
	require.NoError(t, err)
	stop()
	require.NotNil(t, generic.Application("edge"))
	require.Nil(t, legacy.Application("edge"), "a supported generic service must be preferred")
	installed := runtime.store.ActiveRules()
	require.Len(t, installed, 1)
	require.Equal(t, rule, installed[0], "the stream watermark cannot rewrite binding revisions or source scopes")
	packet := mediaRuleTestPacket(t)
	_, ok := runtime.ResolveMedia(packet, "first")
	require.True(t, ok)
	_, ok = runtime.ResolveMedia(packet, "other")
	require.False(t, ok, "another source's domain does not become local capture authority")
	done := make(chan error, 1)
	go func() { done <- run() }()
	require.NoError(t, publisher.ApplyDelta(control, 2, nil, []string{rule.ID}))
	require.Eventually(t, func() bool { _, ok := runtime.ResolveMedia(packet, "first"); return !ok }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { a := generic.Application("edge"); return a != nil && a.ActiveBindings == 0 }, time.Second, time.Millisecond)
	cancel()
	require.Error(t, <-done)
}

type deniedLearnedControl struct {
	learnedpb.UnimplementedLearnedControlServiceServer
}

func (deniedLearnedControl) SubscribeLearnedRules(*learnedpb.LearnedRuleRequest, learnedpb.LearnedControlService_SubscribeLearnedRulesServer) error {
	return status.Error(codes.PermissionDenied, "source denied")
}
func TestHunterGenericAuthorizationFailureCannotDowngrade(t *testing.T) {
	runtime := mediaRuleHunterFixture(t).mediaRules
	conn := mediaRuleTLSConnection(t, stalledMediaSnapshot{}, deniedLearnedControl{})
	setup, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	run, err := runtime.open(t.Context(), setup, conn)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, run)
	require.False(t, runtime.ready())
}

// frozenVersionOneMediaPeer models the pre-grant contract without calling the
// current version-aware service implementation.
type frozenVersionOneMediaPeer struct {
	management.UnimplementedMediaControlServiceServer
	versions     chan uint32
	versionError string
}

func (s *frozenVersionOneMediaPeer) SubscribeMediaRules(req *management.MediaRuleRequest, stream management.MediaControlService_SubscribeMediaRulesServer) error {
	s.versions <- req.ProtocolVersion
	if req.ProtocolVersion != 1 {
		return status.Error(codes.InvalidArgument, s.versionError)
	}
	rule := currentMediaRule()
	if err := stream.Send(&management.MediaRuleUpdate{ProtocolVersion: 1, Session: &management.MediaRuleSession{ProcessorId: "receiver", Generation: 1}, Revision: 1, SnapshotBegin: true, SnapshotEnd: true, Rules: []*management.MediaRule{wire.EncodeRule(rule)}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (*frozenVersionOneMediaPeer) ReportMediaRuleStatus(context.Context, *management.MediaRuleApplication) (*management.MediaRuleReceipt, error) {
	return &management.MediaRuleReceipt{Accepted: true}, nil
}
func TestHunterLegacyVersionFallbackIsExplicitAndOrdinaryOnly(t *testing.T) {
	for _, test := range []struct {
		name, message     string
		protected, accept bool
	}{
		{name: "explicit old version", message: "unsupported media-rule subscription", accept: true},
		{name: "malformed request", message: "malformed media-rule request"},
		{name: "grant contract required", message: "unsupported media-rule subscription", protected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := mediaRuleHunterFixture(t).mediaRules
			if test.protected {
				runtime.capturePolicyCurrent = func(uint64) bool { return true }
			}
			service := &frozenVersionOneMediaPeer{versions: make(chan uint32, 4), versionError: test.message}
			conn := mediaRuleTLSConnection(t, service)
			lifetime, cancel := context.WithCancel(t.Context())
			defer cancel()
			setup, stop := context.WithTimeout(lifetime, time.Second)
			defer stop()
			run, err := runtime.open(lifetime, setup, conn)
			require.Equal(t, uint32(2), <-service.versions)
			if !test.accept {
				require.Error(t, err)
				require.Nil(t, run)
				require.Empty(t, service.versions)
				return
			}
			require.NoError(t, err)
			require.Equal(t, uint32(1), <-service.versions)
			_, ok := runtime.ResolveMedia(mediaRuleTestPacket(t), "first")
			require.True(t, ok)
			done := make(chan error, 1)
			go func() { done <- run() }()
			cancel()
			require.Error(t, <-done)
		})
	}
}
