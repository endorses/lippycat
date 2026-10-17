//go:build all

package hunter

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func mediaRuleTLSConnection(t *testing.T, service management.MediaControlServiceServer) *grpc.ClientConn {
	t.Helper()
	pair, _, _, roots := rawIntegrationCertificate(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	if service != nil {
		management.RegisterMediaControlServiceServer(server, service)
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
