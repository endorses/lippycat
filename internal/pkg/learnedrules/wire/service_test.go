package wire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	pb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func tlsIdentities(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(id string, serial int64) tls.Certificate {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{id}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		d, err := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, key)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{d}, PrivateKey: k}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf("processor", 2)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "processor", RootCAs: pool, Certificates: []tls.Certificate{leaf("hunter", 3)}}
}
func authenticatedSource(ctx context.Context, id string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 {
		return status.Error(codes.Unauthenticated, "unverified peer")
	}
	if err := info.State.VerifiedChains[0][0].VerifyHostname(id); err != nil {
		return status.Error(codes.PermissionDenied, "wrong source certificate")
	}
	if id != "hunter" {
		return status.Error(codes.PermissionDenied, "source registration missing")
	}
	return nil
}
func grpcClient(t *testing.T, service *Service) pb.LearnedControlServiceClient {
	t.Helper()
	serverTLS, clientTLS := tlsIdentities(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	if service != nil {
		pb.RegisterLearnedControlServiceServer(server, service)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, listener.Close())
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("grpc server did not stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///processor", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return pb.NewLearnedControlServiceClient(conn)
}
func receiveSnapshot(t *testing.T, stream pb.LearnedControlService_SubscribeLearnedRulesClient, receiver *Receiver) *pb.LearnedRuleUpdate {
	t.Helper()
	for {
		u, err := stream.Recv()
		require.NoError(t, err)
		require.NoError(t, receiver.Apply(u))
		if u.SnapshotEnd {
			return u
		}
	}
}
func TestAuthenticatedGenericControlDiagnosticLifecycle(t *testing.T) {
	publisher := testStore(t, "")
	binding := testBinding(0)
	binding.Selectors[0].Protocol = learnedrules.TCP
	binding.Selectors[0].Direction = learnedrules.Source
	control, err := publisher.StartSession("processor", binding.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []learnedrules.Binding{binding}))
	service, err := NewService(publisher, testLimits, 1, authenticatedSource)
	require.NoError(t, err)
	client := grpcClient(t, service)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := &pb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: "hunter", ProcessorId: "processor", Capabilities: capabilities()}
	stream, err := client.SubscribeLearnedRules(ctx, request)
	require.NoError(t, err)
	hunter := testStore(t, "hunter")
	receiver, err := NewReceiver(hunter, "processor", testLimits, capabilities())
	require.NoError(t, err)
	initial := receiveSnapshot(t, stream, receiver)
	require.Equal(t, binding.Revision, hunter.ActiveRules()[0].Revision)
	packet := learnedrules.Packet{Protocol: learnedrules.TCP, Source: learnedrules.Endpoint{Address: binding.Selectors[0].Address, Port: binding.Selectors[0].Port}, Destination: learnedrules.Endpoint{Address: netip.MustParseAddr("192.0.2.2"), Port: 80}}
	require.Len(t, hunter.Match(packet, 4).Bindings, 1)
	packet.Source, packet.Destination = packet.Destination, packet.Source
	require.Empty(t, hunter.Match(packet, 4).Bindings)
	report := &pb.LearnedRuleApplication{HunterId: "hunter", Session: initial.Session, SubscriptionId: initial.SubscriptionId, AppliedRevision: initial.Revision, Synchronized: true, ActiveBindings: 1, ActiveSelectors: 1}
	receipt, err := client.ReportLearnedRuleStatus(ctx, report)
	require.NoError(t, err)
	require.True(t, receipt.Accepted)
	require.True(t, service.Application("hunter").Synchronized)
	// One authenticated source cannot report for another source, even over mTLS.
	report.HunterId = "other"
	_, err = client.ReportLearnedRuleStatus(ctx, report)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	report.HunterId = "hunter"
	// Reconnect changes the report token and invalidates older stream status.
	replacement, err := client.SubscribeLearnedRules(ctx, request)
	require.NoError(t, err)
	replacementReceiver, err := NewReceiver(hunter, "processor", testLimits, capabilities())
	require.NoError(t, err)
	next := receiveSnapshot(t, replacement, replacementReceiver)
	require.NotEqual(t, initial.SubscriptionId, next.SubscriptionId)
	_, err = client.ReportLearnedRuleStatus(ctx, report)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	report.SubscriptionId = next.SubscriptionId
	report.AppliedRevision = next.Revision
	_, err = client.ReportLearnedRuleStatus(ctx, report)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplyDelta(control, 2, nil, []string{binding.ID}))
	removed := receiveSnapshot(t, replacement, replacementReceiver)
	require.Greater(t, removed.Revision, next.Revision)
	require.Empty(t, hunter.ActiveRules())
	report.AppliedRevision = removed.Revision
	report.Error = "backend projection incomplete"
	_, err = client.ReportLearnedRuleStatus(ctx, report)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	report.Synchronized = false
	_, err = client.ReportLearnedRuleStatus(ctx, report)
	require.NoError(t, err)
	require.Equal(t, "backend projection incomplete", service.Application("hunter").Error)
}
func TestCapabilitiesRejectBeforeDisclosureAndAuthenticationCannotFallback(t *testing.T) {
	publisher := testStore(t, "")
	binding := testBinding(0)
	control, err := publisher.StartSession("processor", binding.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(control, 1, []learnedrules.Binding{binding}))
	service, err := NewService(publisher, testLimits, 1, authenticatedSource)
	require.NoError(t, err)
	client := grpcClient(t, service)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := &pb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: "impostor", ProcessorId: "processor", Capabilities: capabilities()}
	stream, err := client.SubscribeLearnedRules(ctx, request)
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, LegacyFallbackAllowed(err, true))
	request.HunterId = "hunter"
	request.Capabilities[0].ContextVersion = 2
	stream, err = client.SubscribeLearnedRules(ctx, request)
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.False(t, LegacyFallbackAllowed(err, false))
	require.Zero(t, publisher.Status().Subscribers)
}

type immediateReportStream struct {
	grpc.ServerStream
	ctx       context.Context
	service   *Service
	cancel    context.CancelFunc
	reportErr error
}

func (s *immediateReportStream) Context() context.Context { return s.ctx }
func (s *immediateReportStream) Send(u *pb.LearnedRuleUpdate) error {
	if u.SnapshotEnd {
		_, s.reportErr = s.service.ReportLearnedRuleStatus(s.ctx, &pb.LearnedRuleApplication{HunterId: "hunter", Session: u.Session, SubscriptionId: u.SubscriptionId, AppliedRevision: u.Revision, Synchronized: true})
		s.cancel()
	}
	return nil
}
func TestEffectiveReportCanArriveBeforeFinalSendReturns(t *testing.T) {
	publisher := testStore(t, "")
	b := testBinding(0)
	c, err := publisher.StartSession("processor", b.Session)
	require.NoError(t, err)
	require.NoError(t, publisher.ApplySnapshot(c, 1, []learnedrules.Binding{b}))
	service, err := NewService(publisher, testLimits, 1, func(context.Context, string) error { return nil })
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &immediateReportStream{ctx: ctx, service: service, cancel: cancel}
	require.ErrorIs(t, service.SubscribeLearnedRules(&pb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: "hunter", ProcessorId: "processor", Capabilities: capabilities()}, stream), context.Canceled)
	require.NoError(t, stream.reportErr)
}

func TestNewClientRecognizesExplicitOldServerWithoutDowngradingOtherErrors(t *testing.T) {
	client := grpcClient(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := client.SubscribeLearnedRules(ctx, &pb.LearnedRuleRequest{ProtocolVersion: 1, HunterId: "hunter", ProcessorId: "processor", Capabilities: capabilities()})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.True(t, LegacyFallbackAllowed(err, true))
	require.False(t, LegacyFallbackAllowed(err, false))
}
