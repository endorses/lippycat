//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func relayTestConnection(t *testing.T, p *Processor, peerID string) *grpc.ClientConn {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{peerID}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	data.RegisterRelayDataServiceServer(server, p)
	data.RegisterDataServiceServer(server, p)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		err := <-done
		if !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
		require.NoError(t, listener.Close())
	})
	connection, err := grpc.NewClient("passthrough:///relay-ingress", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: peerID})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	return connection
}

func TestRelayIngressPreservesMultipleOriginsAndSessionIdentity(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", RelayOrigins: map[string][]string{"relay.test": {"edge-a", "edge-b"}}})
	require.NoError(t, err)
	require.NoError(t, p.downstreamManager.Register("relay.test", "127.0.0.1:1", "test"))
	out := p.subscriberManager.Add("relay-observer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := data.NewRelayDataServiceClient(relayTestConnection(t, p, "relay.test")).StreamRelayPackets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1}))
	_, err = stream.Recv()
	require.NoError(t, err)
	for _, origin := range []string{"edge-a", "edge-b"} {
		batch := &data.PacketBatch{HunterId: origin, ProducerSessionId: "capture-session", CaptureEpoch: "capture-epoch", Sequence: 1, TimestampNs: time.Now().UnixNano(), Packets: []*data.CapturedPacket{{Data: make([]byte, 64), CaptureLength: 64, OriginalLength: 64, LinkType: 1, InterfaceName: "eth0", TimestampNs: time.Now().UnixNano()}}}
		require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1, Batch: batch}))
		ack, err := stream.Recv()
		require.NoError(t, err)
		require.Equal(t, uint64(1), ack.AckSequence)
		select {
		case received := <-out:
			require.Equal(t, origin, received.HunterId)
			require.Equal(t, batch.ProducerSessionId, received.ProducerSessionId)
			require.Equal(t, batch.CaptureEpoch, received.CaptureEpoch)
			require.Equal(t, batch.Packets[0].Data, received.Packets[0].Data)
		case <-ctx.Done():
			t.Fatal("relayed origin did not reach central subscriber")
		}
	}
	require.Equal(t, uint64(2), p.packetsReceived.Load())
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1, Batch: &data.PacketBatch{HunterId: "forged", Sequence: 2}}))
	_, err = stream.Recv()
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, uint64(2), p.packetsReceived.Load())
}

func TestRelayIngressRequiresVerifiedDelegationAndCurrentRegistration(t *testing.T) {
	for _, tc := range []struct {
		name, peer, relay string
		register          bool
		expected          codes.Code
	}{
		{"wrong certificate", "other.test", "relay.test", true, codes.Unauthenticated},
		{"no origin delegation", "untrusted.test", "untrusted.test", true, codes.PermissionDenied},
		{"no registration", "relay.test", "relay.test", false, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", RelayOrigins: map[string][]string{"relay.test": {"edge-a"}}})
			require.NoError(t, err)
			if tc.register {
				require.NoError(t, p.downstreamManager.Register(tc.relay, "127.0.0.1:1", "test"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream, err := data.NewRelayDataServiceClient(relayTestConnection(t, p, tc.peer)).StreamRelayPackets(ctx)
			require.NoError(t, err)
			require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: tc.relay, ProtocolVersion: 1}))
			_, err = stream.Recv()
			require.Equal(t, tc.expected, status.Code(err))
		})
	}
}

func TestRelayIngressRegistrationReplacementInvalidatesOldStream(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", RelayOrigins: map[string][]string{"relay.test": {"edge-a"}}})
	require.NoError(t, err)
	require.NoError(t, p.downstreamManager.Register("relay.test", "127.0.0.1:1", "test"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := data.NewRelayDataServiceClient(relayTestConnection(t, p, "relay.test")).StreamRelayPackets(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1}))
	_, err = stream.Recv()
	require.NoError(t, err)
	require.NoError(t, p.downstreamManager.Register("relay.test", "127.0.0.1:1", "replacement"))
	require.NoError(t, stream.Send(&data.RelayPacketMessage{RelayId: "relay.test", ProtocolVersion: 1, Batch: &data.PacketBatch{HunterId: "edge-a", Sequence: 1}}))
	_, err = stream.Recv()
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
