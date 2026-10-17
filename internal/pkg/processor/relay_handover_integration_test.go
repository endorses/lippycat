//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type relayTestPKI struct {
	ca     *x509.Certificate
	key    ed25519.PrivateKey
	pool   *x509.CertPool
	caFile string
}

func newRelayTestPKI(t *testing.T) relayTestPKI {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	file := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return relayTestPKI{ca, key, pool, file}
}

func (p relayTestPKI) identity(t *testing.T, id string) (tls.Certificate, string, string) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{id}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, public, p.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certFile, keyFile
}

func serveRelayTestProcessor(t *testing.T, p *Processor, pair tls.Certificate, roots *x509.CertPool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	p.registerGRPCServices(server)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})
	return listener.Addr().String()
}

// Exercise production registration, direct hunter admission, relay queue/sender,
// delegated central ingress, and a replacement relay processor in one topology.
func TestRelayHandoverPreservesMultipleOriginsAtCommonUpstream(t *testing.T) {
	pki := newRelayTestPKI(t)
	central, err := newTestProcessor(t, Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", RelayOrigins: map[string][]string{"relay-a": {"edge-a", "edge-b"}, "relay-b": {"edge-a", "edge-b"}}})
	require.NoError(t, err)
	pair, _, _ := pki.identity(t, "central")
	address := serveRelayTestProcessor(t, central, pair, pki.pool)
	out := central.subscriberManager.Add("common-observer")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sequence := map[string]uint64{}
	for _, relayID := range []string{"relay-a", "relay-b"} {
		pair, certFile, keyFile := pki.identity(t, relayID)
		relay, err := newTestProcessor(t, Config{ProcessorID: relayID, ListenAddr: "127.0.0.1:0", UpstreamAddr: address, TLSEnabled: true, TLSCAFile: pki.caFile, TLSCertFile: certFile, TLSKeyFile: keyFile})
		require.NoError(t, err)
		relayAddress := serveRelayTestProcessor(t, relay, pair, pki.pool)
		require.NoError(t, relay.upstreamManager.Start())
		require.Eventually(t, relay.upstreamManager.IsConnected, 5*time.Second, 5*time.Millisecond)
		for _, origin := range []string{"edge-a", "edge-b"} {
			pair, _, _ := pki.identity(t, origin)
			conn, err := grpc.NewClient(relayAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
			require.NoError(t, err)
			response, err := management.NewManagementServiceClient(conn).RegisterHunter(ctx, &management.HunterRegistration{HunterId: origin, Hostname: origin, Interfaces: []string{"eth0"}})
			require.NoError(t, err)
			require.True(t, response.Accepted)
			stream, err := data.NewDataServiceClient(conn).StreamPackets(ctx)
			require.NoError(t, err)
			sequence[origin]++
			payload := make([]byte, 64)
			copy(payload, origin+relayID)
			batch := &data.PacketBatch{HunterId: origin, ProducerSessionId: origin + "-session", CaptureEpoch: "unchanged-epoch", Sequence: sequence[origin], TimestampNs: time.Now().UnixNano(), Packets: []*data.CapturedPacket{{Data: payload, TimestampNs: time.Now().UnixNano(), CaptureLength: 64, OriginalLength: 64, LinkType: 1, InterfaceName: "eth0"}}}
			require.NoError(t, stream.Send(batch))
			_, err = stream.Recv()
			require.NoError(t, err)
			select {
			case got := <-out:
				require.Equal(t, origin, got.HunterId)
				require.Equal(t, batch.Sequence, got.Sequence)
				require.Equal(t, batch.ProducerSessionId, got.ProducerSessionId)
				require.Equal(t, batch.CaptureEpoch, got.CaptureEpoch)
				require.Equal(t, batch.Packets[0].TimestampNs, got.Packets[0].TimestampNs)
				require.Equal(t, "eth0", got.Packets[0].InterfaceName)
				require.Equal(t, payload, got.Packets[0].Data)
			case <-ctx.Done():
				t.Fatal("packet did not reach common upstream")
			}
			require.NoError(t, stream.CloseSend())
			require.NoError(t, conn.Close())
		}
		// A different relay accepts the next capture sequence; there is no
		// reidentification of the original producer at the common upstream.
		require.NoError(t, relay.Shutdown())
	}
	require.Equal(t, uint64(4), central.packetsReceived.Load())
}
