//go:build li

package delivery

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAuditMutualTLSOutageFanoutDrainsUnderLiveTraffic(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	ca := x509.NewCertPool()
	require.True(t, ca.AppendCertsFromPEM(certPEM))
	managerConfig := testConfigWithCerts(t)
	managerConfig.DialTimeout = 100 * time.Millisecond
	managerConfig.InitialBackoff = 10 * time.Millisecond
	managerConfig.MaxBackoff = 50 * time.Millisecond
	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()
	var servers []*restartableMDF
	var destinations []uuid.UUID
	for i := 0; i < 2; i++ {
		server := newRestartableMDF(t, certPEM, keyPEM, 0)
		server.Start(t)
		defer server.Close()
		did := uuid.New()
		require.NoError(t, manager.AddDestination(&li.Destination{DID: did, Address: "127.0.0.1", Port: server.Port(), ProtocolType: "X2", X2Enabled: true, TLSConfig: &tls.Config{RootCAs: ca, Certificates: manager.tlsConfig.Certificates, ServerName: "localhost", MinVersion: tls.VersionTLS12}}))
		servers = append(servers, server)
		destinations = append(destinations, did)
	}
	require.Eventually(t, func() bool { return servers[0].verified.Load() > 0 && servers[1].verified.Load() > 0 }, 3*time.Second, time.Millisecond)
	for _, server := range servers {
		server.Stop()
	}
	require.Eventually(t, func() bool { return !manager.IsConnected(destinations[0]) && !manager.IsConnected(destinations[1]) }, time.Second, time.Millisecond)
	config := DefaultClientConfig()
	config.QueueSize = 128
	config.X2QueueBytes = 1 << 20
	config.X3QueueBytes = 1 << 20
	config.SendTimeout = 200 * time.Millisecond
	config.RetryInitialBackoff = 10 * time.Millisecond
	config.RetryMaxBackoff = 50 * time.Millisecond
	config.ShutdownTimeout = time.Second
	client := NewClient(manager, config)
	require.NoError(t, client.Err())
	client.Start()
	defer client.Stop()
	xid := uuid.New()
	expected := make([]string, 64)
	send := func(i int) {
		expected[i] = fmt.Sprintf("%04d:", i) + strings.Repeat("x", 32+i*17)
		wire := make([]byte, 4+len(expected[i]))
		binary.BigEndian.PutUint32(wire[:4], uint32(len(expected[i])))
		copy(wire[4:], expected[i])
		require.NoError(t, client.SendX2(xid, destinations, wire))
	}
	for i := 0; i < 32; i++ {
		send(i)
	}
	require.EqualValues(t, 64, client.Stats().QueueDepth)
	for _, server := range servers {
		server.Start(t)
	}
	for i := 32; i < 64; i++ {
		send(i)
		time.Sleep(time.Millisecond)
	}
	for _, server := range servers {
		for _, want := range expected {
			require.Equal(t, want, server.Receive(t, 3*time.Second))
		}
		require.GreaterOrEqual(t, server.verified.Load(), int64(2))
	}
	require.Eventually(t, func() bool { return client.Stats().QueueDepth == 0 }, time.Second, time.Millisecond)
	require.EqualValues(t, 128, client.Stats().X2Sent)
	require.Zero(t, client.Stats().X2Dropped)
	require.Zero(t, client.Stats().QueueBytes)
	require.Zero(t, client.Stats().PhysicalQueueBytes)
}
