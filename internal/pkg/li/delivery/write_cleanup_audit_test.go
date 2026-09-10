//go:build li

package delivery

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type failDeadlineClearConn struct {
	net.Conn
	failClear   atomic.Bool
	beforeClear func()
}

func (c *failDeadlineClearConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() && c.beforeClear != nil {
		c.beforeClear()
	}
	if deadline.IsZero() && c.failClear.Load() {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func writeCleanupTLSPipe(t *testing.T, transport *failDeadlineClearConn) (*tls.Conn, *tls.Conn) {
	t.Helper()
	certPEM, keyPEM := generateTestCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	clientNet, serverNet := net.Pipe()
	t.Cleanup(func() { require.NoError(t, clientNet.Close()) })
	t.Cleanup(func() { require.NoError(t, serverNet.Close()) })
	transport.Conn = clientNet
	client := tls.Client(transport, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // test-only pipe
	server := tls.Server(serverNet, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	require.NoError(t, client.Handshake())
	require.NoError(t, <-handshake)
	return client, server
}

func TestCompletedWriteDeadlineCleanupRemainsUncertain(t *testing.T) {
	transport := &failDeadlineClearConn{}
	client, server := writeCleanupTLSPipe(t, transport)
	transport.failClear.Store(true)
	m, state := testKeepaliveManager(uuid.New())
	m.registerConnection(state, client, PDUTypeX3)
	payload := []byte("fully accepted before deadline cleanup fails")
	received := make([]byte, len(payload))
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(server, received); read <- err }()
	err := m.WritePDUUntil(client, payload, time.Now().Add(time.Second))
	require.NoError(t, <-read)
	require.Equal(t, payload, received)
	require.ErrorIs(t, err, net.ErrClosed)
	require.ErrorIs(t, err, ErrUncertainWrite, "deadline cleanup cannot classify already transmitted content as unsent")
}

func TestLifecycleCancellationAfterCompletedWriteRecordsSuccess(t *testing.T) {
	transport := &failDeadlineClearConn{}
	conn, peer := writeCleanupTLSPipe(t, transport)
	written := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	releaseWrite := func() { once.Do(func() { close(release) }) }
	transport.beforeClear = func() { close(written); <-release }
	did, xid := uuid.New(), uuid.New()
	manager, state := testKeepaliveManager(did)
	manager.registerConnection(state, conn, PDUTypeX3)
	manager.ReleaseConnection(did, conn)
	config := DefaultClientConfig()
	config.ShutdownTimeout = 10 * time.Millisecond
	client := NewClient(manager, config)
	client.Start()
	t.Cleanup(func() {
		releaseWrite()
		client.Stop()
		manager.Stop()
	})
	payload := []byte("completed before lifecycle cancellation")
	received := make([]byte, len(payload))
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(peer, received); read <- err }()
	require.NoError(t, client.SendX3WithMetadata(xid, []uuid.UUID{did}, payload, DeliveryMetadata{TaskGeneration: 1}))
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("transport did not complete the frame")
	}
	require.NoError(t, <-read)
	require.Equal(t, payload, received)
	client.CancelTask(xid, 1)
	releaseWrite()
	require.Eventually(t, func() bool {
		stats := client.Stats()
		return stats.X3Sent+stats.X3Dropped == 1
	}, time.Second, time.Millisecond)
	stats := client.Stats()
	require.Equal(t, uint64(1), stats.X3Sent)
	require.Zero(t, stats.X3Dropped, "lifecycle cancellation cannot undo a completed local write")
	require.Zero(t, stats.QueueDepth)
	require.Zero(t, stats.QueueBytes)
	require.Zero(t, stats.PhysicalQueueBytes)
}
