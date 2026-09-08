//go:build li

package delivery

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestFailedBackgroundDialPreservesPublishedConnectionState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	defer m.Stop()
	m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	m.config.DialTimeout = time.Second
	m.config.InitialBackoff = time.Hour
	state.backoff = time.Hour
	state.state = connStateDisconnected
	state.dest.Port = listener.Addr().(*net.TCPAddr).Port
	m.wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.connectDestination(did)
	}()
	peer, err := listener.Accept()
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var hello [1]byte
	_, err = peer.Read(hello[:])
	require.NoError(t, err)
	// A second dial publishes a healthy association while the initial dial
	// remains inside its TLS handshake.
	primary, primaryPeer := tlsPipe(t)
	defer primaryPeer.NetConn().Close()
	require.True(t, m.publishPooledConnection(did, state, state.generation, primary, PDUTypeX2))
	require.True(t, m.IsConnected(did))
	require.NoError(t, peer.Close())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background dial did not finish")
	}
	require.True(t, m.IsConnected(did), "a failed competing dial must not mark the healthy association disconnected")
	stats, err := m.Stats(did)
	require.NoError(t, err)
	require.Equal(t, "connected", stats.ConnectionState)
	require.EqualValues(t, 1, stats.X2Connections)
	require.EqualValues(t, 1, stats.ConnectAttempts)
	require.EqualValues(t, 1, stats.ConnectFailures)
	require.Empty(t, stats.LastError, "obsolete dial failure must not replace the healthy connection status")
	state.mu.RLock()
	reconnectScheduled := state.reconnectTimer != nil
	state.mu.RUnlock()
	require.False(t, reconnectScheduled, "healthy association must not acquire another reconnect loop")
}

type delayedCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *delayedCloseConn) Close() error {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Conn.Close()
}

func TestInvalidationPreservesConnectionPublishedDuringClose(t *testing.T) {
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	defer m.Stop()
	state.backoff = time.Hour
	oldNet, peer := net.Pipe()
	defer peer.Close()
	delayed := &delayedCloseConn{Conn: oldNet, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(delayed.release) }) }
	defer release()
	old := tls.Client(delayed, &tls.Config{MinVersion: tls.VersionTLS12})
	m.registerConnection(state, old, PDUTypeX2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.InvalidateConnection(did, old)
	}()
	<-delayed.entered
	primary, primaryPeer := tlsPipe(t)
	defer primaryPeer.NetConn().Close()
	require.True(t, m.publishPooledConnection(did, state, state.generation, primary, PDUTypeX2))
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invalidation did not finish")
	}
	require.True(t, m.IsConnected(did), "closing the removed transport must not disconnect its replacement")
	stats, err := m.Stats(did)
	require.NoError(t, err)
	require.Equal(t, "connected", stats.ConnectionState)
	require.EqualValues(t, 1, stats.X2Connections)
}
