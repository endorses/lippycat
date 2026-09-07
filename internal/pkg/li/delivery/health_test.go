//go:build li

package delivery

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestinationHealthSnapshot(t *testing.T) {
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	m.config.X3KeepaliveTimeP1 = time.Minute
	m.config.X3KeepaliveTimeP2 = 3 * time.Minute
	atomic.StoreInt32(&state.state, connStateDisconnected)
	state.lastError = errors.New("connection refused")
	stats, err := m.Stats(did)
	require.NoError(t, err)
	assert.Equal(t, "disconnected", stats.ConnectionState)
	assert.Equal(t, "connection refused", stats.LastError)
	assert.Zero(t, stats.X2Connections)
	assert.Zero(t, stats.X3Connections)
	assert.True(t, stats.X2Keepalive.Enabled)
	assert.Equal(t, m.config.X2KeepaliveTimeP1, stats.X2Keepalive.TimeP1)
	assert.Equal(t, m.config.X2KeepaliveTimeP2, stats.X2Keepalive.TimeP2)
	assert.False(t, stats.X3Keepalive.Enabled)
	assert.Equal(t, time.Minute, stats.X3Keepalive.TimeP1)
	assert.Equal(t, 3*time.Minute, stats.X3Keepalive.TimeP2)
	assert.Equal(t, stats, m.AllStats()[did])

	atomic.StoreInt32(&state.state, connStateConnecting)
	assert.Equal(t, "connecting", m.AllStats()[did].ConnectionState)
	atomic.StoreInt32(&state.state, connStateConnected)
	state.lastError = nil
	// Registered connections are checked out, so idle pool length is zero.
	m.registerConnection(state, &tls.Conn{}, PDUTypeX2)
	m.registerConnection(state, &tls.Conn{}, PDUTypeX2)
	m.registerConnection(state, &tls.Conn{}, PDUTypeX3)
	// An untracked runtime must not count toward live destination connections.
	m.connectionRuntime.Store(&tls.Conn{}, &connectionRuntime{iface: PDUTypeX3})
	state.stats.X2Keepalive.LastValidACK = time.Now().Add(-time.Minute)
	state.stats.X3Keepalive.LastValidACK = time.Now().Add(-2 * time.Minute)
	for _, snapshot := range []DestinationStats{m.AllStats()[did], func() DestinationStats {
		s, err := m.Stats(did)
		require.NoError(t, err)
		return s
	}()} {
		assert.Equal(t, "connected", snapshot.ConnectionState)
		assert.Empty(t, snapshot.LastError)
		assert.Equal(t, uint64(2), snapshot.X2Connections)
		assert.Equal(t, uint64(1), snapshot.X3Connections)
		assert.GreaterOrEqual(t, snapshot.X2Keepalive.ACKAge, time.Minute)
		assert.GreaterOrEqual(t, snapshot.X3Keepalive.ACKAge, 2*time.Minute)
	}
	assert.Zero(t, state.stats.X2Keepalive.ACKAge, "snapshots must not mutate stored counters")
}

func TestStalledReaderDeliveryHealth(t *testing.T) {
	conn, peer := tlsPipe(t)
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	m.registerConnection(state, conn, PDUTypeX2)
	m.ReleaseConnection(did, conn)
	config := DefaultClientConfig()
	config.SendTimeout = 50 * time.Millisecond
	config.ShutdownTimeout = 10 * time.Millisecond
	config.RetryInitialBackoff = time.Hour
	config.RetryMaxBackoff = time.Hour
	client := NewClient(m, config)
	client.Start()
	t.Cleanup(func() {
		assert.NoError(t, peer.NetConn().Close())
		client.Stop()
		m.Stop()
	})
	// The TLS handshake succeeded, but the receiver never reads product bytes.
	require.NoError(t, client.SendX2(uuid.New(), []uuid.UUID{did}, []byte("product")))
	require.Eventually(t, func() bool {
		return m.AllStats()[did].WriteErrors > 0
	}, 2*time.Second, 10*time.Millisecond)
	// Let invalidation finish its TLS close_notify without waiting on the
	// unresponsive pipe peer, then inspect the dispatcher's retry accounting.
	require.NoError(t, peer.NetConn().Close())
	require.Eventually(t, func() bool {
		return client.DestinationStats()[did].Retries > 0
	}, 2*time.Second, 10*time.Millisecond)
	queue := client.DestinationStats()[did]
	assert.Equal(t, 1, queue.X2QueueDepth)
	assert.Greater(t, queue.X2OldestAge, time.Duration(0))
	assert.Contains(t, queue.LastError, "timeout")
	assert.True(t, queue.LastSuccess.IsZero())
	assert.Zero(t, queue.X2Sent)
	connection := m.AllStats()[did]
	assert.Positive(t, connection.WriteErrors)
	assert.Zero(t, connection.X2Connections)
	assert.Zero(t, connection.PDUsSent)
}
