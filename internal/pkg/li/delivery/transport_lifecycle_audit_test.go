//go:build li

package delivery

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDialCancellationInterruptsTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	m.config.DialTimeout = 10 * time.Second
	state.dest.Port = listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := m.dialDestinationWithContext(ctx, state)
		if conn != nil {
			conn.NetConn().Close()
		}
		result <- err
	}()
	peer, err := listener.Accept()
	require.NoError(t, err)
	defer peer.Close()
	// Observe the ClientHello so cancellation occurs inside the TLS handshake.
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var hello [1]byte
	_, err = peer.Read(hello[:])
	require.NoError(t, err)
	cancel()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("canceled TLS handshake remained blocked until its original deadline")
	}
}

func TestBackgroundDialRejectsReplacedDestination(t *testing.T) {
	for _, background := range []string{"initial", "interface"} {
		t.Run(background, func(t *testing.T) {
			cert, key := generateTestCert(t)
			listener, port := startTestTLSServer(t, cert, key)
			defer listener.Close()
			did := uuid.New()
			m, state := testKeepaliveManager(did)
			m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			m.config.DialTimeout = 5 * time.Second
			m.config.InitialBackoff = time.Millisecond
			m.config.X2KeepaliveEnabled = false
			reachedHandshake := make(chan struct{})
			releaseHandshake := make(chan struct{})
			state.dest = &li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
				VerifyConnection: func(tls.ConnectionState) error { close(reachedHandshake); <-releaseHandshake; return nil },
			}}
			atomic.StoreInt32(&state.state, connStateDisconnected)
			m.wg.Add(1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				if background == "initial" {
					m.connectDestination(did)
				} else {
					m.reconnectInterface(did, PDUTypeX2)
				}
			}()
			<-reachedHandshake
			// Perform the same close/generation/pool replacement as endpoint mutation,
			// without starting an unrelated new dial that could obscure the old one.
			m.mu.Lock()
			m.closeDestinationLocked(did, state)
			state.mu.Lock()
			state.dest = &li.Destination{DID: did, Address: "127.0.0.1", Port: 1, X2Enabled: true}
			state.pool = newConnPool(1)
			state.interfacePools = map[PDUType]*connPool{PDUTypeX2: newConnPool(1), PDUTypeX3: newConnPool(1)}
			state.mu.Unlock()
			m.mu.Unlock()
			close(releaseHandshake)
			<-finished
			// Always close any incorrectly installed association before reporting a
			// failure, so the pre-fix regression does not leak transport workers.
			state.mu.RLock()
			connections := len(state.connections)
			pooled := state.interfacePools[PDUTypeX2].size()
			state.mu.RUnlock()
			m.Stop()
			require.Zero(t, connections, "superseded transport registered against replacement destination")
			require.Zero(t, pooled, "superseded transport published into replacement interface pool")
		})
	}
}

func TestManagerStopCancelsBackgroundTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	m, state := testKeepaliveManager(uuid.New())
	m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	m.config.DialTimeout = 10 * time.Second
	state.dest.Port = listener.Addr().(*net.TCPAddr).Port
	atomic.StoreInt32(&state.state, connStateDisconnected)
	m.wg.Add(1)
	go m.connectDestination(state.dest.DID)
	peer, err := listener.Accept()
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var hello [1]byte
	_, err = peer.Read(hello[:])
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() { m.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("manager Stop did not cancel its background handshake")
	}
}

func TestDeliveryDestinationDefinitionsAreCopies(t *testing.T) {
	m, err := NewManager(testConfigWithCertsDest(t))
	require.NoError(t, err)
	defer m.Stop()
	original := &li.Destination{DID: uuid.New(), Address: "127.0.0.1", Port: 1, X2Enabled: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	require.NoError(t, m.AddDestination(original))
	original.Address = "mutated-input"
	original.TLSConfig.MinVersion = tls.VersionTLS13
	saved, err := m.GetDestination(original.DID)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", saved.Address)
	require.Equal(t, uint16(tls.VersionTLS12), saved.TLSConfig.MinVersion)
	saved.ProtocolType = "X3Only"
	saved.TLSConfig.MinVersion = tls.VersionTLS13
	unchanged, err := m.GetDestination(original.DID)
	require.NoError(t, err)
	require.Empty(t, unchanged.ProtocolType)
	require.Equal(t, uint16(tls.VersionTLS12), unchanged.TLSConfig.MinVersion)
	unchanged.Description = "updated"
	require.NoError(t, m.UpdateDestination(unchanged))
	unchanged.Description = "mutated-update"
	saved, err = m.GetDestination(original.DID)
	require.NoError(t, err)
	require.Equal(t, "updated", saved.Description)
}

func TestManagerStopDoesNotWaitForTLSCloseNotify(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		name := "checked-out"
		if pooled {
			name = "pooled"
		}
		t.Run(name, func(t *testing.T) {
			conn, peer := tlsPipe(t)
			defer peer.NetConn().Close()
			did := uuid.New()
			m, state := testKeepaliveManager(did)
			m.registerConnection(state, conn, PDUTypeX2)
			if pooled {
				m.ReleaseConnection(did, conn)
			}
			stopped := make(chan struct{})
			go func() { m.Stop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				// Unblock a pre-fix TLS close_notify before reporting the regression.
				require.NoError(t, peer.NetConn().Close())
				<-stopped
				t.Fatal("shutdown waited for an idle peer to read TLS close_notify")
			}
		})
	}
}
