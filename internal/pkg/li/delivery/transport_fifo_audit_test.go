//go:build li

package delivery

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestBackgroundConnectionPreservesActiveFIFOTransport(t *testing.T) {
	for _, capacity := range []int{1, 2} {
		for _, checkedOut := range []bool{false, true} {
			name := "idle"
			if checkedOut {
				name = "checked-out"
			}
			t.Run(fmt.Sprintf("capacity-%d/%s", capacity, name), func(t *testing.T) {
				primary, primaryPeer := tlsPipe(t)
				defer primaryPeer.NetConn().Close()
				spare, sparePeer := tlsPipe(t)
				defer sparePeer.NetConn().Close()
				did := uuid.New()
				manager, state := testKeepaliveManager(did)
				defer manager.Stop()
				state.interfacePools[PDUTypeX2] = newConnPool(capacity)
				pool := state.interfacePools[PDUTypeX2]
				manager.registerConnection(state, primary, PDUTypeX2)
				manager.ReleaseConnection(did, primary)
				if checkedOut {
					require.Same(t, primary, pool.get().conn)
				}
				require.False(t, manager.publishPooledConnection(did, state, state.generation, spare, PDUTypeX2))
				if checkedOut {
					pool.mu.Lock()
					inUse := pool.inUse
					pool.mu.Unlock()
					require.Equal(t, 1, inUse, "publishing a spare must not release the active connection")
					manager.ReleaseConnection(did, primary)
				}
				next, err := manager.GetConnectionForInterface(context.Background(), did, PDUTypeX2)
				require.NoError(t, err)
				require.True(t, primary == next, "switching healthy transports can overtake unread frames on the previous TCP stream")
				manager.ReleaseConnection(did, next)
			})
		}
	}
}

func TestForegroundDialReusesConcurrentBackgroundConnection(t *testing.T) {
	cert, key := generateTestCert(t)
	listener, port := startTestTLSServer(t, cert, key)
	defer listener.Close()
	primary, peer := tlsPipe(t)
	defer peer.NetConn().Close()
	did := uuid.New()
	manager, state := testKeepaliveManager(did)
	defer manager.Stop()
	manager.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	manager.config.DialTimeout = time.Second
	state.dest.Port = port
	reached := make(chan struct{})
	release := make(chan struct{})
	state.dest.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error {
		close(reached)
		<-release
		return nil
	}}
	type result struct {
		conn *tls.Conn
		err  error
	}
	acquired := make(chan result, 1)
	go func() {
		conn, err := manager.GetConnectionForInterface(context.Background(), did, PDUTypeX2)
		acquired <- result{conn, err}
	}()
	<-reached
	published := manager.publishPooledConnection(did, state, state.generation, primary, PDUTypeX2)
	close(release)
	require.True(t, published)
	r := <-acquired
	require.NoError(t, r.err)
	require.True(t, primary == r.conn, "foreground must reuse the background association before writing")
	manager.ReleaseConnection(did, r.conn)
	state.mu.RLock()
	count := len(state.connections)
	state.mu.RUnlock()
	require.Equal(t, 1, count)
}
