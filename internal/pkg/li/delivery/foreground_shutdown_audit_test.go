//go:build li

package delivery

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Pause at the caller cancellation check to exercise shutdown between the
// initial manager check and the destination lookup without scheduler timing.
type shutdownGateContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *shutdownGateContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Done()
}

func TestForegroundConnectionCannotPublishAfterManagerStop(t *testing.T) {
	cert, key := generateTestCert(t)
	listener, port := startTestTLSServer(t, cert, key)
	defer listener.Close()
	did := uuid.New()
	m, state := testKeepaliveManager(did)
	m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	m.config.DialTimeout = time.Second
	state.dest.Port = port
	ctx := &shutdownGateContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		conn, err := m.GetConnectionForInterface(ctx, did, PDUTypeX2)
		if conn != nil {
			m.invalidateConnection(did, conn, false)
		}
		result <- err
	}()
	<-ctx.entered
	m.Stop()
	close(ctx.release)
	select {
	case err := <-result:
		require.ErrorIs(t, err, ErrShuttingDown)
	case <-time.After(3 * time.Second):
		t.Fatal("foreground acquisition did not finish after shutdown")
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	require.Empty(t, state.connections)
}
