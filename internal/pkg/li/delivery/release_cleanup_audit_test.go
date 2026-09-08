//go:build li

package delivery

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestReleaseConnectionDoesNotWaitForTLSCloseNotify(t *testing.T) {
	for _, scenario := range []string{"removed", "stopping", "invalid", "full"} {
		t.Run(scenario, func(t *testing.T) {
			conn, peer := tlsPipe(t)
			defer func() { require.NoError(t, peer.NetConn().Close()) }()
			did := uuid.New()
			manager, state := testKeepaliveManager(did)
			defer manager.Stop()
			switch scenario {
			case "removed":
				delete(manager.destinations, did)
			case "stopping":
				manager.shuttingDown.Store(true)
			case "full":
				manager.registerConnection(state, conn, PDUTypeX3)
				state.interfacePools[PDUTypeX3] = newConnPool(0)
			}
			done := make(chan struct{})
			go func() {
				manager.ReleaseConnection(did, conn)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				require.NoError(t, peer.NetConn().Close())
				<-done
				t.Fatal("release blocked delivery owner waiting for TLS close_notify")
			}
		})
	}
}
