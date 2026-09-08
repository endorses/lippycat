//go:build li

package delivery

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestKeepaliveWorkerExitsWhenDisabledOrRetired(t *testing.T) {
	for _, action := range []string{"disabled", "invalidate", "remove", "replace"} {
		t.Run(action, func(t *testing.T) {
			did := uuid.New()
			m, state := testKeepaliveManager(did)
			defer m.Stop()
			m.config.X2KeepaliveEnabled = action != "disabled"
			m.config.X2KeepaliveTimeP1 = time.Hour
			m.config.X2KeepaliveTimeP2 = time.Hour
			conn, peer := tlsPipe(t)
			defer peer.NetConn().Close()
			m.registerConnection(state, conn, PDUTypeX2)
			m.wg.Add(1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				m.keepaliveLoop(did, conn)
			}()
			if action != "disabled" {
				// Observe a frame to prove the timer owner has started before
				// retiring it during its hour-long acknowledgement wait.
				value, ok := m.connectionRuntime.Load(conn)
				require.True(t, ok)
				value.(*connectionRuntime).keepaliveWake <- struct{}{}
				require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
				_, err := x2x3.ReadPDU(peer)
				require.NoError(t, err)
				// Finish deadline cleanup before closing the transport, so the
				// worker exits only through retirement, not a failed frame write.
				runtime := value.(*connectionRuntime)
				runtime.writeMu.Lock()
				runtime.writeMu.Unlock()
				switch action {
				case "invalidate":
					m.invalidateConnection(did, conn, false)
				case "remove":
					require.NoError(t, m.RemoveDestination(did))
				case "replace":
					// Replacement closes the old generation through this same
					// helper; avoid starting an unrelated network dial here.
					m.mu.Lock()
					m.closeDestinationLocked(did, state)
					m.mu.Unlock()
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("retired or disabled keepalive worker still retained by its timer")
			}
		})
	}
}
