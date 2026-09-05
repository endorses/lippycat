//go:build cli || hunter || tap || tui || all

package decrypt

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
	"github.com/stretchr/testify/require"
)

func addLookupClientHello(t *testing.T, sm *SessionManager, flow string, value uint64) [32]byte {
	t.Helper()
	fragment := make([]byte, 39)
	fragment[0], fragment[3], fragment[4], fragment[5] = 1, 35, 3, 3
	binary.BigEndian.PutUint64(fragment[6:14], value)
	record := &Record{ContentType: ContentTypeHandshake, Version: VersionTLS12, Fragment: fragment}
	require.NoError(t, sm.ProcessClientHello(flow, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), 12345, 443, record))
	var random [32]byte
	copy(random[:], fragment[6:38])
	return random
}

func TestSessionManagerClientRandomLookupBound(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()
	cfg := DefaultSessionManagerConfig()
	cfg.MaxSessions = 1
	sm := NewSessionManager(cfg, store)
	defer sm.Stop()
	var previous [32]byte
	for i := uint64(1); i <= 1000; i++ {
		current := addLookupClientHello(t, sm, "reused-flow", i)
		sm.mu.RLock()
		sessions, lookups := len(sm.sessions), len(sm.clientRandomToFlow)
		sm.mu.RUnlock()
		require.Equal(t, 1, sessions)
		require.Equal(t, 1, lookups, "reused flows must not retain old handshake identities")
		require.Same(t, sm.GetSession("reused-flow"), sm.GetSessionByClientRandom(current))
		if i > 1 {
			require.Nil(t, sm.GetSessionByClientRandom(previous))
		}
		previous = current
	}
	addLookupClientHello(t, sm, "replacement-flow", 1001)
	sm.mu.RLock()
	lookups := len(sm.clientRandomToFlow)
	sm.mu.RUnlock()
	require.Equal(t, 1, lookups)
	require.Nil(t, sm.GetSessionByClientRandom(previous))
}

func TestSessionManagerClientRandomLookupOwnership(t *testing.T) {
	for _, operation := range []string{"replace", "expire", "evict"} {
		t.Run(operation, func(t *testing.T) {
			store := keylog.NewStore(keylog.DefaultStoreConfig())
			defer store.Stop()
			cfg := DefaultSessionManagerConfig()
			cfg.MaxSessions = 2
			sm := NewSessionManager(cfg, store)
			defer sm.Stop()
			shared := addLookupClientHello(t, sm, "older-flow", 1)
			addLookupClientHello(t, sm, "current-flow", 1)
			sm.mu.Lock()
			sm.sessions["older-flow"].LastAccess = time.Now().Add(-2 * cfg.SessionTimeout)
			sm.mu.Unlock()
			switch operation {
			case "replace":
				addLookupClientHello(t, sm, "older-flow", 2)
			case "expire":
				sm.cleanup()
			case "evict":
				addLookupClientHello(t, sm, "third-flow", 2)
			}
			require.Same(t, sm.GetSession("current-flow"), sm.GetSessionByClientRandom(shared), "cleanup must preserve another flow's lookup")
		})
	}
}
