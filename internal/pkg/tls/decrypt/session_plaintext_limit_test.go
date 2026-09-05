//go:build cli || hunter || tap || tui || all

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
	"github.com/stretchr/testify/require"
)

func TestSessionManagerPlaintextBudget(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()
	cfg := DefaultSessionManagerConfig()
	cfg.MaxPlaintextBytes = 1 << 20
	sm := NewSessionManager(cfg, store)
	defer sm.Stop()
	key, iv := make([]byte, 16), make([]byte, 12)
	state := &SessionState{Version: VersionTLS13, CipherSuite: 0x1301, ClientWriteKey: key, ClientWriteIV: iv}
	state.SetEncrypted(DirectionClient, true)
	sm.sessions["flow"] = &DecryptionSession{KeysAvailable: true, State: state}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte("a"), 16384)
	inner := append(bytes.Clone(plaintext), byte(ContentTypeApplicationData))
	for seq := uint64(0); seq < 65; seq++ {
		fragment := aead.Seal(nil, ConstructTLS13Nonce(iv, seq), inner, ComputeTLS13AdditionalData(len(inner)+aead.Overhead()))
		decoded, err := sm.DecryptRecord("flow", DirectionClient, &Record{ContentType: ContentTypeApplicationData, Version: VersionTLS12, Fragment: fragment})
		if seq == 64 {
			require.ErrorIs(t, err, ErrPlaintextLimit)
			require.ErrorIs(t, sm.Err(), ErrPlaintextLimit)
			break
		}
		require.NoError(t, err)
		require.Equal(t, plaintext, decoded)
	}
	client, _ := sm.GetDecryptedData("flow")
	require.LessOrEqual(t, len(client), 1<<20, "one TLS flow must not retain plaintext proportional to capture length")
}

func TestSessionManagerPlaintextBudgetAcrossFlowsAndDirections(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()
	cfg := DefaultSessionManagerConfig()
	cfg.MaxPlaintextBytes = 32
	sm := NewSessionManager(cfg, store)
	defer sm.Stop()
	key, iv := make([]byte, 16), make([]byte, 12)
	for _, flow := range []string{"first", "second"} {
		state := &SessionState{Version: VersionTLS13, CipherSuite: 0x1301, ClientWriteKey: key, ClientWriteIV: iv, ServerWriteKey: key, ServerWriteIV: iv}
		state.SetEncrypted(DirectionClient, true)
		state.SetEncrypted(DirectionServer, true)
		sm.sessions[flow] = &DecryptionSession{KeysAvailable: true, State: state}
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	plaintext := bytes.Repeat([]byte("b"), 16)
	inner := append(bytes.Clone(plaintext), byte(ContentTypeApplicationData))
	fragment := aead.Seal(nil, ConstructTLS13Nonce(iv, 0), inner, ComputeTLS13AdditionalData(len(inner)+aead.Overhead()))
	record := &Record{ContentType: ContentTypeApplicationData, Version: VersionTLS12, Fragment: fragment}
	for _, dir := range []Direction{DirectionClient, DirectionServer} {
		decoded, err := sm.DecryptRecord("first", dir, record)
		require.NoError(t, err)
		require.Equal(t, plaintext, decoded)
	}
	_, err = sm.DecryptRecord("second", DirectionClient, record)
	require.ErrorIs(t, err, ErrPlaintextLimit)
	client, server := sm.GetDecryptedData("first")
	require.Len(t, client, 16)
	require.Len(t, server, 16)
	client, server = sm.GetDecryptedData("second")
	require.Empty(t, client)
	require.Empty(t, server)
}

func TestSessionManagerPlaintextBudgetReclaimed(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "eviction"
		if expire {
			name = "expiry"
		}
		t.Run(name, func(t *testing.T) {
			store := keylog.NewStore(keylog.DefaultStoreConfig())
			defer store.Stop()
			cfg := DefaultSessionManagerConfig()
			cfg.MaxPlaintextBytes = 16
			sm := NewSessionManager(cfg, store)
			defer sm.Stop()
			key, iv := make([]byte, 16), make([]byte, 12)
			addSession := func(flow string) {
				state := &SessionState{Version: VersionTLS13, CipherSuite: 0x1301, ClientWriteKey: key, ClientWriteIV: iv}
				state.SetEncrypted(DirectionClient, true)
				sm.sessions[flow] = &DecryptionSession{KeysAvailable: true, State: state}
			}
			block, err := aes.NewCipher(key)
			require.NoError(t, err)
			aead, err := cipher.NewGCM(block)
			require.NoError(t, err)
			plaintext := bytes.Repeat([]byte("c"), 16)
			inner := append(bytes.Clone(plaintext), byte(ContentTypeApplicationData))
			fragment := aead.Seal(nil, ConstructTLS13Nonce(iv, 0), inner, ComputeTLS13AdditionalData(len(inner)+aead.Overhead()))
			record := &Record{ContentType: ContentTypeApplicationData, Version: VersionTLS12, Fragment: fragment}
			addSession("old")
			decoded, err := sm.DecryptRecord("old", DirectionClient, record)
			require.NoError(t, err)
			require.Equal(t, plaintext, decoded)
			if expire {
				sm.sessions["old"].LastAccess = time.Now().Add(-2 * cfg.SessionTimeout)
				sm.cleanup()
			} else {
				sm.mu.Lock()
				sm.evictOldestLocked()
				sm.mu.Unlock()
			}
			require.Nil(t, sm.GetSession("old"))
			addSession("new")
			decoded, err = sm.DecryptRecord("new", DirectionClient, record)
			require.NoError(t, err, "removal must release capacity for subsequent flows")
			require.Equal(t, plaintext, decoded)
			require.NoError(t, sm.Err())
		})
	}
}

func TestSessionManagerPendingPlaintextBudget(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()
	cfg := DefaultSessionManagerConfig()
	cfg.MaxPlaintextBytes = 16
	sm := NewSessionManager(cfg, store)
	defer sm.Stop()
	key, iv := make([]byte, 16), make([]byte, 12)
	state := &SessionState{Version: VersionTLS13, CipherSuite: 0x1301, ClientWriteKey: key, ClientWriteIV: iv}
	state.SetEncrypted(DirectionClient, true)
	session := &DecryptionSession{State: state}
	sm.sessions["pending"] = session
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	inner := append(bytes.Repeat([]byte("d"), 16), byte(ContentTypeApplicationData))
	for seq := uint64(0); seq < 2; seq++ {
		fragment := aead.Seal(nil, ConstructTLS13Nonce(iv, seq), inner, ComputeTLS13AdditionalData(len(inner)+aead.Overhead()))
		_, err := sm.DecryptRecord("pending", DirectionClient, &Record{ContentType: ContentTypeApplicationData, Version: VersionTLS12, Fragment: fragment})
		require.ErrorIs(t, err, ErrNoKeys)
	}
	sm.mu.Lock()
	session.KeysAvailable = true
	sm.processPendingRecordsLocked(session)
	sm.mu.Unlock()
	require.ErrorIs(t, sm.Err(), ErrPlaintextLimit, "pending-record failures must remain visible to the offline indexer")
	client, _ := sm.GetDecryptedData("pending")
	require.Len(t, client, 16)
	require.Empty(t, session.pendingClientRecords)
}
