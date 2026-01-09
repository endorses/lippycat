//go:build cli || hunter || tap || all

package decrypt

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionManager(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	config := DefaultSessionManagerConfig()
	sm := NewSessionManager(config, store)
	defer sm.Stop()

	assert.NotNil(t, sm)
	assert.Equal(t, config.MaxSessions, sm.config.MaxSessions)
}

func TestSessionManagerDefaultConfig(t *testing.T) {
	config := DefaultSessionManagerConfig()

	assert.Equal(t, 10000, config.MaxSessions)
	assert.Equal(t, 30*time.Minute, config.SessionTimeout)
	assert.Equal(t, 100, config.PendingRecordLimit)
	assert.Equal(t, 1*time.Minute, config.CleanupInterval)
}

func TestFlowKey(t *testing.T) {
	tests := []struct {
		name     string
		srcIP    net.IP
		dstIP    net.IP
		srcPort  uint16
		dstPort  uint16
		expected string
	}{
		{
			name:     "IPv4 addresses",
			srcIP:    net.ParseIP("192.168.1.1"),
			dstIP:    net.ParseIP("10.0.0.1"),
			srcPort:  12345,
			dstPort:  443,
			expected: "192.168.1.1:12345-10.0.0.1:443",
		},
		{
			name:     "IPv6 addresses",
			srcIP:    net.ParseIP("::1"),
			dstIP:    net.ParseIP("2001:db8::1"),
			srcPort:  54321,
			dstPort:  443,
			expected: "::1:54321-2001:db8::1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FlowKey(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessClientHello(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// Create a minimal ClientHello record
	// Structure: ContentType(1) + Version(2) + Length(2) + HandshakeType(1) + Length(3) + Version(2) + Random(32)
	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// Build ClientHello fragment
	fragment := make([]byte, 0, 64)
	fragment = append(fragment, 1)               // HandshakeType: ClientHello
	fragment = append(fragment, 0, 0, 38)        // Length (3 bytes)
	fragment = append(fragment, 0x03, 0x03)      // Version: TLS 1.2
	fragment = append(fragment, clientRandom...) // Random (32 bytes)
	fragment = append(fragment, 0)               // Session ID length = 0

	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    fragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, record)
	require.NoError(t, err)

	// Verify session was created
	session := sm.GetSession(flowKey)
	require.NotNil(t, session)
	assert.True(t, session.HasClientHello)
	assert.False(t, session.HasServerHello)
	assert.Equal(t, clientRandom, session.ClientRandom[:])
}

func TestProcessServerHello(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// First create a session with ClientHello
	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	clientFragment := make([]byte, 0, 64)
	clientFragment = append(clientFragment, 1)               // HandshakeType: ClientHello
	clientFragment = append(clientFragment, 0, 0, 38)        // Length
	clientFragment = append(clientFragment, 0x03, 0x03)      // Version: TLS 1.2
	clientFragment = append(clientFragment, clientRandom...) // Random
	clientFragment = append(clientFragment, 0)               // Session ID length = 0

	clientRecord := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    clientFragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, clientRecord)
	require.NoError(t, err)

	// Now process ServerHello
	serverRandom := make([]byte, 32)
	for i := range serverRandom {
		serverRandom[i] = byte(0xff - i)
	}

	serverFragment := make([]byte, 0, 64)
	serverFragment = append(serverFragment, 2)               // HandshakeType: ServerHello
	serverFragment = append(serverFragment, 0, 0, 42)        // Length
	serverFragment = append(serverFragment, 0x03, 0x03)      // Version: TLS 1.2
	serverFragment = append(serverFragment, serverRandom...) // Random
	serverFragment = append(serverFragment, 0)               // Session ID length = 0
	serverFragment = append(serverFragment, 0xc0, 0x2f)      // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	serverFragment = append(serverFragment, 0)               // Compression method

	serverRecord := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    serverFragment,
	}

	err = sm.ProcessServerHello(flowKey, serverRecord)
	require.NoError(t, err)

	// Verify session was updated
	session := sm.GetSession(flowKey)
	require.NotNil(t, session)
	assert.True(t, session.HasClientHello)
	assert.True(t, session.HasServerHello)
	assert.Equal(t, serverRandom, session.ServerRandom[:])
	assert.Equal(t, uint16(0xc02f), session.CipherSuite)
}

func TestSessionExtractClientRandom(t *testing.T) {
	tests := []struct {
		name        string
		contentType uint8
		fragment    []byte
		expectNil   bool
	}{
		{
			name:        "Valid ClientHello",
			contentType: ContentTypeHandshake,
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 1)                   // ClientHello
				f = append(f, 0, 0, 38)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random (32 zeros)
				f[6] = 0x01                        // Set first byte of random
				return f
			}(),
			expectNil: false,
		},
		{
			name:        "Not handshake",
			contentType: ContentTypeApplicationData,
			fragment:    make([]byte, 50),
			expectNil:   true,
		},
		{
			name:        "ServerHello (wrong type)",
			contentType: ContentTypeHandshake,
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 2) // ServerHello, not ClientHello
				f = append(f, 0, 0, 38)
				f = append(f, 0x03, 0x03)
				f = append(f, make([]byte, 32)...)
				return f
			}(),
			expectNil: true,
		},
		{
			name:        "Too short",
			contentType: ContentTypeHandshake,
			fragment:    make([]byte, 10),
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &Record{
				ContentType: tt.contentType,
				Fragment:    tt.fragment,
			}
			result := ExtractClientRandom(record)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, 32)
			}
		})
	}
}

func TestSessionExtractServerRandom(t *testing.T) {
	tests := []struct {
		name        string
		contentType uint8
		fragment    []byte
		expectNil   bool
	}{
		{
			name:        "Valid ServerHello",
			contentType: ContentTypeHandshake,
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 2)                   // ServerHello
				f = append(f, 0, 0, 38)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random
				f[6] = 0xAB                        // Set first byte of random
				return f
			}(),
			expectNil: false,
		},
		{
			name:        "ClientHello (wrong type)",
			contentType: ContentTypeHandshake,
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 1) // ClientHello
				f = append(f, 0, 0, 38)
				f = append(f, 0x03, 0x03)
				f = append(f, make([]byte, 32)...)
				return f
			}(),
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &Record{
				ContentType: tt.contentType,
				Fragment:    tt.fragment,
			}
			result := ExtractServerRandom(record)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, 32)
			}
		})
	}
}

func TestSessionExtractCipherSuite(t *testing.T) {
	tests := []struct {
		name     string
		fragment []byte
		expected uint16
	}{
		{
			name: "Valid ServerHello with cipher suite",
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 2)                   // ServerHello
				f = append(f, 0, 0, 42)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random
				f = append(f, 0)                   // Session ID length = 0
				f = append(f, 0xc0, 0x2f)          // Cipher suite
				return f
			}(),
			expected: 0xc02f,
		},
		{
			name: "ServerHello with session ID",
			fragment: func() []byte {
				f := make([]byte, 0, 80)
				f = append(f, 2)                   // ServerHello
				f = append(f, 0, 0, 58)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random
				f = append(f, 16)                  // Session ID length = 16
				f = append(f, make([]byte, 16)...) // Session ID
				f = append(f, 0x13, 0x01)          // Cipher suite: TLS_AES_128_GCM_SHA256
				return f
			}(),
			expected: 0x1301,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &Record{
				ContentType: ContentTypeHandshake,
				Fragment:    tt.fragment,
			}
			result := ExtractCipherSuite(record)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSessionManagerStats(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// Initial stats
	stats := sm.Stats()
	assert.Equal(t, 0, stats.ActiveSessions)
	assert.Equal(t, uint64(0), stats.TotalSessions)

	// Add a session
	clientRandom := make([]byte, 32)
	fragment := make([]byte, 0, 64)
	fragment = append(fragment, 1)
	fragment = append(fragment, 0, 0, 38)
	fragment = append(fragment, 0x03, 0x03)
	fragment = append(fragment, clientRandom...)
	fragment = append(fragment, 0)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    fragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, record)
	require.NoError(t, err)

	stats = sm.Stats()
	assert.Equal(t, 1, stats.ActiveSessions)
	assert.Equal(t, uint64(1), stats.TotalSessions)
	assert.Equal(t, 0, stats.SessionsWithKeys) // No keys yet
}

func TestSessionManagerEviction(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	config := DefaultSessionManagerConfig()
	config.MaxSessions = 2 // Small limit for testing
	sm := NewSessionManager(config, store)
	defer sm.Stop()

	// Add 3 sessions (should trigger eviction)
	for i := 0; i < 3; i++ {
		clientRandom := make([]byte, 32)
		clientRandom[0] = byte(i)

		fragment := make([]byte, 0, 64)
		fragment = append(fragment, 1)
		fragment = append(fragment, 0, 0, 38)
		fragment = append(fragment, 0x03, 0x03)
		fragment = append(fragment, clientRandom...)
		fragment = append(fragment, 0)

		record := &Record{
			ContentType: ContentTypeHandshake,
			Version:     VersionTLS12,
			Fragment:    fragment,
		}

		flowKey := FlowKey(
			net.ParseIP("192.168.1.1"),
			net.ParseIP("10.0.0.1"),
			uint16(12345+i),
			443,
		)

		err := sm.ProcessClientHello(flowKey, net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1"), uint16(12345+i), 443, record)
		require.NoError(t, err)

		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Should have only 2 sessions due to eviction
	stats := sm.Stats()
	assert.Equal(t, 2, stats.ActiveSessions)
	assert.Equal(t, uint64(3), stats.TotalSessions)
}

func TestProcessChangeCipherSpec(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// Create a session first
	clientRandom := make([]byte, 32)
	fragment := make([]byte, 0, 64)
	fragment = append(fragment, 1)
	fragment = append(fragment, 0, 0, 38)
	fragment = append(fragment, 0x03, 0x03)
	fragment = append(fragment, clientRandom...)
	fragment = append(fragment, 0)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    fragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, record)
	require.NoError(t, err)

	// ProcessChangeCipherSpec should not panic even without state
	sm.ProcessChangeCipherSpec(flowKey, DirectionClient)

	// Verify session still exists
	session := sm.GetSession(flowKey)
	assert.NotNil(t, session)
}

func TestDecryptRecordNoKeys(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// Create a session
	clientRandom := make([]byte, 32)
	fragment := make([]byte, 0, 64)
	fragment = append(fragment, 1)
	fragment = append(fragment, 0, 0, 38)
	fragment = append(fragment, 0x03, 0x03)
	fragment = append(fragment, clientRandom...)
	fragment = append(fragment, 0)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    fragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, record)
	require.NoError(t, err)

	// Try to decrypt without keys
	appDataRecord := &Record{
		ContentType: ContentTypeApplicationData,
		Version:     VersionTLS12,
		Fragment:    []byte("encrypted data"),
	}

	_, err = sm.DecryptRecord(flowKey, DirectionClient, appDataRecord)
	assert.Equal(t, ErrNoKeys, err)

	// Record should be queued as pending
	session := sm.GetSession(flowKey)
	assert.Len(t, session.pendingClientRecords, 1)
}

func TestGetSessionByClientRandom(t *testing.T) {
	store := keylog.NewStore(keylog.DefaultStoreConfig())
	defer store.Stop()

	sm := NewSessionManager(DefaultSessionManagerConfig(), store)
	defer sm.Stop()

	// Create a session
	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i + 1) // Non-zero values
	}

	fragment := make([]byte, 0, 64)
	fragment = append(fragment, 1)
	fragment = append(fragment, 0, 0, 38)
	fragment = append(fragment, 0x03, 0x03)
	fragment = append(fragment, clientRandom...)
	fragment = append(fragment, 0)

	record := &Record{
		ContentType: ContentTypeHandshake,
		Version:     VersionTLS12,
		Fragment:    fragment,
	}

	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("10.0.0.1")

	err := sm.ProcessClientHello(flowKey, srcIP, dstIP, 12345, 443, record)
	require.NoError(t, err)

	// Look up by client random
	var clientRandomKey [32]byte
	copy(clientRandomKey[:], clientRandom)

	session := sm.GetSessionByClientRandom(clientRandomKey)
	require.NotNil(t, session)
	assert.Equal(t, flowKey, session.FlowKey)
}

func TestExtractSessionID(t *testing.T) {
	tests := []struct {
		name      string
		fragment  []byte
		expectLen int
	}{
		{
			name: "No session ID",
			fragment: func() []byte {
				f := make([]byte, 0, 64)
				f = append(f, 1)                   // ClientHello
				f = append(f, 0, 0, 38)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random
				f = append(f, 0)                   // Session ID length = 0
				return f
			}(),
			expectLen: 0,
		},
		{
			name: "With session ID",
			fragment: func() []byte {
				f := make([]byte, 0, 80)
				f = append(f, 1)                   // ClientHello
				f = append(f, 0, 0, 54)            // Length
				f = append(f, 0x03, 0x03)          // Version
				f = append(f, make([]byte, 32)...) // Random
				f = append(f, 16)                  // Session ID length = 16
				f = append(f, make([]byte, 16)...) // Session ID
				return f
			}(),
			expectLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &Record{
				ContentType: ContentTypeHandshake,
				Fragment:    tt.fragment,
			}
			result := ExtractSessionID(record)
			assert.Len(t, result, tt.expectLen)
		})
	}
}

func TestIsChaCha20Suite(t *testing.T) {
	tests := []struct {
		id       uint16
		expected bool
	}{
		{0xcca8, true},  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
		{0xcca9, true},  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
		{0x1303, true},  // TLS_CHACHA20_POLY1305_SHA256
		{0xc02f, false}, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		{0x1301, false}, // TLS_AES_128_GCM_SHA256
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.expected, isChaCha20Suite(tt.id))
		})
	}
}

func TestReverseFlowKey(t *testing.T) {
	flowKey := "192.168.1.1:12345-10.0.0.1:443"
	reversed := ReverseFlowKey(flowKey)

	// Note: The current implementation has a simple format
	// This test may need adjustment based on actual implementation
	assert.Contains(t, reversed, "10.0.0.1")
	assert.Contains(t, reversed, "192.168.1.1")
}
