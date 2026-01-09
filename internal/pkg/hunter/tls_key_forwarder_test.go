//go:build hunter || tap || all

package hunter

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestKeyStore creates a keylog store for testing with a short TTL.
func createTestKeyStore() *keylog.Store {
	config := keylog.StoreConfig{
		MaxSessions:     1000,
		SessionTTL:      1 * time.Hour,
		CleanupInterval: 1 * time.Hour, // Don't run cleanup during tests
	}
	return keylog.NewStore(config)
}

// createTestClientRandom creates a test client random with specified byte values.
func createTestClientRandom(seed byte) []byte {
	cr := make([]byte, 32)
	for i := range cr {
		cr[i] = seed + byte(i)
	}
	return cr
}

func TestNewTLSKeyForwarder(t *testing.T) {
	t.Run("with key store", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()

		forwarder := NewTLSKeyForwarder(store)
		require.NotNil(t, forwarder)
		assert.NotNil(t, forwarder.keyStore)
		assert.NotNil(t, forwarder.forwardedSessions)
	})

	t.Run("without key store", func(t *testing.T) {
		forwarder := NewTLSKeyForwarder(nil)
		require.NotNil(t, forwarder)
		assert.Nil(t, forwarder.keyStore)
	})
}

func TestTLSKeyForwarder_AttachKeys(t *testing.T) {
	t.Run("no key store returns false", func(t *testing.T) {
		forwarder := NewTLSKeyForwarder(nil)

		packet := &data.CapturedPacket{}
		clientRandom := createTestClientRandom(0x01)
		result := forwarder.AttachKeys(packet, clientRandom, nil, 0, 0x0303,
			net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 12345, 443)

		assert.False(t, result)
		assert.Nil(t, packet.TlsKeys)
	})

	t.Run("invalid client random length returns false", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()
		forwarder := NewTLSKeyForwarder(store)

		packet := &data.CapturedPacket{}
		result := forwarder.AttachKeys(packet, []byte{0x01, 0x02}, nil, 0, 0x0303,
			net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 12345, 443)

		assert.False(t, result)
		assert.Nil(t, packet.TlsKeys)
	})

	t.Run("missing session keys returns false", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()
		forwarder := NewTLSKeyForwarder(store)

		packet := &data.CapturedPacket{}
		clientRandom := createTestClientRandom(0x01)
		result := forwarder.AttachKeys(packet, clientRandom, nil, 0, 0x0303,
			net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 12345, 443)

		assert.False(t, result)
		assert.Nil(t, packet.TlsKeys)

		// Check stats
		_, missing := forwarder.Stats()
		assert.Equal(t, uint64(1), missing)
	})

	t.Run("TLS 1.2 keys attached successfully", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()
		forwarder := NewTLSKeyForwarder(store)

		// Add TLS 1.2 keys to store
		clientRandom := createTestClientRandom(0x01)
		var cr [32]byte
		copy(cr[:], clientRandom)

		preMasterSecret := make([]byte, 48)
		for i := range preMasterSecret {
			preMasterSecret[i] = 0xAA
		}

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       preMasterSecret,
		})

		// Attach keys to packet
		packet := &data.CapturedPacket{}
		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")
		result := forwarder.AttachKeys(packet, clientRandom, nil, 0x002F, 0x0303,
			srcIP, dstIP, 12345, 443)

		assert.True(t, result)
		require.NotNil(t, packet.TlsKeys)
		assert.Equal(t, clientRandom, packet.TlsKeys.ClientRandom)
		assert.Equal(t, preMasterSecret, packet.TlsKeys.PreMasterSecret)
		assert.Equal(t, uint32(0x0303), packet.TlsKeys.TlsVersion)
		assert.Equal(t, uint32(0x002F), packet.TlsKeys.CipherSuite)
		assert.Equal(t, "192.168.1.1", packet.TlsKeys.SrcIp)
		assert.Equal(t, "192.168.1.2", packet.TlsKeys.DstIp)
		assert.Equal(t, uint32(12345), packet.TlsKeys.SrcPort)
		assert.Equal(t, uint32(443), packet.TlsKeys.DstPort)

		// Check stats
		forwarded, _ := forwarder.Stats()
		assert.Equal(t, uint64(1), forwarded)
	})

	t.Run("TLS 1.3 keys attached successfully", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()
		forwarder := NewTLSKeyForwarder(store)

		// Add TLS 1.3 keys to store
		clientRandom := createTestClientRandom(0x02)
		var cr [32]byte
		copy(cr[:], clientRandom)

		clientTrafficSecret := make([]byte, 32)
		serverTrafficSecret := make([]byte, 32)
		for i := range clientTrafficSecret {
			clientTrafficSecret[i] = 0xBB
			serverTrafficSecret[i] = 0xCC
		}

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientTrafficSecret0,
			ClientRandom: cr,
			Secret:       clientTrafficSecret,
		})
		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelServerTrafficSecret0,
			ClientRandom: cr,
			Secret:       serverTrafficSecret,
		})

		// Attach keys to packet
		packet := &data.CapturedPacket{}
		result := forwarder.AttachKeys(packet, clientRandom, nil, 0x1301, 0x0304,
			net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 54321, 8443)

		assert.True(t, result)
		require.NotNil(t, packet.TlsKeys)
		assert.Equal(t, clientTrafficSecret, packet.TlsKeys.ClientTrafficSecret_0)
		assert.Equal(t, serverTrafficSecret, packet.TlsKeys.ServerTrafficSecret_0)
	})

	t.Run("duplicate forwarding prevented", func(t *testing.T) {
		store := createTestKeyStore()
		defer store.Stop()
		forwarder := NewTLSKeyForwarder(store)

		// Add keys to store
		clientRandom := createTestClientRandom(0x03)
		var cr [32]byte
		copy(cr[:], clientRandom)

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       make([]byte, 48),
		})

		srcIP := net.ParseIP("192.168.1.1")
		dstIP := net.ParseIP("192.168.1.2")

		// First attach should succeed
		packet1 := &data.CapturedPacket{}
		result1 := forwarder.AttachKeys(packet1, clientRandom, nil, 0, 0,
			srcIP, dstIP, 12345, 443)
		assert.True(t, result1)
		require.NotNil(t, packet1.TlsKeys)

		// Second attach should fail (already forwarded)
		packet2 := &data.CapturedPacket{}
		result2 := forwarder.AttachKeys(packet2, clientRandom, nil, 0, 0,
			srcIP, dstIP, 12345, 443)
		assert.False(t, result2)
		assert.Nil(t, packet2.TlsKeys)

		// Stats should show only 1 forwarded
		forwarded, _ := forwarder.Stats()
		assert.Equal(t, uint64(1), forwarded)
	})
}

func TestTLSKeyForwarder_AttachKeysFromClientRandom(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	// Add keys to store
	clientRandom := createTestClientRandom(0x04)
	var cr [32]byte
	copy(cr[:], clientRandom)

	store.Add(&keylog.KeyEntry{
		Label:        keylog.LabelClientRandom,
		ClientRandom: cr,
		Secret:       make([]byte, 48),
	})

	// Use convenience method
	packet := &data.CapturedPacket{}
	result := forwarder.AttachKeysFromClientRandom(packet, clientRandom,
		net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 12345, 443)

	assert.True(t, result)
	require.NotNil(t, packet.TlsKeys)
}

func TestTLSKeyForwarder_HasKeysForSession(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	clientRandom := createTestClientRandom(0x05)
	var cr [32]byte
	copy(cr[:], clientRandom)

	// No keys yet
	assert.False(t, forwarder.HasKeysForSession(clientRandom))

	// Add keys
	store.Add(&keylog.KeyEntry{
		Label:        keylog.LabelClientRandom,
		ClientRandom: cr,
		Secret:       make([]byte, 48),
	})

	// Now should have keys
	assert.True(t, forwarder.HasKeysForSession(clientRandom))

	// Invalid length
	assert.False(t, forwarder.HasKeysForSession([]byte{0x01}))
}

func TestTLSKeyForwarder_WasKeyForwarded(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	clientRandom := createTestClientRandom(0x06)
	var cr [32]byte
	copy(cr[:], clientRandom)

	// Add keys
	store.Add(&keylog.KeyEntry{
		Label:        keylog.LabelClientRandom,
		ClientRandom: cr,
		Secret:       make([]byte, 48),
	})

	// Not forwarded yet
	assert.False(t, forwarder.WasKeyForwarded(clientRandom))

	// Forward keys
	packet := &data.CapturedPacket{}
	forwarder.AttachKeys(packet, clientRandom, nil, 0, 0,
		net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 443)

	// Now should be forwarded
	assert.True(t, forwarder.WasKeyForwarded(clientRandom))

	// Invalid length
	assert.False(t, forwarder.WasKeyForwarded([]byte{0x01}))
}

func TestTLSKeyForwarder_Reset(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	// Add and forward some keys
	for i := byte(0); i < 5; i++ {
		clientRandom := createTestClientRandom(i)
		var cr [32]byte
		copy(cr[:], clientRandom)

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       make([]byte, 48),
		})

		packet := &data.CapturedPacket{}
		forwarder.AttachKeys(packet, clientRandom, nil, 0, 0,
			net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 443)
	}

	assert.Equal(t, 5, forwarder.SessionCount())

	// Reset
	forwarder.Reset()

	assert.Equal(t, 0, forwarder.SessionCount())
}

func TestTLSKeyForwarder_Cleanup(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	// Add and forward many sessions
	for i := byte(0); i < 20; i++ {
		clientRandom := createTestClientRandom(i)
		var cr [32]byte
		copy(cr[:], clientRandom)

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       make([]byte, 48),
		})

		packet := &data.CapturedPacket{}
		forwarder.AttachKeys(packet, clientRandom, nil, 0, 0,
			net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 443)
	}

	assert.Equal(t, 20, forwarder.SessionCount())

	// Cleanup to max 10
	removed := forwarder.Cleanup(10)
	assert.Equal(t, 10, removed)
	assert.Equal(t, 10, forwarder.SessionCount())

	// Cleanup with higher limit does nothing
	removed = forwarder.Cleanup(15)
	assert.Equal(t, 0, removed)
	assert.Equal(t, 10, forwarder.SessionCount())
}

func TestTLSKeyForwarder_ConcurrentAccess(t *testing.T) {
	store := createTestKeyStore()
	defer store.Stop()
	forwarder := NewTLSKeyForwarder(store)

	// Add keys for concurrent testing
	for i := byte(0); i < 100; i++ {
		clientRandom := createTestClientRandom(i)
		var cr [32]byte
		copy(cr[:], clientRandom)

		store.Add(&keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       make([]byte, 48),
		})
	}

	// Concurrent attach attempts
	done := make(chan bool, 100)
	for i := byte(0); i < 100; i++ {
		go func(seed byte) {
			clientRandom := createTestClientRandom(seed)
			packet := &data.CapturedPacket{}
			forwarder.AttachKeys(packet, clientRandom, nil, 0, 0,
				net.ParseIP("1.2.3.4"), net.ParseIP("5.6.7.8"), 1234, 443)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Should have 100 forwarded (each unique)
	forwarded, _ := forwarder.Stats()
	assert.Equal(t, uint64(100), forwarded)
	assert.Equal(t, 100, forwarder.SessionCount())
}
