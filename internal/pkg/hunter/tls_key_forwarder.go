//go:build hunter || tap || all

package hunter

import (
	"net"
	"sync"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
)

// TLSKeyForwarder manages TLS session key forwarding to processors.
// It tracks which sessions have had their keys forwarded to avoid duplicates,
// and converts keylog.SessionKeys to proto TLSSessionKeys messages.
type TLSKeyForwarder struct {
	keyStore *keylog.Store

	// Track sessions that have had keys forwarded (by client random hex)
	forwardedSessions map[string]bool
	mu                sync.RWMutex

	// Statistics
	keysForwarded uint64
	keysMissing   uint64
}

// NewTLSKeyForwarder creates a new TLS key forwarder.
// keyStore can be nil if TLS decryption is not enabled.
func NewTLSKeyForwarder(keyStore *keylog.Store) *TLSKeyForwarder {
	return &TLSKeyForwarder{
		keyStore:          keyStore,
		forwardedSessions: make(map[string]bool),
	}
}

// AttachKeys checks if TLS session keys are available for the given packet
// and attaches them if this is the first matched packet for that session.
// It updates the packet's TlsKeys field and returns true if keys were attached.
//
// Parameters:
//   - packet: The captured packet proto message to attach keys to
//   - clientRandom: The 32-byte client random from the TLS ClientHello
//   - serverRandom: The 32-byte server random from the TLS ServerHello (optional)
//   - cipherSuite: The negotiated cipher suite
//   - tlsVersion: The TLS version (e.g., 0x0303 for TLS 1.2)
//   - srcIP, dstIP: Source and destination IP addresses
//   - srcPort, dstPort: Source and destination ports
func (f *TLSKeyForwarder) AttachKeys(
	packet *data.CapturedPacket,
	clientRandom []byte,
	serverRandom []byte,
	cipherSuite uint16,
	tlsVersion uint16,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
) bool {
	if f.keyStore == nil {
		return false
	}

	if len(clientRandom) != 32 {
		return false
	}

	// Convert to hex for tracking
	clientRandomHex := keylog.BytesToHex(clientRandom)

	// Check if we already forwarded keys for this session
	f.mu.RLock()
	alreadyForwarded := f.forwardedSessions[clientRandomHex]
	f.mu.RUnlock()

	if alreadyForwarded {
		return false
	}

	// Look up session keys
	var cr [32]byte
	copy(cr[:], clientRandom)
	sessionKeys := f.keyStore.Get(cr)
	if sessionKeys == nil {
		f.mu.Lock()
		f.keysMissing++
		f.mu.Unlock()
		return false
	}

	// Check if we have decryption keys
	if !sessionKeys.HasDecryptionKeys() {
		f.mu.Lock()
		f.keysMissing++
		f.mu.Unlock()
		return false
	}

	// Mark as forwarded (double-check with write lock)
	f.mu.Lock()
	if f.forwardedSessions[clientRandomHex] {
		f.mu.Unlock()
		return false
	}
	f.forwardedSessions[clientRandomHex] = true
	f.keysForwarded++
	f.mu.Unlock()

	// Build proto TLSSessionKeys
	tlsKeys := &data.TLSSessionKeys{
		ClientRandom: clientRandom,
		TlsVersion:   uint32(tlsVersion),
		CipherSuite:  uint32(cipherSuite),
		SrcIp:        srcIP.String(),
		SrcPort:      uint32(srcPort),
		DstIp:        dstIP.String(),
		DstPort:      uint32(dstPort),
	}

	// Copy server random if available
	if len(serverRandom) == 32 {
		tlsKeys.ServerRandom = serverRandom
	}

	// Copy TLS 1.2 pre-master secret
	if len(sessionKeys.PreMasterSecret) > 0 {
		tlsKeys.PreMasterSecret = make([]byte, len(sessionKeys.PreMasterSecret))
		copy(tlsKeys.PreMasterSecret, sessionKeys.PreMasterSecret)
	}

	// Copy TLS 1.3 secrets
	if len(sessionKeys.ClientHandshakeTrafficSecret) > 0 {
		tlsKeys.ClientHandshakeTrafficSecret = make([]byte, len(sessionKeys.ClientHandshakeTrafficSecret))
		copy(tlsKeys.ClientHandshakeTrafficSecret, sessionKeys.ClientHandshakeTrafficSecret)
	}
	if len(sessionKeys.ServerHandshakeTrafficSecret) > 0 {
		tlsKeys.ServerHandshakeTrafficSecret = make([]byte, len(sessionKeys.ServerHandshakeTrafficSecret))
		copy(tlsKeys.ServerHandshakeTrafficSecret, sessionKeys.ServerHandshakeTrafficSecret)
	}
	if len(sessionKeys.ClientTrafficSecret0) > 0 {
		tlsKeys.ClientTrafficSecret_0 = make([]byte, len(sessionKeys.ClientTrafficSecret0))
		copy(tlsKeys.ClientTrafficSecret_0, sessionKeys.ClientTrafficSecret0)
	}
	if len(sessionKeys.ServerTrafficSecret0) > 0 {
		tlsKeys.ServerTrafficSecret_0 = make([]byte, len(sessionKeys.ServerTrafficSecret0))
		copy(tlsKeys.ServerTrafficSecret_0, sessionKeys.ServerTrafficSecret0)
	}
	if len(sessionKeys.ExporterSecret) > 0 {
		tlsKeys.ExporterSecret = make([]byte, len(sessionKeys.ExporterSecret))
		copy(tlsKeys.ExporterSecret, sessionKeys.ExporterSecret)
	}
	if len(sessionKeys.EarlyExporterSecret) > 0 {
		tlsKeys.EarlyExporterSecret = make([]byte, len(sessionKeys.EarlyExporterSecret))
		copy(tlsKeys.EarlyExporterSecret, sessionKeys.EarlyExporterSecret)
	}
	if len(sessionKeys.ClientEarlyTrafficSecret) > 0 {
		tlsKeys.ClientEarlyTrafficSecret = make([]byte, len(sessionKeys.ClientEarlyTrafficSecret))
		copy(tlsKeys.ClientEarlyTrafficSecret, sessionKeys.ClientEarlyTrafficSecret)
	}

	// Attach to packet
	packet.TlsKeys = tlsKeys

	logger.Debug("TLS session keys attached to packet",
		"client_random", clientRandomHex[:16]+"...",
		"tls_version", tlsVersion,
		"cipher_suite", cipherSuite,
		"is_tls13", sessionKeys.IsTLS13())

	return true
}

// AttachKeysFromClientRandom is a convenience method that looks up keys by client random only.
// Use this when you have the client random but not other session details yet.
func (f *TLSKeyForwarder) AttachKeysFromClientRandom(
	packet *data.CapturedPacket,
	clientRandom []byte,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
) bool {
	return f.AttachKeys(packet, clientRandom, nil, 0, 0, srcIP, dstIP, srcPort, dstPort)
}

// HasKeysForSession checks if session keys are available for the given client random.
func (f *TLSKeyForwarder) HasKeysForSession(clientRandom []byte) bool {
	if f.keyStore == nil || len(clientRandom) != 32 {
		return false
	}

	var cr [32]byte
	copy(cr[:], clientRandom)
	sessionKeys := f.keyStore.Get(cr)
	return sessionKeys != nil && sessionKeys.HasDecryptionKeys()
}

// WasKeyForwarded checks if keys have already been forwarded for the given client random.
func (f *TLSKeyForwarder) WasKeyForwarded(clientRandom []byte) bool {
	if len(clientRandom) != 32 {
		return false
	}

	clientRandomHex := keylog.BytesToHex(clientRandom)

	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.forwardedSessions[clientRandomHex]
}

// Stats returns forwarding statistics.
func (f *TLSKeyForwarder) Stats() (forwarded, missing uint64) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.keysForwarded, f.keysMissing
}

// Reset clears the forwarded sessions tracking.
// This is useful when the processor connection is re-established.
func (f *TLSKeyForwarder) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwardedSessions = make(map[string]bool)
}

// SessionCount returns the number of sessions being tracked.
func (f *TLSKeyForwarder) SessionCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.forwardedSessions)
}

// Cleanup removes old session tracking entries.
// This should be called periodically to prevent memory growth.
// maxSessions specifies the maximum number of sessions to track.
func (f *TLSKeyForwarder) Cleanup(maxSessions int) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.forwardedSessions) <= maxSessions {
		return 0
	}

	// Simple approach: clear all and let new sessions be tracked
	// A more sophisticated approach would use LRU eviction
	removed := len(f.forwardedSessions) - maxSessions
	if removed > 0 {
		// Clear the oldest entries (since Go maps don't maintain order,
		// we just clear some entries randomly which is acceptable for this use case)
		count := 0
		for k := range f.forwardedSessions {
			delete(f.forwardedSessions, k)
			count++
			if count >= removed {
				break
			}
		}
	}

	return removed
}
