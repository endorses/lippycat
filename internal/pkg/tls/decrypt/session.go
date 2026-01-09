//go:build cli || hunter || tap || tui || all

package decrypt

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls/decrypt/ciphers"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
)

// SessionManagerConfig configures the session manager.
type SessionManagerConfig struct {
	// MaxSessions limits the number of active decryption sessions.
	// When exceeded, oldest sessions are evicted (LRU).
	// Default: 10000
	MaxSessions int

	// SessionTimeout is how long to keep an inactive session.
	// Default: 30 minutes
	SessionTimeout time.Duration

	// PendingRecordLimit limits buffered records per session while waiting for keys.
	// Default: 100
	PendingRecordLimit int

	// CleanupInterval is how often to run the cleanup routine.
	// Default: 1 minute
	CleanupInterval time.Duration

	// OnDecryptedData is called when application data is successfully decrypted.
	// The callback receives the session ID (client random hex), direction, and plaintext.
	OnDecryptedData func(sessionID string, dir Direction, plaintext []byte)
}

// DefaultSessionManagerConfig returns the default configuration.
func DefaultSessionManagerConfig() SessionManagerConfig {
	return SessionManagerConfig{
		MaxSessions:        10000,
		SessionTimeout:     30 * time.Minute,
		PendingRecordLimit: 100,
		CleanupInterval:    1 * time.Minute,
	}
}

// SessionManager integrates TLS session tracking with key log lookup and decryption.
// It manages the lifecycle of decryption sessions and handles the case where
// keys arrive before or after the TLS handshake is observed.
type SessionManager struct {
	config   SessionManagerConfig
	keyStore *keylog.Store

	// Sessions indexed by flow key (srcIP:srcPort-dstIP:dstPort)
	sessions map[string]*DecryptionSession
	// Reverse lookup: client random -> flow key (for key arrival callbacks)
	clientRandomToFlow map[[32]byte]string

	mu       sync.RWMutex
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Statistics
	totalSessions     uint64
	decryptedRecords  uint64
	failedDecryptions uint64
	keysMatched       uint64
	pendingDropped    uint64
}

// NewSessionManager creates a new session manager.
func NewSessionManager(config SessionManagerConfig, keyStore *keylog.Store) *SessionManager {
	if config.MaxSessions <= 0 {
		config.MaxSessions = DefaultSessionManagerConfig().MaxSessions
	}
	if config.SessionTimeout <= 0 {
		config.SessionTimeout = DefaultSessionManagerConfig().SessionTimeout
	}
	if config.PendingRecordLimit <= 0 {
		config.PendingRecordLimit = DefaultSessionManagerConfig().PendingRecordLimit
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = DefaultSessionManagerConfig().CleanupInterval
	}

	sm := &SessionManager{
		config:             config,
		keyStore:           keyStore,
		sessions:           make(map[string]*DecryptionSession),
		clientRandomToFlow: make(map[[32]byte]string),
		stopChan:           make(chan struct{}),
	}

	// Register callback with key store for key arrivals
	if keyStore != nil {
		keyStore.SetOnKeyAdded(sm.onKeyAdded)
	}

	// Start cleanup goroutine
	sm.wg.Add(1)
	go sm.cleanupLoop()

	return sm
}

// DecryptionSession holds the decryption state for a single TLS session.
type DecryptionSession struct {
	// Flow identification
	FlowKey    string
	SrcIP      net.IP
	SrcPort    uint16
	DstIP      net.IP
	DstPort    uint16
	CreatedAt  time.Time
	LastAccess time.Time

	// TLS handshake info (from ClientHello/ServerHello)
	ClientRandom   [32]byte
	ServerRandom   [32]byte
	CipherSuite    uint16
	Version        uint16
	HasClientHello bool
	HasServerHello bool

	// Key derivation state
	KeysAvailable bool
	State         *SessionState

	// Record parsing and reassembly
	clientParser *RecordParser
	serverParser *RecordParser

	// Pending records (waiting for keys)
	pendingClientRecords []*PendingRecord
	pendingServerRecords []*PendingRecord

	// Decrypted application data buffers
	ClientAppData []byte
	ServerAppData []byte

	// Session resumption info
	SessionID     []byte
	SessionTicket []byte

	// Statistics
	RecordsDecrypted   uint64
	DecryptionFailures uint64
}

// PendingRecord stores an encrypted record waiting for keys.
type PendingRecord struct {
	Record    *Record
	Timestamp time.Time
}

// ProcessClientHello processes a ClientHello and initializes a session.
func (sm *SessionManager) ProcessClientHello(flowKey string, srcIP, dstIP net.IP, srcPort, dstPort uint16, record *Record) error {
	clientRandom := ExtractClientRandom(record)
	if clientRandom == nil {
		return fmt.Errorf("failed to extract client random from ClientHello")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if session already exists
	session, exists := sm.sessions[flowKey]
	if !exists {
		// Check if we need to evict
		if len(sm.sessions) >= sm.config.MaxSessions {
			sm.evictOldestLocked()
		}

		session = &DecryptionSession{
			FlowKey:      flowKey,
			SrcIP:        srcIP,
			SrcPort:      srcPort,
			DstIP:        dstIP,
			DstPort:      dstPort,
			CreatedAt:    time.Now(),
			LastAccess:   time.Now(),
			clientParser: NewRecordParser(),
			serverParser: NewRecordParser(),
		}
		sm.sessions[flowKey] = session
		sm.totalSessions++
	}

	// Store client random
	copy(session.ClientRandom[:], clientRandom)
	session.HasClientHello = true
	session.LastAccess = time.Now()

	// Create reverse lookup
	var clientRandomKey [32]byte
	copy(clientRandomKey[:], clientRandom)
	sm.clientRandomToFlow[clientRandomKey] = flowKey

	// Extract session ID for resumption
	if len(record.Fragment) > 38 {
		sessionIDLen := int(record.Fragment[38])
		if sessionIDLen > 0 && len(record.Fragment) >= 39+sessionIDLen {
			session.SessionID = make([]byte, sessionIDLen)
			copy(session.SessionID, record.Fragment[39:39+sessionIDLen])
		}
	}

	// Check if keys are already available
	sm.tryDeriveKeysLocked(session)

	return nil
}

// ProcessServerHello processes a ServerHello and completes handshake info.
func (sm *SessionManager) ProcessServerHello(flowKey string, record *Record) error {
	serverRandom := ExtractServerRandom(record)
	if serverRandom == nil {
		return fmt.Errorf("failed to extract server random from ServerHello")
	}

	cipherSuite := ExtractCipherSuite(record)
	if cipherSuite == 0 {
		return fmt.Errorf("failed to extract cipher suite from ServerHello")
	}

	version := ExtractTLSVersion(record)

	// For ServerHello, flow is reversed (server -> client), so look up with reversed key
	// The caller should handle flow reversal
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[flowKey]
	if !exists {
		// ServerHello arrived before ClientHello - create session
		if len(sm.sessions) >= sm.config.MaxSessions {
			sm.evictOldestLocked()
		}

		session = &DecryptionSession{
			FlowKey:      flowKey,
			CreatedAt:    time.Now(),
			LastAccess:   time.Now(),
			clientParser: NewRecordParser(),
			serverParser: NewRecordParser(),
		}
		sm.sessions[flowKey] = session
		sm.totalSessions++
	}

	copy(session.ServerRandom[:], serverRandom)
	session.CipherSuite = cipherSuite
	session.Version = version
	session.HasServerHello = true
	session.LastAccess = time.Now()

	// Try to derive keys now that we have server info
	sm.tryDeriveKeysLocked(session)

	return nil
}

// ProcessChangeCipherSpec marks the point where encryption begins.
func (sm *SessionManager) ProcessChangeCipherSpec(flowKey string, dir Direction) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[flowKey]
	if !exists {
		return
	}

	if session.State == nil {
		return
	}

	session.State.SetEncrypted(dir, true)
	session.LastAccess = time.Now()
}

// DecryptRecord attempts to decrypt an application data record.
// Returns the decrypted plaintext or an error if decryption fails.
func (sm *SessionManager) DecryptRecord(flowKey string, dir Direction, record *Record) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[flowKey]
	if !exists {
		return nil, fmt.Errorf("no session for flow %s", flowKey)
	}

	session.LastAccess = time.Now()

	// If keys not available, queue record for later
	if !session.KeysAvailable || session.State == nil {
		sm.queuePendingRecordLocked(session, dir, record)
		return nil, ErrNoKeys
	}

	// Check if encryption is active for this direction
	if !session.State.IsEncrypted(dir) {
		// Not encrypted yet - this might be handshake data
		return record.Fragment, nil
	}

	return sm.decryptRecordLocked(session, dir, record)
}

// decryptRecordLocked performs the actual decryption.
func (sm *SessionManager) decryptRecordLocked(session *DecryptionSession, dir Direction, record *Record) ([]byte, error) {
	state := session.State

	// Get the appropriate cipher and IV for this direction
	key := state.GetWriteKey(dir)
	iv := state.GetWriteIV(dir)
	seqNum := state.IncrementSeqNum(dir)

	cipherSuiteInfo := GetCipherSuiteInfo(state.CipherSuite)
	if cipherSuiteInfo == nil {
		session.DecryptionFailures++
		sm.failedDecryptions++
		return nil, ErrUnsupportedCipher
	}

	var plaintext []byte
	var err error

	if cipherSuiteInfo.IsTLS13 {
		plaintext, err = sm.decryptTLS13Record(state, dir, record, key, iv, seqNum, cipherSuiteInfo)
	} else {
		plaintext, err = sm.decryptTLS12Record(state, dir, record, key, iv, seqNum, cipherSuiteInfo)
	}

	if err != nil {
		session.DecryptionFailures++
		sm.failedDecryptions++
		return nil, err
	}

	session.RecordsDecrypted++
	sm.decryptedRecords++

	// Append to application data buffer
	if record.ContentType == ContentTypeApplicationData {
		if dir == DirectionClient {
			session.ClientAppData = append(session.ClientAppData, plaintext...)
		} else {
			session.ServerAppData = append(session.ServerAppData, plaintext...)
		}

		// Call callback if set
		if sm.config.OnDecryptedData != nil {
			clientRandomHex := keylog.BytesToHex(session.ClientRandom[:])
			sm.config.OnDecryptedData(clientRandomHex, dir, plaintext)
		}
	}

	return plaintext, nil
}

// decryptTLS12Record decrypts a TLS 1.2 record.
func (sm *SessionManager) decryptTLS12Record(state *SessionState, dir Direction, record *Record, key, iv []byte, seqNum uint64, cipherSuiteInfo *CipherSuiteInfo) ([]byte, error) {
	fragment := record.Fragment

	var cipher ciphers.Cipher
	var nonce []byte
	var additionalData []byte
	var ciphertext []byte
	var err error

	if cipherSuiteInfo.IsAEAD {
		// AEAD cipher (GCM or ChaCha20-Poly1305)
		if isChaCha20Suite(cipherSuiteInfo.ID) {
			// ChaCha20-Poly1305: nonce = IV XOR seqNum
			nonce = ConstructChaCha20Nonce(iv, seqNum)
			ciphertext = fragment
		} else {
			// GCM: explicit nonce in record (8 bytes)
			if len(fragment) < 8 {
				return nil, ErrInvalidRecord
			}
			explicitNonce := fragment[:8]
			ciphertext = fragment[8:]
			nonce = ConstructGCMNonce(iv, explicitNonce)
		}

		// Compute AAD
		plaintextLen := len(ciphertext) - 16 // 16-byte auth tag
		if plaintextLen < 0 {
			return nil, ErrInvalidRecord
		}
		additionalData = ComputeAdditionalData(seqNum, record.ContentType, record.Version, plaintextLen)

		cipher, err = ciphers.NewCipher(cipherSuiteInfo.ID, key, iv, nil)
	} else {
		// CBC cipher with HMAC
		macKey := state.ClientMACKey
		if dir == DirectionServer {
			macKey = state.ServerMACKey
		}

		// For TLS 1.1+, explicit IV is in the record
		if state.Version >= VersionTLS11 {
			if len(fragment) < cipherSuiteInfo.IVLen {
				return nil, ErrInvalidRecord
			}
			nonce = fragment[:cipherSuiteInfo.IVLen]
			ciphertext = fragment[cipherSuiteInfo.IVLen:]
		} else {
			// TLS 1.0: implicit IV (use last cipher block)
			nonce = iv
			ciphertext = fragment
		}

		// AAD for MAC verification
		additionalData = ComputeAdditionalData(seqNum, record.ContentType, record.Version, 0)

		cipher, err = ciphers.NewCipher(cipherSuiteInfo.ID, key, nonce, macKey)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext, err := cipher.Decrypt(ciphertext, nonce, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// decryptTLS13Record decrypts a TLS 1.3 record.
func (sm *SessionManager) decryptTLS13Record(state *SessionState, dir Direction, record *Record, key, iv []byte, seqNum uint64, cipherSuiteInfo *CipherSuiteInfo) ([]byte, error) {
	// TLS 1.3: nonce = IV XOR seqNum (padded to IV length)
	nonce := ConstructTLS13Nonce(iv, seqNum)

	// AAD is the record header (5 bytes)
	additionalData := ComputeTLS13AdditionalData(len(record.Fragment))

	cipher, err := ciphers.NewCipher(cipherSuiteInfo.ID, key, iv, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext, err := cipher.Decrypt(record.Fragment, nonce, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// TLS 1.3 inner plaintext has padding and real content type at the end
	// Remove padding zeros and extract real content type
	if len(plaintext) > 0 {
		// Find the last non-zero byte (real content type)
		i := len(plaintext) - 1
		for i >= 0 && plaintext[i] == 0 {
			i--
		}
		if i >= 0 {
			// realContentType := plaintext[i]
			plaintext = plaintext[:i]
		}
	}

	return plaintext, nil
}

// tryDeriveKeysLocked attempts to derive session keys if all prerequisites are met.
func (sm *SessionManager) tryDeriveKeysLocked(session *DecryptionSession) {
	// Need both handshake messages
	if !session.HasClientHello || !session.HasServerHello {
		return
	}

	// Need cipher suite
	if session.CipherSuite == 0 {
		return
	}

	// Check if we have keys in the keylog store
	keys := sm.keyStore.Get(session.ClientRandom)
	if keys == nil {
		return
	}

	cipherSuiteInfo := GetCipherSuiteInfo(session.CipherSuite)
	if cipherSuiteInfo == nil {
		logger.Debug("Unsupported cipher suite", "suite", fmt.Sprintf("0x%04x", session.CipherSuite))
		return
	}

	// Initialize session state
	session.State = &SessionState{
		Version:       session.Version,
		ClientRandom:  session.ClientRandom,
		ServerRandom:  session.ServerRandom,
		CipherSuite:   session.CipherSuite,
		HashAlgorithm: cipherSuiteInfo.HashAlgorithm,
	}

	// Derive keys based on TLS version
	if cipherSuiteInfo.IsTLS13 || session.Version == VersionTLS13 {
		sm.deriveKeysTLS13Locked(session, keys, cipherSuiteInfo)
	} else {
		sm.deriveKeysTLS12Locked(session, keys, cipherSuiteInfo)
	}

	session.KeysAvailable = true
	sm.keysMatched++

	logger.Debug("Derived session keys",
		"flow", session.FlowKey,
		"version", VersionName(session.Version),
		"cipher", cipherSuiteInfo.Name,
	)

	// Process pending records
	sm.processPendingRecordsLocked(session)
}

// deriveKeysTLS12Locked derives TLS 1.2 session keys.
func (sm *SessionManager) deriveKeysTLS12Locked(session *DecryptionSession, keys *keylog.SessionKeys, cipherSuiteInfo *CipherSuiteInfo) {
	if len(keys.PreMasterSecret) == 0 {
		logger.Debug("No pre-master secret for TLS 1.2 session")
		return
	}

	// Derive master secret and key material
	keyMaterial, _ := DeriveKeysFromPreMaster(
		keys.PreMasterSecret,
		session.ClientRandom[:],
		session.ServerRandom[:],
		cipherSuiteInfo,
	)

	session.State.ClientWriteKey = keyMaterial.ClientWriteKey
	session.State.ServerWriteKey = keyMaterial.ServerWriteKey
	session.State.ClientWriteIV = keyMaterial.ClientWriteIV
	session.State.ServerWriteIV = keyMaterial.ServerWriteIV
	session.State.ClientMACKey = keyMaterial.ClientMACKey
	session.State.ServerMACKey = keyMaterial.ServerMACKey
}

// deriveKeysTLS13Locked derives TLS 1.3 session keys.
func (sm *SessionManager) deriveKeysTLS13Locked(session *DecryptionSession, keys *keylog.SessionKeys, cipherSuiteInfo *CipherSuiteInfo) {
	// For TLS 1.3, we use the traffic secrets directly from the keylog
	if len(keys.ClientTrafficSecret0) == 0 || len(keys.ServerTrafficSecret0) == 0 {
		logger.Debug("Missing TLS 1.3 traffic secrets")
		return
	}

	// Derive keys from traffic secrets
	clientKeys := DeriveTrafficKeys(cipherSuiteInfo.HashAlgorithm, keys.ClientTrafficSecret0, cipherSuiteInfo)
	serverKeys := DeriveTrafficKeys(cipherSuiteInfo.HashAlgorithm, keys.ServerTrafficSecret0, cipherSuiteInfo)

	session.State.ClientWriteKey = clientKeys.Key
	session.State.ClientWriteIV = clientKeys.IV
	session.State.ServerWriteKey = serverKeys.Key
	session.State.ServerWriteIV = serverKeys.IV

	// Store traffic secrets for potential key updates
	session.State.ClientTrafficSecret = keys.ClientTrafficSecret0
	session.State.ServerTrafficSecret = keys.ServerTrafficSecret0

	// TLS 1.3 encryption starts immediately after ServerHello
	session.State.ClientEncrypted = true
	session.State.ServerEncrypted = true
}

// onKeyAdded is called when a new key entry is added to the key store.
func (sm *SessionManager) onKeyAdded(clientRandom [32]byte, entry *keylog.KeyEntry) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Find session by client random
	flowKey, exists := sm.clientRandomToFlow[clientRandom]
	if !exists {
		// Session not yet seen - keys will be used when session appears
		return
	}

	session, exists := sm.sessions[flowKey]
	if !exists {
		return
	}

	// Try to derive keys
	sm.tryDeriveKeysLocked(session)
}

// queuePendingRecordLocked adds a record to the pending queue.
func (sm *SessionManager) queuePendingRecordLocked(session *DecryptionSession, dir Direction, record *Record) {
	pending := &PendingRecord{
		Record:    record,
		Timestamp: time.Now(),
	}

	if dir == DirectionClient {
		if len(session.pendingClientRecords) >= sm.config.PendingRecordLimit {
			// Drop oldest record
			session.pendingClientRecords = session.pendingClientRecords[1:]
			sm.pendingDropped++
		}
		session.pendingClientRecords = append(session.pendingClientRecords, pending)
	} else {
		if len(session.pendingServerRecords) >= sm.config.PendingRecordLimit {
			session.pendingServerRecords = session.pendingServerRecords[1:]
			sm.pendingDropped++
		}
		session.pendingServerRecords = append(session.pendingServerRecords, pending)
	}
}

// processPendingRecordsLocked decrypts any pending records now that keys are available.
func (sm *SessionManager) processPendingRecordsLocked(session *DecryptionSession) {
	// Process client pending records
	for _, pending := range session.pendingClientRecords {
		if _, err := sm.decryptRecordLocked(session, DirectionClient, pending.Record); err != nil {
			logger.Debug("Failed to decrypt pending client record", "error", err)
		}
	}
	session.pendingClientRecords = nil

	// Process server pending records
	for _, pending := range session.pendingServerRecords {
		if _, err := sm.decryptRecordLocked(session, DirectionServer, pending.Record); err != nil {
			logger.Debug("Failed to decrypt pending server record", "error", err)
		}
	}
	session.pendingServerRecords = nil
}

// GetSession retrieves a session by flow key.
func (sm *SessionManager) GetSession(flowKey string) *DecryptionSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[flowKey]
}

// GetSessionByClientRandom retrieves a session by client random.
func (sm *SessionManager) GetSessionByClientRandom(clientRandom [32]byte) *DecryptionSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	flowKey, exists := sm.clientRandomToFlow[clientRandom]
	if !exists {
		return nil
	}
	return sm.sessions[flowKey]
}

// GetDecryptedData returns the decrypted application data for a session.
func (sm *SessionManager) GetDecryptedData(flowKey string) (clientData, serverData []byte) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[flowKey]
	if !exists {
		return nil, nil
	}

	return session.ClientAppData, session.ServerAppData
}

// FlowKey generates a flow key from connection parameters.
func FlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

// ReverseFlowKey returns the reversed flow key.
func ReverseFlowKey(flowKey string) string {
	// Parse the flow key: srcIP:srcPort-dstIP:dstPort
	// Find the separator between src and dst
	dashIdx := -1
	for i := len(flowKey) - 1; i >= 0; i-- {
		if flowKey[i] == '-' {
			dashIdx = i
			break
		}
	}
	if dashIdx < 0 {
		return flowKey
	}

	src := flowKey[:dashIdx]
	dst := flowKey[dashIdx+1:]

	// Swap src and dst
	return dst + "-" + src
}

// Stats returns session manager statistics.
func (sm *SessionManager) Stats() SessionManagerStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activeSessions := 0
	sessionsWithKeys := 0

	for _, session := range sm.sessions {
		activeSessions++
		if session.KeysAvailable {
			sessionsWithKeys++
		}
	}

	return SessionManagerStats{
		ActiveSessions:    activeSessions,
		SessionsWithKeys:  sessionsWithKeys,
		TotalSessions:     sm.totalSessions,
		DecryptedRecords:  sm.decryptedRecords,
		FailedDecryptions: sm.failedDecryptions,
		KeysMatched:       sm.keysMatched,
		PendingDropped:    sm.pendingDropped,
	}
}

// SessionManagerStats contains session manager statistics.
type SessionManagerStats struct {
	ActiveSessions    int
	SessionsWithKeys  int
	TotalSessions     uint64
	DecryptedRecords  uint64
	FailedDecryptions uint64
	KeysMatched       uint64
	PendingDropped    uint64
}

// Stop stops the session manager.
func (sm *SessionManager) Stop() {
	close(sm.stopChan)
	sm.wg.Wait()
}

// cleanupLoop periodically removes expired sessions.
func (sm *SessionManager) cleanupLoop() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanup()
		case <-sm.stopChan:
			return
		}
	}
}

// cleanup removes expired sessions.
func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for flowKey, session := range sm.sessions {
		if now.Sub(session.LastAccess) > sm.config.SessionTimeout {
			// Remove reverse lookup
			delete(sm.clientRandomToFlow, session.ClientRandom)
			delete(sm.sessions, flowKey)
		}
	}
}

// evictOldestLocked removes the oldest session.
func (sm *SessionManager) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for flowKey, session := range sm.sessions {
		if first || session.LastAccess.Before(oldestTime) {
			oldestKey = flowKey
			oldestTime = session.LastAccess
			first = false
		}
	}

	if !first {
		session := sm.sessions[oldestKey]
		delete(sm.clientRandomToFlow, session.ClientRandom)
		delete(sm.sessions, oldestKey)
	}
}

// isChaCha20Suite checks if the cipher suite is ChaCha20-Poly1305.
func isChaCha20Suite(id uint16) bool {
	switch id {
	case ciphers.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		ciphers.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		ciphers.TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// ExtractSessionID extracts the session ID from a ClientHello/ServerHello for resumption.
func ExtractSessionID(record *Record) []byte {
	if record.ContentType != ContentTypeHandshake {
		return nil
	}

	if len(record.Fragment) < 39 {
		return nil
	}

	handshakeType := record.Fragment[0]
	if handshakeType != 1 && handshakeType != 2 { // ClientHello or ServerHello
		return nil
	}

	// Skip: Type(1) + Length(3) + Version(2) + Random(32) = 38 bytes
	sessionIDLen := int(record.Fragment[38])
	if sessionIDLen == 0 || len(record.Fragment) < 39+sessionIDLen {
		return nil
	}

	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, record.Fragment[39:39+sessionIDLen])
	return sessionID
}

// ExtractSessionTicket extracts a session ticket from a NewSessionTicket message.
func ExtractSessionTicket(record *Record) (lifetime uint32, ticket []byte) {
	if record.ContentType != ContentTypeHandshake {
		return 0, nil
	}

	if len(record.Fragment) < 10 {
		return 0, nil
	}

	handshakeType := record.Fragment[0]
	if handshakeType != 4 { // NewSessionTicket
		return 0, nil
	}

	// Skip: Type(1) + Length(3) = 4 bytes
	// Lifetime: 4 bytes
	lifetime = binary.BigEndian.Uint32(record.Fragment[4:8])

	// Ticket length: 2 bytes
	ticketLen := binary.BigEndian.Uint16(record.Fragment[8:10])
	if len(record.Fragment) < 10+int(ticketLen) {
		return lifetime, nil
	}

	ticket = make([]byte, ticketLen)
	copy(ticket, record.Fragment[10:10+ticketLen])
	return lifetime, ticket
}
