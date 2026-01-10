//go:build li

// Package delivery implements X2/X3 delivery to MDF endpoints per ETSI TS 103 221-2.
//
// The package manages persistent TLS connections to MDF (Mediation and Delivery Function)
// endpoints and provides reliable delivery of X2 (IRI) and X3 (CC) PDUs.
package delivery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Connection state constants.
const (
	connStateDisconnected int32 = iota
	connStateConnecting
	connStateConnected
)

// Default configuration values.
const (
	// DefaultDialTimeout is the default timeout for establishing connections.
	DefaultDialTimeout = 10 * time.Second

	// DefaultWriteTimeout is the default timeout for write operations.
	DefaultWriteTimeout = 5 * time.Second

	// DefaultInitialBackoff is the initial backoff duration for reconnection.
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the maximum backoff duration for reconnection.
	DefaultMaxBackoff = 5 * time.Minute

	// DefaultBackoffMultiplier is the multiplier for exponential backoff.
	DefaultBackoffMultiplier = 2.0

	// DefaultMaxPoolSize is the default maximum connections per destination.
	DefaultMaxPoolSize = 4

	// DefaultKeepAliveInterval is the interval for TCP keep-alives.
	DefaultKeepAliveInterval = 30 * time.Second
)

// Errors returned by the destination manager.
var (
	// ErrDestinationNotFound indicates the requested destination DID does not exist.
	ErrDestinationNotFound = errors.New("destination not found")

	// ErrDestinationExists indicates a destination with the given DID already exists.
	ErrDestinationExists = errors.New("destination already exists")

	// ErrNotConnected indicates the destination is not connected.
	ErrNotConnected = errors.New("destination not connected")

	// ErrConnectionFailed indicates a connection attempt failed.
	ErrConnectionFailed = errors.New("connection failed")

	// ErrShuttingDown indicates the manager is shutting down.
	ErrShuttingDown = errors.New("manager is shutting down")

	// ErrPoolExhausted indicates no connections are available in the pool.
	ErrPoolExhausted = errors.New("connection pool exhausted")

	// ErrMutualTLSRequired indicates mutual TLS is required but not configured.
	ErrMutualTLSRequired = errors.New("mutual TLS required: client certificate and key must be provided")

	// ErrCertificatePinningFailed indicates the server certificate doesn't match pinned fingerprints.
	ErrCertificatePinningFailed = errors.New("certificate pinning failed: server certificate fingerprint not in pinned list")
)

// DestinationConfig holds configuration for the destination manager.
// Mutual TLS is REQUIRED for X2/X3 delivery per ETSI TS 103 221-2.
type DestinationConfig struct {
	// TLSCertFile is the path to the client TLS certificate for mutual TLS.
	// REQUIRED: mutual TLS is mandatory for LI delivery.
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key.
	// REQUIRED: mutual TLS is mandatory for LI delivery.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate for server verification.
	// If empty, system CA pool is used.
	TLSCAFile string

	// TLSPinnedCerts contains SHA256 fingerprints of pinned server certificates.
	// If non-empty, server certificates must match one of these fingerprints.
	// Fingerprints should be lowercase hex-encoded SHA256 hashes.
	TLSPinnedCerts []string

	// DialTimeout is the timeout for establishing connections.
	DialTimeout time.Duration

	// WriteTimeout is the timeout for write operations.
	WriteTimeout time.Duration

	// InitialBackoff is the initial backoff duration for reconnection.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration for reconnection.
	MaxBackoff time.Duration

	// BackoffMultiplier is the multiplier for exponential backoff.
	BackoffMultiplier float64

	// MaxPoolSize is the maximum number of connections per destination.
	MaxPoolSize int

	// KeepAliveInterval is the interval for TCP keep-alives.
	KeepAliveInterval time.Duration
}

// DefaultConfig returns a DestinationConfig with default values.
func DefaultConfig() DestinationConfig {
	return DestinationConfig{
		DialTimeout:       DefaultDialTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		InitialBackoff:    DefaultInitialBackoff,
		MaxBackoff:        DefaultMaxBackoff,
		BackoffMultiplier: DefaultBackoffMultiplier,
		MaxPoolSize:       DefaultMaxPoolSize,
		KeepAliveInterval: DefaultKeepAliveInterval,
	}
}

// destinationState holds the runtime state for a destination.
type destinationState struct {
	mu sync.RWMutex

	// dest is the destination configuration from the registry.
	dest *li.Destination

	// pool holds the connection pool for this destination.
	pool *connPool

	// state is the current connection state.
	state int32

	// backoff is the current backoff duration for reconnection.
	backoff time.Duration

	// lastError is the most recent connection error.
	lastError error

	// lastConnectAttempt is the time of the last connection attempt.
	lastConnectAttempt time.Time

	// reconnectTimer triggers reconnection attempts.
	reconnectTimer *time.Timer

	// stats holds connection statistics.
	stats DestinationStats
}

// DestinationStats contains statistics for a destination.
type DestinationStats struct {
	// ConnectAttempts is the total number of connection attempts.
	ConnectAttempts uint64

	// ConnectSuccesses is the number of successful connections.
	ConnectSuccesses uint64

	// ConnectFailures is the number of failed connections.
	ConnectFailures uint64

	// Disconnects is the number of disconnections.
	Disconnects uint64

	// BytesSent is the total bytes sent.
	BytesSent uint64

	// PDUsSent is the total PDUs sent.
	PDUsSent uint64

	// WriteErrors is the number of write errors.
	WriteErrors uint64
}

// connPool manages a pool of TLS connections to a destination.
type connPool struct {
	mu sync.Mutex

	// conns holds available connections.
	conns []*pooledConn

	// maxSize is the maximum pool size.
	maxSize int

	// inUse tracks connections currently in use.
	inUse int

	// closed indicates the pool is closed.
	closed bool
}

// pooledConn wraps a TLS connection with pool management.
type pooledConn struct {
	conn      *tls.Conn
	createdAt time.Time
	lastUsed  time.Time
}

// newConnPool creates a new connection pool.
func newConnPool(maxSize int) *connPool {
	return &connPool{
		conns:   make([]*pooledConn, 0, maxSize),
		maxSize: maxSize,
	}
}

// get retrieves a connection from the pool.
// Returns nil if no connection is available.
func (p *connPool) get() *pooledConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	if len(p.conns) == 0 {
		return nil
	}

	// Get the last connection (LIFO for better locality).
	conn := p.conns[len(p.conns)-1]
	p.conns = p.conns[:len(p.conns)-1]
	p.inUse++
	conn.lastUsed = time.Now()
	return conn
}

// put returns a connection to the pool.
// Returns false if the pool is full or closed.
func (p *connPool) put(conn *pooledConn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return false
	}

	p.inUse--

	if len(p.conns) >= p.maxSize {
		return false
	}

	p.conns = append(p.conns, conn)
	return true
}

// close closes all connections in the pool.
func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for _, conn := range p.conns {
		if err := conn.conn.Close(); err != nil {
			logger.Debug("error closing pooled connection", "error", err)
		}
	}
	p.conns = nil
}

// size returns the current pool size (available connections).
func (p *connPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// Manager manages X2/X3 delivery destinations and their TLS connections.
//
// Destinations are configured via X1 (CreateDestination, RemoveDestination).
// The manager maintains persistent TLS connections with automatic reconnection.
type Manager struct {
	mu sync.RWMutex

	// config holds the manager configuration.
	config DestinationConfig

	// destinations maps DID to destination state.
	destinations map[uuid.UUID]*destinationState

	// tlsConfig is the base TLS configuration for client connections.
	tlsConfig *tls.Config

	// stopChan signals shutdown.
	stopChan chan struct{}

	// wg tracks background goroutines.
	wg sync.WaitGroup

	// shuttingDown indicates shutdown is in progress.
	shuttingDown atomic.Bool
}

// NewManager creates a new destination manager.
func NewManager(config DestinationConfig) (*Manager, error) {
	// Mutual TLS is REQUIRED for X2/X3 delivery per ETSI TS 103 221-2.
	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return nil, ErrMutualTLSRequired
	}

	// Build TLS config.
	tlsConfig, err := buildClientTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	return &Manager{
		config:       config,
		destinations: make(map[uuid.UUID]*destinationState),
		tlsConfig:    tlsConfig,
		stopChan:     make(chan struct{}),
	}, nil
}

// buildClientTLSConfig builds the TLS configuration for X2/X3 delivery client connections.
// Per ETSI TS 103 221-2, mutual TLS is REQUIRED for delivery to MDF endpoints.
// TLS 1.2 is minimum, TLS 1.3 is preferred.
func buildClientTLSConfig(config DestinationConfig) (*tls.Config, error) {
	// Validate that mTLS is configured - this is mandatory for LI delivery.
	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return nil, ErrMutualTLSRequired
	}

	// Load client certificate for mutual TLS.
	cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Minimum TLS 1.2, prefer TLS 1.3 (Go's crypto/tls prefers 1.3 when available)
		MinVersion: tls.VersionTLS12,
		// Secure cipher suites - TLS 1.3 suites are automatically preferred when available
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (automatically used when TLS 1.3 is negotiated)
			// tls.TLS_AES_256_GCM_SHA384,       // Handled automatically by Go for TLS 1.3
			// tls.TLS_AES_128_GCM_SHA256,       // Handled automatically by Go for TLS 1.3
			// tls.TLS_CHACHA20_POLY1305_SHA256, // Handled automatically by Go for TLS 1.3

			// TLS 1.2 cipher suites (fallback when TLS 1.3 not available)
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		// Prefer server cipher order for TLS 1.2 (TLS 1.3 always uses server preference)
		PreferServerCipherSuites: true,
	}

	// Load CA certificate if provided, otherwise use system CA pool.
	if config.TLSCAFile != "" {
		caCert, err := os.ReadFile(config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = certPool
	}

	// Configure certificate pinning if fingerprints are provided.
	if len(config.TLSPinnedCerts) > 0 {
		// Normalize fingerprints to lowercase for consistent comparison.
		pinnedFingerprints := make(map[string]struct{}, len(config.TLSPinnedCerts))
		for _, fp := range config.TLSPinnedCerts {
			pinnedFingerprints[strings.ToLower(strings.ReplaceAll(fp, ":", ""))] = struct{}{}
		}

		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// At least one certificate in the chain must match a pinned fingerprint.
			for _, rawCert := range rawCerts {
				fingerprint := sha256.Sum256(rawCert)
				fpHex := hex.EncodeToString(fingerprint[:])
				if _, ok := pinnedFingerprints[fpHex]; ok {
					logger.Debug("certificate pinning: matched pinned fingerprint",
						"fingerprint", fpHex,
					)
					return nil
				}
			}

			// Log what we received for debugging.
			if len(rawCerts) > 0 {
				fingerprint := sha256.Sum256(rawCerts[0])
				logger.Warn("certificate pinning failed: no matching fingerprint",
					"server_fingerprint", hex.EncodeToString(fingerprint[:]),
					"pinned_count", len(pinnedFingerprints),
				)
			}

			return ErrCertificatePinningFailed
		}
	}

	return tlsConfig, nil
}

// Start begins the manager's background operations.
func (m *Manager) Start() {
	logger.Info("destination manager started")
}

// Stop gracefully shuts down the manager and closes all connections.
func (m *Manager) Stop() {
	m.shuttingDown.Store(true)
	close(m.stopChan)

	m.mu.Lock()
	for did, state := range m.destinations {
		m.closeDestinationLocked(did, state)
	}
	m.mu.Unlock()

	m.wg.Wait()
	logger.Info("destination manager stopped")
}

// AddDestination adds a new destination and initiates connection.
func (m *Manager) AddDestination(dest *li.Destination) error {
	if m.shuttingDown.Load() {
		return ErrShuttingDown
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.destinations[dest.DID]; exists {
		return ErrDestinationExists
	}

	state := &destinationState{
		dest:    dest,
		pool:    newConnPool(m.config.MaxPoolSize),
		state:   connStateDisconnected,
		backoff: m.config.InitialBackoff,
	}

	m.destinations[dest.DID] = state

	// Start connection in background.
	m.wg.Add(1)
	go m.connectDestination(dest.DID)

	logger.Info("destination added",
		"did", dest.DID,
		"address", dest.Address,
		"port", dest.Port,
	)

	return nil
}

// RemoveDestination removes a destination and closes its connections.
func (m *Manager) RemoveDestination(did uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.destinations[did]
	if !exists {
		return ErrDestinationNotFound
	}

	m.closeDestinationLocked(did, state)
	delete(m.destinations, did)

	logger.Info("destination removed", "did", did)
	return nil
}

// UpdateDestination updates a destination's configuration.
// If address or port changed, connections are re-established.
func (m *Manager) UpdateDestination(dest *li.Destination) error {
	if m.shuttingDown.Load() {
		return ErrShuttingDown
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.destinations[dest.DID]
	if !exists {
		return ErrDestinationNotFound
	}

	state.mu.Lock()
	oldDest := state.dest
	addressChanged := oldDest.Address != dest.Address || oldDest.Port != dest.Port
	state.dest = dest
	state.mu.Unlock()

	// Reconnect if address changed.
	if addressChanged {
		m.closeDestinationLocked(dest.DID, state)
		state.pool = newConnPool(m.config.MaxPoolSize)
		state.backoff = m.config.InitialBackoff

		m.wg.Add(1)
		go m.connectDestination(dest.DID)

		logger.Info("destination updated, reconnecting",
			"did", dest.DID,
			"address", dest.Address,
			"port", dest.Port,
		)
	}

	return nil
}

// GetDestination returns the destination configuration by DID.
func (m *Manager) GetDestination(did uuid.UUID) (*li.Destination, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.destinations[did]
	if !exists {
		return nil, ErrDestinationNotFound
	}

	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.dest, nil
}

// GetConnection acquires a connection to the destination.
// The caller must call ReleaseConnection when done.
// The context is used for connection establishment timeout and cancellation.
func (m *Manager) GetConnection(ctx context.Context, did uuid.UUID) (*tls.Conn, error) {
	if m.shuttingDown.Load() {
		return nil, ErrShuttingDown
	}

	// Check for context cancellation early.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrDestinationNotFound
	}

	// Try to get from pool.
	if pooled := state.pool.get(); pooled != nil {
		return pooled.conn, nil
	}

	// Check if connected.
	if atomic.LoadInt32(&state.state) != connStateConnected {
		return nil, ErrNotConnected
	}

	// Create a new connection using the provided context.
	conn, err := m.dialDestinationWithContext(ctx, state)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// ReleaseConnection returns a connection to the pool.
func (m *Manager) ReleaseConnection(did uuid.UUID, conn *tls.Conn) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists || m.shuttingDown.Load() {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing released connection", "error", err)
		}
		return
	}

	pooled := &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	if !state.pool.put(pooled) {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing excess connection", "error", err)
		}
	}
}

// InvalidateConnection closes a connection that encountered an error.
func (m *Manager) InvalidateConnection(did uuid.UUID, conn *tls.Conn) {
	if err := conn.Close(); err != nil {
		logger.Debug("error closing invalidated connection", "error", err)
	}

	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists {
		return
	}

	state.mu.Lock()
	state.stats.Disconnects++
	state.mu.Unlock()

	// Check if we need to reconnect.
	if state.pool.size() == 0 && atomic.LoadInt32(&state.state) == connStateConnected {
		atomic.StoreInt32(&state.state, connStateDisconnected)
		m.scheduleReconnect(did, state)
	}
}

// IsConnected returns whether the destination has active connections.
func (m *Manager) IsConnected(did uuid.UUID) bool {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	return atomic.LoadInt32(&state.state) == connStateConnected
}

// Stats returns statistics for a destination.
func (m *Manager) Stats(did uuid.UUID) (DestinationStats, error) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists {
		return DestinationStats{}, ErrDestinationNotFound
	}

	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.stats, nil
}

// AllStats returns statistics for all destinations.
func (m *Manager) AllStats() map[uuid.UUID]DestinationStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[uuid.UUID]DestinationStats, len(m.destinations))
	for did, state := range m.destinations {
		state.mu.RLock()
		stats[did] = state.stats
		state.mu.RUnlock()
	}
	return stats
}

// DestinationCount returns the number of registered destinations.
func (m *Manager) DestinationCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.destinations)
}

// connectDestination establishes connections to a destination.
func (m *Manager) connectDestination(did uuid.UUID) {
	defer m.wg.Done()

	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists || m.shuttingDown.Load() {
		return
	}

	// Attempt to transition to connecting state.
	if !atomic.CompareAndSwapInt32(&state.state, connStateDisconnected, connStateConnecting) {
		return
	}

	state.mu.Lock()
	state.stats.ConnectAttempts++
	state.lastConnectAttempt = time.Now()
	state.mu.Unlock()

	// Dial the destination.
	conn, err := m.dialDestination(state)
	if err != nil {
		atomic.StoreInt32(&state.state, connStateDisconnected)

		state.mu.Lock()
		state.stats.ConnectFailures++
		state.lastError = err
		state.mu.Unlock()

		logger.Warn("destination connection failed",
			"did", did,
			"error", err,
			"backoff", state.backoff,
		)

		m.scheduleReconnect(did, state)
		return
	}

	// Put the initial connection in the pool.
	pooled := &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}
	state.pool.put(pooled)

	atomic.StoreInt32(&state.state, connStateConnected)

	state.mu.Lock()
	state.stats.ConnectSuccesses++
	state.backoff = m.config.InitialBackoff // Reset backoff on success.
	state.lastError = nil
	dest := state.dest
	state.mu.Unlock()

	logger.Info("destination connected",
		"did", did,
		"address", dest.Address,
		"port", dest.Port,
	)
}

// dialDestination creates a new TLS connection to the destination.
// Uses a background context with the configured dial timeout.
func (m *Manager) dialDestination(state *destinationState) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.DialTimeout)
	defer cancel()
	return m.dialDestinationWithContext(ctx, state)
}

// dialDestinationWithContext creates a new TLS connection using the provided context.
// The context controls both the TCP dial and TLS handshake timeouts.
func (m *Manager) dialDestinationWithContext(ctx context.Context, state *destinationState) (*tls.Conn, error) {
	state.mu.RLock()
	dest := state.dest
	state.mu.RUnlock()

	address := fmt.Sprintf("%s:%d", dest.Address, dest.Port)

	// Create dialer with keepalive.
	dialer := &net.Dialer{
		KeepAlive: m.config.KeepAliveInterval,
	}

	// Dial TCP using the provided context for timeout/cancellation.
	tcpConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Build TLS config for this connection.
	tlsConfig := m.tlsConfig.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	tlsConfig.ServerName = dest.Address

	// Use destination-specific TLS config if available.
	if dest.TLSConfig != nil {
		tlsConfig = dest.TLSConfig.Clone()
	}

	// Wrap with TLS.
	tlsConn := tls.Client(tcpConn, tlsConfig)

	// Perform handshake with context-based timeout.
	// Calculate remaining time from context deadline for handshake.
	handshakeDeadline := time.Now().Add(m.config.DialTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}

	if err := tlsConn.SetDeadline(handshakeDeadline); err != nil {
		if closeErr := tcpConn.Close(); closeErr != nil {
			logger.Debug("error closing connection after deadline error", "error", closeErr)
		}
		return nil, fmt.Errorf("%w: failed to set deadline: %v", ErrConnectionFailed, err)
	}

	// Check for context cancellation before handshake.
	select {
	case <-ctx.Done():
		if closeErr := tcpConn.Close(); closeErr != nil {
			logger.Debug("error closing connection after context cancellation", "error", closeErr)
		}
		return nil, ctx.Err()
	default:
	}

	if err := tlsConn.Handshake(); err != nil {
		if closeErr := tcpConn.Close(); closeErr != nil {
			logger.Debug("error closing connection after handshake error", "error", closeErr)
		}
		return nil, fmt.Errorf("%w: TLS handshake failed: %v", ErrConnectionFailed, err)
	}

	// Clear deadline for normal operation.
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		if closeErr := tlsConn.Close(); closeErr != nil {
			logger.Debug("error closing connection after deadline clear error", "error", closeErr)
		}
		return nil, fmt.Errorf("%w: failed to clear deadline: %v", ErrConnectionFailed, err)
	}

	return tlsConn, nil
}

// scheduleReconnect schedules a reconnection attempt with exponential backoff.
func (m *Manager) scheduleReconnect(did uuid.UUID, state *destinationState) {
	if m.shuttingDown.Load() {
		return
	}

	state.mu.Lock()
	backoff := state.backoff
	// Increase backoff for next attempt.
	state.backoff = time.Duration(float64(state.backoff) * m.config.BackoffMultiplier)
	if state.backoff > m.config.MaxBackoff {
		state.backoff = m.config.MaxBackoff
	}

	// Cancel any existing timer.
	if state.reconnectTimer != nil {
		state.reconnectTimer.Stop()
	}

	state.reconnectTimer = time.AfterFunc(backoff, func() {
		if !m.shuttingDown.Load() {
			m.wg.Add(1)
			go m.connectDestination(did)
		}
	})
	state.mu.Unlock()

	logger.Debug("reconnect scheduled",
		"did", did,
		"backoff", backoff,
	)
}

// closeDestinationLocked closes a destination's connections.
// Caller must hold m.mu.
func (m *Manager) closeDestinationLocked(did uuid.UUID, state *destinationState) {
	state.mu.Lock()
	if state.reconnectTimer != nil {
		state.reconnectTimer.Stop()
		state.reconnectTimer = nil
	}
	state.mu.Unlock()

	state.pool.close()
	atomic.StoreInt32(&state.state, connStateDisconnected)
}

// RecordBytesSent records bytes sent for statistics.
func (m *Manager) RecordBytesSent(did uuid.UUID, bytes uint64) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if exists {
		state.mu.Lock()
		state.stats.BytesSent += bytes
		state.stats.PDUsSent++
		state.mu.Unlock()
	}
}

// RecordWriteError records a write error for statistics.
func (m *Manager) RecordWriteError(did uuid.UUID) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if exists {
		state.mu.Lock()
		state.stats.WriteErrors++
		state.mu.Unlock()
	}
}
