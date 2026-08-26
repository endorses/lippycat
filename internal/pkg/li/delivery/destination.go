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
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
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
	DefaultInitialBackoff = 500 * time.Millisecond

	// DefaultMaxBackoff is the maximum backoff duration for reconnection.
	DefaultMaxBackoff = 5 * time.Second

	// DefaultBackoffMultiplier is the multiplier for exponential backoff.
	DefaultBackoffMultiplier = 2.0

	// DefaultMaxPoolSize is the default maximum connections per destination.
	DefaultMaxPoolSize = 4

	// DefaultKeepAliveIdle is the idle period before TCP keep-alive probes start.
	DefaultKeepAliveIdle = 15 * time.Second

	// DefaultKeepAliveInterval is the interval between TCP keep-alive probes.
	DefaultKeepAliveInterval = 5 * time.Second

	// DefaultKeepAliveCount is the number of failed probes before disconnect.
	DefaultKeepAliveCount             = 3
	DefaultApplicationKeepaliveTimeP1 = 60 * time.Second
	DefaultApplicationKeepaliveTimeP2 = 180 * time.Second
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
	ErrInvalidKeepaliveTimer    = errors.New("enabled X2/X3 keepalive timers must be at least one second")
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
	// BackoffJitter is the bounded fractional reconnect jitter (0..1).
	BackoffJitter float64

	// SuccessfulWritesBeforeBackoffReset avoids resetting reconnect backoff on
	// connections that immediately fail again. Defaults to one completed write.
	SuccessfulWritesBeforeBackoffReset int

	// MaxPoolSize is the maximum number of connections per destination.
	MaxPoolSize int

	// KeepAliveInterval is the interval for TCP keep-alives.
	KeepAliveInterval time.Duration

	// KeepAliveIdle is the idle period before TCP keep-alive probes start.
	KeepAliveIdle time.Duration

	// KeepAliveCount is the number of failed probes before disconnect.
	KeepAliveCount int

	X2KeepaliveEnabled bool
	X2KeepaliveTimeP1  time.Duration
	X2KeepaliveTimeP2  time.Duration
	X3KeepaliveEnabled bool
	X3KeepaliveTimeP1  time.Duration
	X3KeepaliveTimeP2  time.Duration
	// X2/X3AcknowledgeInboundKeepalive enable the optional responder role. When
	// enabled, a valid inbound Keepalive is answered on the same interface and
	// TLS association with an ACK carrying the identical sequence number.
	X2AcknowledgeInboundKeepalive bool
	X3AcknowledgeInboundKeepalive bool
	// DeliveryFault is invoked after TIME_P2 forces a disconnect. The LI
	// manager wires this to the X1 delivery-error reporting path.
	DeliveryFault func(did uuid.UUID, err error)
}

// DefaultConfig returns a DestinationConfig with default values.
func DefaultConfig() DestinationConfig {
	return DestinationConfig{
		DialTimeout:                        DefaultDialTimeout,
		WriteTimeout:                       DefaultWriteTimeout,
		InitialBackoff:                     DefaultInitialBackoff,
		MaxBackoff:                         DefaultMaxBackoff,
		BackoffMultiplier:                  DefaultBackoffMultiplier,
		BackoffJitter:                      0.20,
		SuccessfulWritesBeforeBackoffReset: 1,
		MaxPoolSize:                        DefaultMaxPoolSize,
		KeepAliveIdle:                      DefaultKeepAliveIdle,
		KeepAliveInterval:                  DefaultKeepAliveInterval,
		KeepAliveCount:                     DefaultKeepAliveCount,
		X2KeepaliveTimeP1:                  DefaultApplicationKeepaliveTimeP1,
		X2KeepaliveTimeP2:                  DefaultApplicationKeepaliveTimeP2,
		X3KeepaliveTimeP1:                  DefaultApplicationKeepaliveTimeP1,
		X3KeepaliveTimeP2:                  DefaultApplicationKeepaliveTimeP2,
	}
}

// destinationState holds the runtime state for a destination.
type destinationState struct {
	mu sync.RWMutex

	// dest is the destination configuration from the registry.
	dest *li.Destination

	// pool holds the connection pool for this destination.
	pool           *connPool
	interfacePools map[PDUType]*connPool

	// state is the current connection state.
	state int32

	// backoff is the current backoff duration for reconnection.
	backoff          time.Duration
	successfulWrites int

	// lastError is the most recent connection error.
	lastError error

	// lastConnectAttempt is the time of the last connection attempt.
	lastConnectAttempt time.Time
	lastFailureLog     time.Time
	failuresSinceLog   uint64

	// reconnectTimer triggers reconnection attempts.
	reconnectTimer *time.Timer

	// connections tracks every live connection, including checked-out pool
	// entries, so reader and writer failures can invalidate idempotently.
	connections map[*tls.Conn]struct{}

	// generation changes whenever endpoint connection state is replaced.
	generation uint64

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
	X2Keepalive InterfaceKeepaliveStats
	X3Keepalive InterfaceKeepaliveStats
}

type InterfaceKeepaliveStats struct {
	Enabled         bool
	TimeP1          time.Duration
	TimeP2          time.Duration
	LastSequence    uint32
	LastSent        time.Time
	LastValidACK    time.Time
	ACKAge          time.Duration
	Timeouts        uint64
	Sent            uint64
	Acknowledged    uint64
	Disconnected    uint64
	Reconnected     uint64
	Inbound         uint64
	InboundACKed    uint64
	Unexpected      uint64
	Malformed       uint64
	ReconnectReason string
}

type connectionRuntime struct {
	writeMu              sync.Mutex
	mu                   sync.Mutex
	iface                PDUType
	keepalive            *interfaceKeepaliveState
	ackInbound           bool
	lastUnexpectedLog    time.Time
	suppressedUnexpected uint64
}

type interfaceKeepaliveState struct {
	enabled           bool
	timeP1, timeP2    time.Duration
	next              uint32
	outstanding       map[uint32]time.Time
	lastSequence      uint32
	lastSent, lastACK time.Time
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

	if p.inUse > 0 {
		p.inUse--
	}

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

// remove discards a connection from the pool and fixes checked-out accounting.
func (p *connPool) remove(conn *tls.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, pooled := range p.conns {
		if pooled.conn == conn {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return
		}
	}
	if p.inUse > 0 {
		p.inUse--
	}
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
	shuttingDown      atomic.Bool
	connectionRuntime sync.Map // *tls.Conn -> *connectionRuntime
}

// NewManager creates a new destination manager.
func NewManager(config DestinationConfig) (*Manager, error) {
	// Mutual TLS is REQUIRED for X2/X3 delivery per ETSI TS 103 221-2.
	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return nil, ErrMutualTLSRequired
	}
	defaults := DefaultConfig()
	if config.DialTimeout <= 0 {
		config.DialTimeout = defaults.DialTimeout
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = defaults.WriteTimeout
	}
	if config.InitialBackoff <= 0 {
		config.InitialBackoff = defaults.InitialBackoff
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = defaults.MaxBackoff
	}
	if config.BackoffMultiplier <= 1 {
		config.BackoffMultiplier = defaults.BackoffMultiplier
	}
	if config.BackoffJitter <= 0 || config.BackoffJitter > 1 {
		config.BackoffJitter = defaults.BackoffJitter
	}
	if config.SuccessfulWritesBeforeBackoffReset <= 0 {
		config.SuccessfulWritesBeforeBackoffReset = defaults.SuccessfulWritesBeforeBackoffReset
	}
	if config.MaxPoolSize <= 0 {
		config.MaxPoolSize = defaults.MaxPoolSize
	}
	if config.KeepAliveIdle <= 0 {
		config.KeepAliveIdle = defaults.KeepAliveIdle
	}
	if config.KeepAliveInterval <= 0 {
		config.KeepAliveInterval = defaults.KeepAliveInterval
	}
	if config.KeepAliveCount <= 0 {
		config.KeepAliveCount = defaults.KeepAliveCount
	}
	if config.X2KeepaliveTimeP1 == 0 {
		config.X2KeepaliveTimeP1 = defaults.X2KeepaliveTimeP1
	}
	if config.X2KeepaliveTimeP2 == 0 {
		config.X2KeepaliveTimeP2 = defaults.X2KeepaliveTimeP2
	}
	if config.X3KeepaliveTimeP1 == 0 {
		config.X3KeepaliveTimeP1 = defaults.X3KeepaliveTimeP1
	}
	if config.X3KeepaliveTimeP2 == 0 {
		config.X3KeepaliveTimeP2 = defaults.X3KeepaliveTimeP2
	}
	if (config.X2KeepaliveEnabled && (config.X2KeepaliveTimeP1 < time.Second || config.X2KeepaliveTimeP2 < time.Second)) ||
		(config.X3KeepaliveEnabled && (config.X3KeepaliveTimeP1 < time.Second || config.X3KeepaliveTimeP2 < time.Second)) {
		return nil, ErrInvalidKeepaliveTimer
	}
	if config.InitialBackoff > config.MaxBackoff {
		return nil, fmt.Errorf("initial reconnect backoff %s exceeds maximum %s",
			config.InitialBackoff, config.MaxBackoff)
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
		dest:           dest,
		pool:           newConnPool(m.config.MaxPoolSize),
		interfacePools: map[PDUType]*connPool{PDUTypeX2: newConnPool(m.config.MaxPoolSize), PDUTypeX3: newConnPool(m.config.MaxPoolSize)},
		state:          connStateDisconnected,
		backoff:        m.config.InitialBackoff,
		connections:    make(map[*tls.Conn]struct{}),
		generation:     1,
		stats: DestinationStats{
			X2Keepalive: InterfaceKeepaliveStats{Enabled: m.config.X2KeepaliveEnabled, TimeP1: m.config.X2KeepaliveTimeP1, TimeP2: m.config.X2KeepaliveTimeP2},
			X3Keepalive: InterfaceKeepaliveStats{Enabled: m.config.X3KeepaliveEnabled, TimeP1: m.config.X3KeepaliveTimeP1, TimeP2: m.config.X3KeepaliveTimeP2},
		},
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
	if addressChanged {
		state.generation++
	}
	state.mu.Unlock()

	// Reconnect if address changed.
	if addressChanged {
		m.closeDestinationLocked(dest.DID, state)
		state.mu.Lock()
		state.pool = newConnPool(m.config.MaxPoolSize)
		state.interfacePools = map[PDUType]*connPool{PDUTypeX2: newConnPool(m.config.MaxPoolSize), PDUTypeX3: newConnPool(m.config.MaxPoolSize)}
		state.backoff = m.config.InitialBackoff
		state.mu.Unlock()

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
	return m.GetConnectionForInterface(ctx, did, PDUTypeX2)
}

// GetConnectionForInterface acquires a transport dedicated to X2 or X3. A
// keepalive acknowledgement is therefore associated by its TLS connection,
// even when the two interfaces use overlapping sequence numbers.
func (m *Manager) GetConnectionForInterface(ctx context.Context, did uuid.UUID, iface PDUType) (*tls.Conn, error) {
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

	state.mu.RLock()
	pool := state.interfacePools[iface]
	state.mu.RUnlock()
	if pool == nil {
		return nil, fmt.Errorf("unsupported delivery interface %d", iface)
	}

	// Try to get from pool.
	if pooled := pool.get(); pooled != nil {
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
	m.registerConnection(state, conn, iface)
	m.watchConnection(did, conn)

	return conn, nil
}

// ReleaseConnection returns a connection to the pool.
func (m *Manager) ReleaseConnection(did uuid.UUID, conn *tls.Conn) {
	m.releaseConnection(did, conn)
}

func (m *Manager) releaseConnection(did uuid.UUID, conn *tls.Conn) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists || m.shuttingDown.Load() {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing released connection", "error", err)
		}
		return
	}

	state.mu.RLock()
	_, healthy := state.connections[conn]
	if !healthy {
		state.mu.RUnlock()
		if err := conn.Close(); err != nil {
			logger.Debug("error closing invalid released connection", "error", err)
		}
		return
	}

	pooled := &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	value, runtimeOK := m.connectionRuntime.Load(conn)
	pool := state.pool
	if runtimeOK {
		runtime := value.(*connectionRuntime)
		pool = state.interfacePools[runtime.iface]
		if runtime.keepalive.enabled {
			if runtime.iface == PDUTypeX2 {
				state.stats.X2Keepalive.Disconnected++
			} else {
				state.stats.X3Keepalive.Disconnected++
			}
		}
	}
	put := pool.put(pooled)
	state.mu.RUnlock()
	if !put {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing excess connection", "error", err)
		}
	}
}

// InvalidateConnection closes a connection that encountered an error.
func (m *Manager) InvalidateConnection(did uuid.UUID, conn *tls.Conn) {
	m.invalidateConnection(did, conn, true)
}

func (m *Manager) invalidateConnection(did uuid.UUID, conn *tls.Conn, reconnectDestination bool) {
	m.mu.RLock()
	state, exists := m.destinations[did]
	m.mu.RUnlock()

	if !exists {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing invalidated connection", "error", err)
		}
		return
	}

	state.mu.Lock()
	if _, exists := state.connections[conn]; !exists {
		state.mu.Unlock()
		return
	}
	value, runtimeOK := m.connectionRuntime.Load(conn)
	delete(state.connections, conn)
	m.connectionRuntime.Delete(conn)
	state.stats.Disconnects++
	remaining := len(state.connections)
	pool := state.pool
	if runtimeOK {
		pool = state.interfacePools[value.(*connectionRuntime).iface]
	}
	state.mu.Unlock()
	pool.remove(conn)

	if err := conn.Close(); err != nil {
		logger.Debug("error closing invalidated connection", "error", err)
	}

	// Check if we need to reconnect.
	if remaining == 0 && atomic.CompareAndSwapInt32(&state.state, connStateConnected, connStateDisconnected) && reconnectDestination {
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
	stats := state.stats
	if !stats.X2Keepalive.LastValidACK.IsZero() {
		stats.X2Keepalive.ACKAge = time.Since(stats.X2Keepalive.LastValidACK)
	}
	if !stats.X3Keepalive.LastValidACK.IsZero() {
		stats.X3Keepalive.ACKAge = time.Since(stats.X3Keepalive.LastValidACK)
	}
	return stats, nil
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
	generation := state.generation
	state.stats.ConnectAttempts++
	state.lastConnectAttempt = time.Now()
	state.mu.Unlock()

	// Dial the destination.
	conn, err := m.dialDestination(state)
	state.mu.RLock()
	currentGeneration := state.generation
	state.mu.RUnlock()
	if currentGeneration != generation {
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil {
				logger.Debug("error closing superseded destination connection", "error", closeErr)
			}
		}
		return
	}
	if err != nil {
		atomic.StoreInt32(&state.state, connStateDisconnected)

		state.mu.Lock()
		state.stats.ConnectFailures++
		state.lastError = err
		state.failuresSinceLog++
		failures := state.failuresSinceLog
		shouldLog := state.lastFailureLog.IsZero() || time.Since(state.lastFailureLog) >= 30*time.Second
		if shouldLog {
			state.lastFailureLog = time.Now()
			state.failuresSinceLog = 0
		}
		backoff := state.backoff
		state.mu.Unlock()

		if shouldLog {
			logger.Warn("destination connection failed",
				"did", did, "error", err, "backoff", backoff,
				"failures_since_last_log", failures,
			)
		}

		m.scheduleReconnect(did, state)
		return
	}

	// Put the initial connection in the pool.
	iface := PDUTypeX2
	if !m.config.X2KeepaliveEnabled && m.config.X3KeepaliveEnabled {
		iface = PDUTypeX3
	}
	m.registerConnection(state, conn, iface)
	pooled := &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}
	state.mu.RLock()
	pool := state.interfacePools[iface]
	state.mu.RUnlock()
	pool.put(pooled)

	atomic.StoreInt32(&state.state, connStateConnected)

	state.mu.Lock()
	state.stats.ConnectSuccesses++
	state.successfulWrites = 0
	state.lastError = nil
	dest := state.dest
	state.mu.Unlock()

	m.watchConnection(did, conn)

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

	// Create dialer with an explicit keepalive policy so idle half-closed peers
	// are detected even when no LI traffic is being written.
	dialer := &net.Dialer{
		KeepAlive: m.config.KeepAliveInterval,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     m.config.KeepAliveIdle,
			Interval: m.config.KeepAliveInterval,
			Count:    m.config.KeepAliveCount,
		},
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

// registerConnection tracks a live connection before it becomes available.
func (m *Manager) registerConnection(state *destinationState, conn *tls.Conn, iface PDUType) {
	state.mu.Lock()
	if state.connections == nil {
		state.connections = make(map[*tls.Conn]struct{})
	}
	state.connections[conn] = struct{}{}
	state.mu.Unlock()
	keepalive := &interfaceKeepaliveState{outstanding: make(map[uint32]time.Time)}
	if iface == PDUTypeX2 {
		keepalive.enabled, keepalive.timeP1, keepalive.timeP2 = m.config.X2KeepaliveEnabled, m.config.X2KeepaliveTimeP1, m.config.X2KeepaliveTimeP2
	} else {
		keepalive.enabled, keepalive.timeP1, keepalive.timeP2 = m.config.X3KeepaliveEnabled, m.config.X3KeepaliveTimeP1, m.config.X3KeepaliveTimeP2
	}
	ackInbound := m.config.X2AcknowledgeInboundKeepalive
	if iface == PDUTypeX3 {
		ackInbound = m.config.X3AcknowledgeInboundKeepalive
	}
	runtime := &connectionRuntime{iface: iface, keepalive: keepalive, ackInbound: ackInbound}
	m.connectionRuntime.Store(conn, runtime)
	m.updateKeepaliveStatsForState(state, iface, keepalive, "")
}

// watchConnection runs the framed inbound reader and application keepalive
// timers. Reads are never discarded: only valid ACKs for an outstanding
// sequence refresh liveness.
func (m *Manager) watchConnection(did uuid.UUID, conn *tls.Conn) {
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		for {
			pdu, err := x2x3.ReadPDU(conn)
			if err == nil {
				m.handleInboundPDU(did, conn, pdu)
				continue
			}
			if !m.shuttingDown.Load() {
				logger.Info("destination connection closed by peer",
					"did", did,
					"error", err,
				)
			}
			m.InvalidateConnection(did, conn)
			return
		}
	}()
	go m.keepaliveLoop(did, conn)
}

func (m *Manager) handleInboundPDU(did uuid.UUID, conn *tls.Conn, pdu *x2x3.PDU) {
	value, ok := m.connectionRuntime.Load(conn)
	if !ok {
		return
	}
	runtime := value.(*connectionRuntime)
	if pdu.Header.Type != x2x3.PDUTypeKeepaliveAck && pdu.Header.Type != x2x3.PDUTypeKeepalive {
		m.recordUnexpectedInbound(did, runtime, false, fmt.Sprintf("unexpected control PDU type %s", pdu.Header.Type))
		return
	}
	seq, err := pdu.KeepaliveSequence()
	if err != nil {
		m.recordUnexpectedInbound(did, runtime, true, err.Error())
		return
	}

	runtime.mu.Lock()
	state := runtime.keepalive
	if pdu.Header.Type == x2x3.PDUTypeKeepaliveAck {
		if _, exists := state.outstanding[seq]; !exists {
			runtime.mu.Unlock()
			m.recordUnexpectedInbound(did, runtime, false, fmt.Sprintf("unexpected keepalive ACK sequence %d", seq))
			return
		}
		delete(state.outstanding, seq)
		state.lastACK = time.Now()
		m.incrementKeepaliveStat(did, runtime.iface, func(stats *InterfaceKeepaliveStats) { stats.Acknowledged++ })
		m.updateKeepaliveStats(did, runtime.iface, state, "")
		runtime.mu.Unlock()
		return
	}
	m.incrementKeepaliveStat(did, runtime.iface, func(stats *InterfaceKeepaliveStats) { stats.Inbound++ })
	ackInbound := runtime.ackInbound
	runtime.mu.Unlock()
	if !ackInbound {
		m.recordUnexpectedInbound(did, runtime, false, fmt.Sprintf("inbound keepalive sequence %d while acknowledgement is disabled", seq))
		return
	}
	frame, err := x2x3.NewKeepaliveAckPDU(seq).MarshalBinary()
	if err != nil {
		m.recordUnexpectedInbound(did, runtime, true, err.Error())
		return
	}
	if err := m.writeFrame(conn, frame, m.config.WriteTimeout); err != nil {
		m.InvalidateConnection(did, conn)
		return
	}
	m.incrementKeepaliveStat(did, runtime.iface, func(stats *InterfaceKeepaliveStats) { stats.InboundACKed++ })
}

// recordUnexpectedInbound keeps protocol anomalies observable without allowing
// a noisy peer to amplify logs. Counters are never rate limited.
func (m *Manager) recordUnexpectedInbound(did uuid.UUID, runtime *connectionRuntime, malformed bool, reason string) {
	m.incrementKeepaliveStat(did, runtime.iface, func(stats *InterfaceKeepaliveStats) {
		stats.Unexpected++
		if malformed {
			stats.Malformed++
		}
	})
	runtime.mu.Lock()
	now := time.Now()
	if runtime.lastUnexpectedLog.IsZero() || now.Sub(runtime.lastUnexpectedLog) >= 30*time.Second {
		suppressed := runtime.suppressedUnexpected
		runtime.lastUnexpectedLog, runtime.suppressedUnexpected = now, 0
		runtime.mu.Unlock()
		logger.Warn("unexpected MDF control PDU", "did", did, "interface", runtime.iface, "reason", reason, "suppressed", suppressed)
		return
	}
	runtime.suppressedUnexpected++
	runtime.mu.Unlock()
}

func (m *Manager) keepaliveLoop(did uuid.UUID, conn *tls.Conn) {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Second / 4)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopChan:
			return
		case now := <-ticker.C:
			value, ok := m.connectionRuntime.Load(conn)
			if !ok {
				return
			}
			runtime := value.(*connectionRuntime)
			var frames [][]byte
			var timeoutErr error
			runtime.mu.Lock()
			iface, state := runtime.iface, runtime.keepalive
			if !state.enabled {
				runtime.mu.Unlock()
				continue
			}
			for _, sent := range state.outstanding {
				if now.Sub(sent) >= state.timeP2 {
					timeoutErr = fmt.Errorf("interface %d keepalive acknowledgement timeout after %s", iface, state.timeP2)
					break
				}
			}
			if timeoutErr != nil {
				m.updateKeepaliveStats(did, iface, state, timeoutErr.Error())
			} else if len(state.outstanding) == 0 && (state.lastSent.IsZero() || now.Sub(state.lastSent) >= state.timeP1) {
				seq := state.next
				state.next++
				pdu := x2x3.NewKeepalivePDUWithSequence(seq)
				frame, err := pdu.MarshalBinary()
				if err == nil {
					frames = append(frames, frame)
					state.outstanding[seq] = now
					state.lastSequence = seq
					state.lastSent = now
					m.incrementKeepaliveStat(did, iface, func(stats *InterfaceKeepaliveStats) { stats.Sent++ })
					m.updateKeepaliveStats(did, iface, state, "")
				}
			}
			runtime.mu.Unlock()
			if timeoutErr != nil {
				if m.config.DeliveryFault != nil {
					m.config.DeliveryFault(did, timeoutErr)
				}
				m.invalidateConnection(did, conn, false)
				m.wg.Add(1)
				go m.reconnectInterface(did, iface)
				return
			}
			for _, frame := range frames {
				if err := m.writeFrame(conn, frame, m.config.WriteTimeout); err != nil {
					m.InvalidateConnection(did, conn)
					return
				}
			}
		}
	}
}

// reconnectInterface restores only the timed-out X2 or X3 transport using a
// capped, jittered backoff. The other interface remains untouched.
func (m *Manager) reconnectInterface(did uuid.UUID, iface PDUType) {
	defer m.wg.Done()
	backoff := m.config.InitialBackoff
	for {
		wait := backoff
		if m.config.BackoffJitter > 0 {
			factor := 1 - m.config.BackoffJitter + rand.Float64()*(2*m.config.BackoffJitter)
			wait = time.Duration(float64(backoff) * factor)
		}
		select {
		case <-m.stopChan:
			return
		case <-time.After(wait):
		}
		m.mu.RLock()
		state, exists := m.destinations[did]
		m.mu.RUnlock()
		if !exists || m.shuttingDown.Load() {
			return
		}
		conn, err := m.dialDestination(state)
		if err != nil {
			backoff = min(time.Duration(float64(backoff)*m.config.BackoffMultiplier), m.config.MaxBackoff)
			continue
		}
		m.registerConnection(state, conn, iface)
		m.incrementKeepaliveStat(did, iface, func(stats *InterfaceKeepaliveStats) { stats.Reconnected++ })
		m.watchConnection(did, conn)
		state.mu.RLock()
		pool := state.interfacePools[iface]
		state.mu.RUnlock()
		if !pool.put(&pooledConn{conn: conn, createdAt: time.Now(), lastUsed: time.Now()}) {
			m.InvalidateConnection(did, conn)
			return
		}
		atomic.StoreInt32(&state.state, connStateConnected)
		return
	}
}

func (m *Manager) updateKeepaliveStats(did uuid.UUID, iface PDUType, keepalive *interfaceKeepaliveState, reason string) {
	m.mu.RLock()
	state, ok := m.destinations[did]
	m.mu.RUnlock()
	if !ok {
		return
	}
	m.updateKeepaliveStatsForState(state, iface, keepalive, reason)
}

func (m *Manager) incrementKeepaliveStat(did uuid.UUID, iface PDUType, update func(*InterfaceKeepaliveStats)) {
	m.mu.RLock()
	state, ok := m.destinations[did]
	m.mu.RUnlock()
	if !ok {
		return
	}
	state.mu.Lock()
	if iface == PDUTypeX2 {
		update(&state.stats.X2Keepalive)
	} else {
		update(&state.stats.X3Keepalive)
	}
	state.mu.Unlock()
}

func (m *Manager) updateKeepaliveStatsForState(state *destinationState, iface PDUType, keepalive *interfaceKeepaliveState, reason string) {
	stats := InterfaceKeepaliveStats{Enabled: keepalive.enabled, TimeP1: keepalive.timeP1, TimeP2: keepalive.timeP2, LastSequence: keepalive.lastSequence, LastSent: keepalive.lastSent, LastValidACK: keepalive.lastACK, ReconnectReason: reason}
	if !keepalive.lastACK.IsZero() {
		stats.ACKAge = time.Since(keepalive.lastACK)
	}
	state.mu.Lock()
	if iface == PDUTypeX2 {
		previous := state.stats.X2Keepalive
		stats.Timeouts, stats.Sent, stats.Acknowledged, stats.Disconnected, stats.Reconnected, stats.Inbound, stats.InboundACKed, stats.Unexpected, stats.Malformed = previous.Timeouts, previous.Sent, previous.Acknowledged, previous.Disconnected, previous.Reconnected, previous.Inbound, previous.InboundACKed, previous.Unexpected, previous.Malformed
		if reason == "" {
			stats.ReconnectReason = state.stats.X2Keepalive.ReconnectReason
		}
		if reason != "" {
			stats.Timeouts++
		}
		state.stats.X2Keepalive = stats
	} else {
		previous := state.stats.X3Keepalive
		stats.Timeouts, stats.Sent, stats.Acknowledged, stats.Disconnected, stats.Reconnected, stats.Inbound, stats.InboundACKed, stats.Unexpected, stats.Malformed = previous.Timeouts, previous.Sent, previous.Acknowledged, previous.Disconnected, previous.Reconnected, previous.Inbound, previous.InboundACKed, previous.Unexpected, previous.Malformed
		if reason == "" {
			stats.ReconnectReason = state.stats.X3Keepalive.ReconnectReason
		}
		if reason != "" {
			stats.Timeouts++
		}
		state.stats.X3Keepalive = stats
	}
	state.mu.Unlock()
}

func (m *Manager) writeFrame(conn *tls.Conn, data []byte, timeout time.Duration) error {
	value, ok := m.connectionRuntime.Load(conn)
	if !ok {
		return ErrNotConnected
	}
	runtime := value.(*connectionRuntime)
	runtime.writeMu.Lock()
	defer runtime.writeMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	n, err := conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	clearErr := conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

// WritePDU serializes content with control frames on the TLS connection.
func (m *Manager) WritePDU(conn *tls.Conn, data []byte, timeout time.Duration) error {
	return m.writeFrame(conn, data, timeout)
}

// scheduleReconnect schedules a reconnection attempt with exponential backoff.
func (m *Manager) scheduleReconnect(did uuid.UUID, state *destinationState) {
	if m.shuttingDown.Load() {
		return
	}

	state.mu.Lock()
	backoff := state.backoff
	wait := backoff
	if m.config.BackoffJitter > 0 {
		factor := 1 - m.config.BackoffJitter + rand.Float64()*(2*m.config.BackoffJitter)
		wait = time.Duration(float64(backoff) * factor)
	}
	// Increase backoff for next attempt.
	state.backoff = time.Duration(float64(state.backoff) * m.config.BackoffMultiplier)
	if state.backoff > m.config.MaxBackoff {
		state.backoff = m.config.MaxBackoff
	}

	// Cancel any existing timer.
	if state.reconnectTimer != nil {
		state.reconnectTimer.Stop()
	}

	state.reconnectTimer = time.AfterFunc(wait, func() {
		if !m.shuttingDown.Load() {
			m.wg.Add(1)
			go m.connectDestination(did)
		}
	})
	state.mu.Unlock()

	logger.Debug("reconnect scheduled",
		"did", did,
		"backoff", wait,
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
	state.generation++
	connections := make([]*tls.Conn, 0, len(state.connections))
	for conn := range state.connections {
		connections = append(connections, conn)
		delete(state.connections, conn)
		m.connectionRuntime.Delete(conn)
	}
	pool := state.pool
	interfacePools := state.interfacePools
	state.mu.Unlock()

	pool.close()
	for _, interfacePool := range interfacePools {
		interfacePool.close()
	}
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			logger.Debug("error closing destination connection",
				"did", did,
				"error", err,
			)
		}
	}
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
		state.successfulWrites++
		threshold := m.config.SuccessfulWritesBeforeBackoffReset
		if threshold <= 0 {
			threshold = 1
		}
		if state.successfulWrites >= threshold {
			state.backoff = m.config.InitialBackoff
			state.successfulWrites = 0
		}
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
