package grpcpool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/grpc"
)

// ConnectionPool manages a pool of gRPC connections with reference counting
// and automatic cleanup of idle connections.
//
// The pool provides connection reuse to eliminate TLS handshake overhead and
// reduce latency for repeated requests to the same target. Expected performance:
// - First connection: 50-100ms (TLS handshake)
// - Subsequent connections: 5-10ms (from pool)
//
// Thread-safe for concurrent access.
type ConnectionPool struct {
	mu sync.RWMutex

	// Connections indexed by target address
	connections map[string]*pooledConn

	// Configuration
	maxIdleTime     time.Duration // Max time connection can be idle before cleanup
	cleanupInterval time.Duration // How often to run cleanup

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// pooledConn represents a connection with reference counting and idle tracking
type pooledConn struct {
	conn *grpc.ClientConn
	mu   sync.RWMutex

	// Reference counting
	refCount int

	// Idle tracking
	lastUsed time.Time

	// Lifecycle
	closed bool
}

// PoolConfig contains configuration for the connection pool
type PoolConfig struct {
	// MaxIdleTime is the maximum time a connection can be idle before cleanup
	// Default: 5 minutes
	MaxIdleTime time.Duration

	// CleanupInterval is how often to run cleanup of idle connections
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultPoolConfig returns a PoolConfig with default values
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdleTime:     5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
	}
}

// NewConnectionPool creates a new gRPC connection pool
func NewConnectionPool(config PoolConfig) *ConnectionPool {
	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 5 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := &ConnectionPool{
		connections:     make(map[string]*pooledConn),
		maxIdleTime:     config.MaxIdleTime,
		cleanupInterval: config.CleanupInterval,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start cleanup goroutine
	pool.wg.Add(1)
	go pool.cleanupLoop()

	logger.Info("Created gRPC connection pool",
		"max_idle_time", config.MaxIdleTime,
		"cleanup_interval", config.CleanupInterval)

	return pool
}

// Get retrieves or creates a connection to the specified address.
// The caller MUST call Release() when done with the connection.
//
// The dialOptions are used when creating a new connection. If a connection
// already exists in the pool, dialOptions are ignored.
//
// Example:
//
//	conn, err := pool.Get(ctx, "localhost:55555", dialOptions...)
//	if err != nil {
//	    return err
//	}
//	defer pool.Release("localhost:55555")
//
//	// Use connection...
//	client := service.NewClient(conn)
func Get(pool *ConnectionPool, ctx context.Context, address string, dialOptions ...grpc.DialOption) (*grpc.ClientConn, error) {
	if pool == nil {
		return nil, fmt.Errorf("connection pool is nil")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Check if connection exists in pool
	if pc, exists := pool.connections[address]; exists {
		pc.mu.Lock()
		defer pc.mu.Unlock()

		if !pc.closed {
			// Connection available, increment refcount
			pc.refCount++
			pc.lastUsed = time.Now()

			logger.Debug("Reusing pooled connection",
				"address", address,
				"refcount", pc.refCount)

			return pc.conn, nil
		}

		// Connection is closed, remove from pool
		delete(pool.connections, address)
	}

	// Create new connection
	logger.Debug("Creating new connection",
		"address", address)

	conn, err := grpc.DialContext(ctx, address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	pc := &pooledConn{
		conn:     conn,
		refCount: 1,
		lastUsed: time.Now(),
		closed:   false,
	}

	pool.connections[address] = pc

	logger.Debug("Created new connection",
		"address", address,
		"pool_size", len(pool.connections))

	return conn, nil
}

// Release decrements the reference count for a connection.
// When refcount reaches 0, the connection becomes eligible for cleanup.
//
// The caller must call Release() exactly once for each successful Get().
func Release(pool *ConnectionPool, address string) {
	if pool == nil {
		return
	}
	pool.mu.RLock()
	pc, exists := pool.connections[address]
	pool.mu.RUnlock()

	if !exists {
		logger.Warn("Attempted to release unknown connection",
			"address", address)
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.refCount > 0 {
		pc.refCount--
		pc.lastUsed = time.Now()

		logger.Debug("Released connection",
			"address", address,
			"refcount", pc.refCount)
	} else {
		logger.Warn("Attempted to release connection with refcount 0",
			"address", address)
	}
}

// Close closes the connection pool and all managed connections.
// All connections are closed regardless of reference count.
func Close(pool *ConnectionPool) {
	if pool == nil {
		return
	}
	logger.Info("Closing connection pool",
		"pool_size", len(pool.connections))

	// Stop cleanup goroutine
	pool.cancel()
	pool.wg.Wait()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Close all connections
	for address, pc := range pool.connections {
		pc.mu.Lock()
		if !pc.closed {
			if err := pc.conn.Close(); err != nil {
				logger.Error("Failed to close connection during pool shutdown",
					"error", err,
					"address", address)
			}
			pc.closed = true
		}
		pc.mu.Unlock()
	}

	// Clear the map
	pool.connections = make(map[string]*pooledConn)

	logger.Info("Connection pool closed")
}

// cleanupLoop runs periodically to cleanup idle connections
func (pool *ConnectionPool) cleanupLoop() {
	defer pool.wg.Done()

	ticker := time.NewTicker(pool.cleanupInterval)
	defer ticker.Stop()

	logger.Debug("Starting connection pool cleanup loop",
		"interval", pool.cleanupInterval)

	for {
		select {
		case <-pool.ctx.Done():
			logger.Debug("Connection pool cleanup loop stopped")
			return
		case <-ticker.C:
			pool.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes idle connections that exceed maxIdleTime
func (pool *ConnectionPool) cleanupIdleConnections() {
	now := time.Now()
	var toClose []string

	// Find connections to close (with read lock)
	pool.mu.RLock()
	for address, pc := range pool.connections {
		pc.mu.RLock()
		idleTime := now.Sub(pc.lastUsed)
		shouldClose := !pc.closed && pc.refCount == 0 && idleTime > pool.maxIdleTime
		pc.mu.RUnlock()

		if shouldClose {
			toClose = append(toClose, address)
		}
	}
	pool.mu.RUnlock()

	if len(toClose) == 0 {
		return
	}

	// Close idle connections (with write lock)
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, address := range toClose {
		pc, exists := pool.connections[address]
		if !exists {
			continue
		}

		pc.mu.Lock()
		// Double-check conditions with lock held
		idleTime := now.Sub(pc.lastUsed)
		if !pc.closed && pc.refCount == 0 && idleTime > pool.maxIdleTime {
			logger.Info("Closing idle connection",
				"address", address,
				"idle_time", idleTime.Round(time.Second))

			if err := pc.conn.Close(); err != nil {
				logger.Error("Failed to close idle connection",
					"error", err,
					"address", address)
			}
			pc.closed = true
			delete(pool.connections, address)
		}
		pc.mu.Unlock()
	}

	logger.Debug("Cleanup complete",
		"closed", len(toClose),
		"pool_size", len(pool.connections))
}

// Stats returns statistics about the connection pool
type Stats struct {
	TotalConnections  int
	ActiveConnections int // refCount > 0
	IdleConnections   int // refCount == 0
}

// GetStats returns statistics about the connection pool
func GetStats(pool *ConnectionPool) Stats {
	if pool == nil {
		return Stats{}
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	stats := Stats{
		TotalConnections: len(pool.connections),
	}

	for _, pc := range pool.connections {
		pc.mu.RLock()
		if pc.refCount > 0 {
			stats.ActiveConnections++
		} else {
			stats.IdleConnections++
		}
		pc.mu.RUnlock()
	}

	return stats
}
