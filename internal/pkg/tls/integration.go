//go:build cli || hunter || tap || tui || all

// Package tls provides TLS protocol analysis and decryption capabilities.
package tls

import (
	"context"
	"fmt"
	"os"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls/decrypt"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
)

// DecryptConfig configures TLS decryption using SSLKEYLOGFILE.
type DecryptConfig struct {
	// KeylogFile is the path to the SSLKEYLOGFILE.
	// Either KeylogFile or KeylogPipe should be set, not both.
	KeylogFile string

	// KeylogPipe is the path to a named pipe for real-time key injection.
	// Either KeylogFile or KeylogPipe should be set, not both.
	KeylogPipe string

	// OnDecryptedData is called when application data is successfully decrypted.
	// The callback receives the session ID (client random hex), direction, and plaintext.
	OnDecryptedData func(sessionID string, dir decrypt.Direction, plaintext []byte)
}

// IsEnabled returns true if TLS decryption is configured.
func (c *DecryptConfig) IsEnabled() bool {
	return c.KeylogFile != "" || c.KeylogPipe != ""
}

// Validate checks if the configuration is valid.
func (c *DecryptConfig) Validate() error {
	if c.KeylogFile != "" && c.KeylogPipe != "" {
		return fmt.Errorf("cannot specify both --tls-keylog and --tls-keylog-pipe")
	}

	// Check if keylog file exists (unless it's a pipe)
	if c.KeylogFile != "" {
		info, err := os.Stat(c.KeylogFile)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist yet - that's fine, watcher will wait for it
				logger.Debug("TLS keylog file does not exist yet, will watch for creation",
					"path", c.KeylogFile)
			} else {
				return fmt.Errorf("failed to stat keylog file: %w", err)
			}
		} else if info.IsDir() {
			return fmt.Errorf("keylog path is a directory: %s", c.KeylogFile)
		}
	}

	// Check if keylog pipe exists and is a named pipe
	if c.KeylogPipe != "" {
		info, err := os.Stat(c.KeylogPipe)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("keylog pipe does not exist: %s (create with: mkfifo %s)", c.KeylogPipe, c.KeylogPipe)
			}
			return fmt.Errorf("failed to stat keylog pipe: %w", err)
		}
		if info.Mode()&os.ModeNamedPipe == 0 {
			return fmt.Errorf("keylog path is not a named pipe: %s (create with: mkfifo %s)", c.KeylogPipe, c.KeylogPipe)
		}
	}

	return nil
}

// Decryptor provides TLS traffic decryption using SSLKEYLOGFILE keys.
type Decryptor struct {
	config         DecryptConfig
	keyStore       *keylog.Store
	keyWatcher     *keylog.Watcher
	sessionManager *decrypt.SessionManager
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewDecryptor creates a new TLS decryptor.
// Returns nil if decryption is not enabled.
func NewDecryptor(config DecryptConfig) (*Decryptor, error) {
	if !config.IsEnabled() {
		return nil, nil
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create key store
	storeConfig := keylog.DefaultStoreConfig()
	keyStore := keylog.NewStore(storeConfig)

	// Create session manager
	sessionConfig := decrypt.DefaultSessionManagerConfig()
	sessionConfig.OnDecryptedData = config.OnDecryptedData
	sessionManager := decrypt.NewSessionManager(sessionConfig, keyStore)

	// Determine keylog path
	keylogPath := config.KeylogFile
	if keylogPath == "" {
		keylogPath = config.KeylogPipe
	}

	// Create watcher
	watcherConfig := keylog.DefaultWatcherConfig()
	keyWatcher := keylog.NewWatcher(keylogPath, keyStore, watcherConfig)

	ctx, cancel := context.WithCancel(context.Background())

	return &Decryptor{
		config:         config,
		keyStore:       keyStore,
		keyWatcher:     keyWatcher,
		sessionManager: sessionManager,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// Start begins watching the keylog file for new keys.
func (d *Decryptor) Start() error {
	if d == nil {
		return nil
	}

	if err := d.keyWatcher.Start(d.ctx); err != nil {
		return fmt.Errorf("failed to start keylog watcher: %w", err)
	}

	keylogPath := d.config.KeylogFile
	if keylogPath == "" {
		keylogPath = d.config.KeylogPipe
	}

	logger.Info("TLS decryption enabled",
		"keylog", keylogPath)

	return nil
}

// Stop stops the decryptor and releases resources.
func (d *Decryptor) Stop() {
	if d == nil {
		return
	}

	d.cancel()

	if d.keyWatcher != nil {
		if err := d.keyWatcher.Stop(); err != nil {
			logger.Error("Failed to stop keylog watcher", "error", err)
		}
	}

	if d.sessionManager != nil {
		d.sessionManager.Stop()
	}

	if d.keyStore != nil {
		d.keyStore.Stop()
	}
}

// SessionManager returns the session manager for processing TLS handshakes.
func (d *Decryptor) SessionManager() *decrypt.SessionManager {
	if d == nil {
		return nil
	}
	return d.sessionManager
}

// KeyStore returns the key store for direct access to session keys.
func (d *Decryptor) KeyStore() *keylog.Store {
	if d == nil {
		return nil
	}
	return d.keyStore
}

// Stats returns combined statistics from the decryptor components.
func (d *Decryptor) Stats() DecryptorStats {
	if d == nil {
		return DecryptorStats{}
	}

	var stats DecryptorStats
	if d.keyStore != nil {
		storeStats := d.keyStore.Stats()
		stats.TotalSessions = storeStats.TotalSessions
		stats.TLS12Sessions = storeStats.TLS12Sessions
		stats.TLS13Sessions = storeStats.TLS13Sessions
		stats.SessionsWithKeys = storeStats.CompleteSessions
	}

	if d.sessionManager != nil {
		sessionStats := d.sessionManager.Stats()
		stats.ActiveSessions = sessionStats.ActiveSessions
		stats.DecryptedRecords = sessionStats.DecryptedRecords
		stats.FailedDecryptions = sessionStats.FailedDecryptions
		stats.KeysMatched = sessionStats.KeysMatched
	}

	if d.keyWatcher != nil {
		watcherStats := d.keyWatcher.Stats()
		stats.KeylogLinesRead = watcherStats.LinesRead
		stats.KeylogEntriesAdded = watcherStats.EntriesAdded
		stats.KeylogErrors = watcherStats.Errors
	}

	return stats
}

// DecryptorStats contains combined decryptor statistics.
type DecryptorStats struct {
	// Key store stats
	TotalSessions    int
	TLS12Sessions    int
	TLS13Sessions    int
	SessionsWithKeys int

	// Session manager stats
	ActiveSessions    int
	DecryptedRecords  uint64
	FailedDecryptions uint64
	KeysMatched       uint64

	// Watcher stats
	KeylogLinesRead    uint64
	KeylogEntriesAdded uint64
	KeylogErrors       uint64
}

// GetDecryptConfigFromViper reads TLS decryption config from viper settings.
// The prefix is used to namespace the config keys (e.g., "http", "tap.http").
func GetDecryptConfigFromViper(prefix string) DecryptConfig {
	// Import viper here to avoid circular dependencies
	// This helper is called from command handlers that already have viper imported

	// The actual implementation reads from viper using:
	// - {prefix}.tls_keylog or tls.keylog
	// - {prefix}.tls_keylog_pipe or tls.keylog_pipe
	//
	// Since we can't import viper here (it's in cmd layer),
	// this is a documentation placeholder. Commands should use
	// the pattern shown in the sniff/tap/hunt implementations.

	return DecryptConfig{}
}
