//go:build processor || tap || all

// Package processor - TLS Keylog Writer
//
// This file contains the TLS keylog writer for the processor that:
//   - Receives TLS session keys forwarded from hunters
//   - Stores them in memory for TUI/display decryption
//   - Writes them to a keylog file in NSS format (Wireshark-compatible)
package processor

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
)

// TLSKeylogWriterConfig configures the TLS keylog writer.
type TLSKeylogWriterConfig struct {
	// OutputDir is the directory to write keylog files
	// If empty, no keylog files are written
	OutputDir string

	// FilePattern is the filename pattern for keylog files
	// Supports: {timestamp}, {date}
	// Default: "session_{timestamp}.keys"
	FilePattern string

	// MaxEntries is the maximum number of key entries to keep in memory
	// Default: 10000
	MaxEntries int

	// SessionTTL is how long to keep session keys in memory
	// Default: 1 hour
	SessionTTL time.Duration
}

// DefaultTLSKeylogWriterConfig returns sensible defaults.
func DefaultTLSKeylogWriterConfig() *TLSKeylogWriterConfig {
	return &TLSKeylogWriterConfig{
		FilePattern: "session_{timestamp}.keys",
		MaxEntries:  10000,
		SessionTTL:  time.Hour,
	}
}

// TLSKeylogWriter writes TLS session keys to files and stores them in memory.
type TLSKeylogWriter struct {
	config *TLSKeylogWriterConfig

	// In-memory key store for TUI/display decryption
	keyStore *keylog.Store

	// Current keylog file
	currentFile     *os.File
	currentWriter   *bufio.Writer
	currentFilePath string
	fileStartTime   time.Time

	// Track which client randoms have been written (avoid duplicates)
	writtenKeys map[string]bool

	// Statistics
	keysReceived uint64
	keysWritten  uint64

	mu sync.Mutex
}

// NewTLSKeylogWriter creates a new TLS keylog writer.
func NewTLSKeylogWriter(config *TLSKeylogWriterConfig) (*TLSKeylogWriter, error) {
	if config == nil {
		config = DefaultTLSKeylogWriterConfig()
	}

	// Create in-memory key store
	storeConfig := keylog.StoreConfig{
		MaxSessions: config.MaxEntries,
		SessionTTL:  config.SessionTTL,
	}
	store := keylog.NewStore(storeConfig)

	w := &TLSKeylogWriter{
		config:      config,
		keyStore:    store,
		writtenKeys: make(map[string]bool),
	}

	// Create output directory if specified
	if config.OutputDir != "" {
		if err := os.MkdirAll(config.OutputDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create keylog output directory: %w", err)
		}
		logger.Info("TLS keylog writer initialized",
			"output_dir", config.OutputDir,
			"pattern", config.FilePattern)
	} else {
		logger.Info("TLS keylog writer initialized (memory only, no file output)")
	}

	return w, nil
}

// ProcessPacketKeys extracts and stores TLS session keys from a captured packet.
// This should be called during packet processing for packets that contain TLS keys.
func (w *TLSKeylogWriter) ProcessPacketKeys(packet *data.CapturedPacket) {
	if packet.TlsKeys == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.keysReceived++

	keys := packet.TlsKeys
	if len(keys.ClientRandom) != 32 {
		logger.Warn("Invalid client random length in TLS keys", "length", len(keys.ClientRandom))
		return
	}

	clientRandomHex := hex.EncodeToString(keys.ClientRandom)

	// Check if we already have these keys
	if w.writtenKeys[clientRandomHex] {
		return
	}

	// Mark as received
	w.writtenKeys[clientRandomHex] = true

	// Convert to keylog entries and add to store
	var cr [32]byte
	copy(cr[:], keys.ClientRandom)

	// Add TLS 1.2 pre-master secret if present
	if len(keys.PreMasterSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelClientRandom,
			ClientRandom: cr,
			Secret:       keys.PreMasterSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "CLIENT_RANDOM", keys.PreMasterSecret)
	}

	// Add TLS 1.3 secrets
	if len(keys.ClientHandshakeTrafficSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelClientHandshakeTrafficSecret,
			ClientRandom: cr,
			Secret:       keys.ClientHandshakeTrafficSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", keys.ClientHandshakeTrafficSecret)
	}

	if len(keys.ServerHandshakeTrafficSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelServerHandshakeTrafficSecret,
			ClientRandom: cr,
			Secret:       keys.ServerHandshakeTrafficSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "SERVER_HANDSHAKE_TRAFFIC_SECRET", keys.ServerHandshakeTrafficSecret)
	}

	if len(keys.ClientTrafficSecret_0) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelClientTrafficSecret0,
			ClientRandom: cr,
			Secret:       keys.ClientTrafficSecret_0,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "CLIENT_TRAFFIC_SECRET_0", keys.ClientTrafficSecret_0)
	}

	if len(keys.ServerTrafficSecret_0) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelServerTrafficSecret0,
			ClientRandom: cr,
			Secret:       keys.ServerTrafficSecret_0,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "SERVER_TRAFFIC_SECRET_0", keys.ServerTrafficSecret_0)
	}

	if len(keys.ExporterSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelExporterSecret,
			ClientRandom: cr,
			Secret:       keys.ExporterSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "EXPORTER_SECRET", keys.ExporterSecret)
	}

	if len(keys.EarlyExporterSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelEarlyExporterSecret,
			ClientRandom: cr,
			Secret:       keys.EarlyExporterSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "EARLY_EXPORTER_SECRET", keys.EarlyExporterSecret)
	}

	if len(keys.ClientEarlyTrafficSecret) > 0 {
		entry := &keylog.KeyEntry{
			Label:        keylog.LabelClientEarlyTrafficSecret,
			ClientRandom: cr,
			Secret:       keys.ClientEarlyTrafficSecret,
		}
		w.keyStore.Add(entry)
		w.writeEntry(clientRandomHex, "CLIENT_EARLY_TRAFFIC_SECRET", keys.ClientEarlyTrafficSecret)
	}

	logger.Debug("TLS session keys processed",
		"client_random", clientRandomHex[:16]+"...",
		"tls_version", keys.TlsVersion,
		"has_pre_master", len(keys.PreMasterSecret) > 0,
		"has_tls13_secrets", len(keys.ClientTrafficSecret_0) > 0)
}

// writeEntry writes a single keylog entry to the file.
// Must be called with mu held.
func (w *TLSKeylogWriter) writeEntry(clientRandomHex, label string, secret []byte) {
	if w.config.OutputDir == "" {
		return
	}

	// Ensure we have an open file
	if err := w.ensureFileOpen(); err != nil {
		logger.Warn("Failed to open keylog file", "error", err)
		return
	}

	// Write entry in NSS format: LABEL client_random_hex secret_hex
	secretHex := hex.EncodeToString(secret)
	line := fmt.Sprintf("%s %s %s\n", label, clientRandomHex, secretHex)

	if _, err := w.currentWriter.WriteString(line); err != nil {
		logger.Warn("Failed to write keylog entry", "error", err)
		return
	}

	// Flush to ensure the entry is written
	if err := w.currentWriter.Flush(); err != nil {
		logger.Warn("Failed to flush keylog file", "error", err)
		return
	}

	w.keysWritten++
}

// ensureFileOpen ensures a keylog file is open.
// Must be called with mu held.
func (w *TLSKeylogWriter) ensureFileOpen() error {
	if w.currentFile != nil {
		return nil
	}

	// Generate filename
	filename := w.config.FilePattern
	now := time.Now()

	// Replace placeholders
	filename = replacePatternPlaceholders(filename, now, "")

	filePath := filepath.Join(w.config.OutputDir, filename)

	// Open file for appending
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("failed to open keylog file: %w", err)
	}

	w.currentFile = file
	w.currentWriter = bufio.NewWriter(file)
	w.currentFilePath = filePath
	w.fileStartTime = now

	logger.Info("Opened TLS keylog file", "path", filePath)

	return nil
}

// replacePatternPlaceholders replaces placeholders in the filename pattern.
func replacePatternPlaceholders(pattern string, t time.Time, extra string) string {
	result := pattern

	// {timestamp} -> Unix timestamp
	result = replaceAll(result, "{timestamp}", fmt.Sprintf("%d", t.Unix()))

	// {date} -> YYYY-MM-DD
	result = replaceAll(result, "{date}", t.Format("2006-01-02"))

	// {datetime} -> YYYY-MM-DD_HH-MM-SS
	result = replaceAll(result, "{datetime}", t.Format("2006-01-02_15-04-05"))

	return result
}

// GetKeyStore returns the in-memory key store for TUI/display decryption.
func (w *TLSKeylogWriter) GetKeyStore() *keylog.Store {
	return w.keyStore
}

// Stats returns statistics about keys processed.
func (w *TLSKeylogWriter) Stats() (received, written uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.keysReceived, w.keysWritten
}

// Close closes the keylog file and stops the key store.
func (w *TLSKeylogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Stop the key store cleanup goroutine
	if w.keyStore != nil {
		w.keyStore.Stop()
	}

	// Close the file
	if w.currentFile != nil {
		if w.currentWriter != nil {
			if err := w.currentWriter.Flush(); err != nil {
				logger.Warn("Failed to flush keylog file on close", "error", err)
			}
		}
		if err := w.currentFile.Close(); err != nil {
			logger.Warn("Failed to close keylog file", "error", err)
			return err
		}
		w.currentFile = nil
		w.currentWriter = nil

		logger.Info("Closed TLS keylog file",
			"path", w.currentFilePath,
			"keys_written", w.keysWritten)
	}

	return nil
}

// RotateFile closes the current file and opens a new one.
// This can be called to start a new keylog file (e.g., when rotating PCAP files).
func (w *TLSKeylogWriter) RotateFile() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Close current file
	if w.currentFile != nil {
		if w.currentWriter != nil {
			if err := w.currentWriter.Flush(); err != nil {
				logger.Warn("Failed to flush keylog file on rotate", "error", err)
			}
		}
		if err := w.currentFile.Close(); err != nil {
			logger.Warn("Failed to close keylog file on rotate", "error", err)
		}
		w.currentFile = nil
		w.currentWriter = nil
	}

	// Open new file on next write
	return nil
}

// CurrentFilePath returns the path to the current keylog file.
func (w *TLSKeylogWriter) CurrentFilePath() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentFilePath
}
