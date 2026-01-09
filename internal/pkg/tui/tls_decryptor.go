//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/tls/decrypt"
	"github.com/endorses/lippycat/internal/pkg/tls/keylog"
	"github.com/spf13/viper"
)

// TLSDecryptor wraps the TLS decryption components for TUI use.
// It provides thread-safe access to the session manager for packet processing
// and decrypted data retrieval.
type TLSDecryptor struct {
	keyStore       *keylog.Store
	keyWatcher     *keylog.Watcher
	sessionManager *decrypt.SessionManager
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
}

// Global TLS decryptor for TUI (similar to offlineCallTracker)
var (
	globalTLSDecryptor *TLSDecryptor
	tlsDecryptorMu     sync.RWMutex
)

// NewTLSDecryptor creates a new TLS decryptor from a keylog file path.
func NewTLSDecryptor(keylogPath string) (*TLSDecryptor, error) {
	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	// Create key store
	storeConfig := keylog.DefaultStoreConfig()
	keyStore := keylog.NewStore(storeConfig)

	// Create session manager
	sessionConfig := decrypt.DefaultSessionManagerConfig()
	sessionManager := decrypt.NewSessionManager(sessionConfig, keyStore)

	decryptor := &TLSDecryptor{
		keyStore:       keyStore,
		sessionManager: sessionManager,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start key file watcher if path provided
	if keylogPath != "" {
		watcherConfig := keylog.DefaultWatcherConfig()
		watcher := keylog.NewWatcher(keylogPath, keyStore, watcherConfig)
		decryptor.keyWatcher = watcher
		if err := watcher.Start(ctx); err != nil {
			cancel()
			return nil, err
		}
	}

	return decryptor, nil
}

// Stop stops the TLS decryptor and cleans up resources.
func (d *TLSDecryptor) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Cancel context to stop watcher
	if d.cancel != nil {
		d.cancel()
	}
	if d.keyWatcher != nil {
		d.keyWatcher.Stop()
	}
	if d.sessionManager != nil {
		d.sessionManager.Stop()
	}
}

// ProcessTLSHandshake processes a TLS handshake packet (ClientHello or ServerHello).
// It extracts the necessary information and feeds it to the session manager.
func (d *TLSDecryptor) ProcessTLSHandshake(srcIP, dstIP, srcPort, dstPort string, rawData []byte, isClientHello bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sessionManager == nil {
		return
	}

	// Parse IPs
	srcNetIP := net.ParseIP(srcIP)
	dstNetIP := net.ParseIP(dstIP)
	if srcNetIP == nil || dstNetIP == nil {
		return
	}

	// Parse ports
	srcP, err := strconv.ParseUint(srcPort, 10, 16)
	if err != nil {
		return
	}
	dstP, err := strconv.ParseUint(dstPort, 10, 16)
	if err != nil {
		return
	}

	// Build flow key (client -> server direction for both ClientHello and ServerHello)
	var flowKey string
	if isClientHello {
		flowKey = decrypt.FlowKey(srcNetIP, dstNetIP, uint16(srcP), uint16(dstP))
	} else {
		// ServerHello comes from server to client, so reverse
		flowKey = decrypt.FlowKey(dstNetIP, srcNetIP, uint16(dstP), uint16(srcP))
	}

	// Parse TLS record from raw data
	// Skip Ethernet (14) + IP (20 or 40) + TCP (20+) headers to get to TLS
	// This is a simplified approach - in practice, the TLS data should be extracted
	// from the application layer payload
	tlsData := extractTLSPayload(rawData)
	if tlsData == nil || len(tlsData) < 5 {
		return
	}

	// Parse TLS record
	parser := decrypt.NewRecordParser()
	records, _ := parser.ParseRecords(tlsData)
	if len(records) == 0 {
		return
	}

	// Process the first handshake record
	record := records[0]
	if record.ContentType != decrypt.ContentTypeHandshake {
		return
	}

	if isClientHello {
		_ = d.sessionManager.ProcessClientHello(flowKey, srcNetIP, dstNetIP, uint16(srcP), uint16(dstP), record)
	} else {
		_ = d.sessionManager.ProcessServerHello(flowKey, record)
	}
}

// ProcessApplicationData processes a TLS application data record and attempts decryption.
func (d *TLSDecryptor) ProcessApplicationData(srcIP, dstIP, srcPort, dstPort string, rawData []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sessionManager == nil {
		return
	}

	// Parse IPs
	srcNetIP := net.ParseIP(srcIP)
	dstNetIP := net.ParseIP(dstIP)
	if srcNetIP == nil || dstNetIP == nil {
		return
	}

	// Parse ports
	srcP, err := strconv.ParseUint(srcPort, 10, 16)
	if err != nil {
		return
	}
	dstP, err := strconv.ParseUint(dstPort, 10, 16)
	if err != nil {
		return
	}

	// Build flow key - need to determine direction
	// Try both directions and see which one has a session
	flowKey1 := decrypt.FlowKey(srcNetIP, dstNetIP, uint16(srcP), uint16(dstP))
	flowKey2 := decrypt.FlowKey(dstNetIP, srcNetIP, uint16(dstP), uint16(srcP))

	var flowKey string
	var dir decrypt.Direction

	if session := d.sessionManager.GetSession(flowKey1); session != nil {
		flowKey = flowKey1
		dir = decrypt.DirectionClient
	} else if session := d.sessionManager.GetSession(flowKey2); session != nil {
		flowKey = flowKey2
		dir = decrypt.DirectionServer
	} else {
		return // No session found
	}

	// Extract TLS payload
	tlsData := extractTLSPayload(rawData)
	if tlsData == nil || len(tlsData) < 5 {
		return
	}

	// Parse TLS record
	parser := decrypt.NewRecordParser()
	records, _ := parser.ParseRecords(tlsData)
	if len(records) == 0 {
		return
	}

	// Decrypt application data records
	for _, record := range records {
		if record.ContentType == decrypt.ContentTypeApplicationData {
			_, _ = d.sessionManager.DecryptRecord(flowKey, dir, record)
		}
	}
}

// GetDecryptedData returns the decrypted data for a flow identified by packet addresses.
func (d *TLSDecryptor) GetDecryptedData(srcIP, dstIP, srcPort, dstPort string) (clientData, serverData []byte) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.sessionManager == nil {
		return nil, nil
	}

	// Parse IPs
	srcNetIP := net.ParseIP(srcIP)
	dstNetIP := net.ParseIP(dstIP)
	if srcNetIP == nil || dstNetIP == nil {
		return nil, nil
	}

	// Parse ports
	srcP, err := strconv.ParseUint(srcPort, 10, 16)
	if err != nil {
		return nil, nil
	}
	dstP, err := strconv.ParseUint(dstPort, 10, 16)
	if err != nil {
		return nil, nil
	}

	// Try both flow key directions
	flowKey1 := decrypt.FlowKey(srcNetIP, dstNetIP, uint16(srcP), uint16(dstP))
	flowKey2 := decrypt.FlowKey(dstNetIP, srcNetIP, uint16(dstP), uint16(srcP))

	// Check first direction
	clientData, serverData = d.sessionManager.GetDecryptedData(flowKey1)
	if len(clientData) > 0 || len(serverData) > 0 {
		return clientData, serverData
	}

	// Try reverse direction
	return d.sessionManager.GetDecryptedData(flowKey2)
}

// HasDecryptedData checks if decrypted data is available for a flow.
func (d *TLSDecryptor) HasDecryptedData(srcIP, dstIP, srcPort, dstPort string) bool {
	clientData, serverData := d.GetDecryptedData(srcIP, dstIP, srcPort, dstPort)
	return len(clientData) > 0 || len(serverData) > 0
}

// SetTLSDecryptor sets the global TLS decryptor for TUI use.
func SetTLSDecryptor(decryptor *TLSDecryptor) {
	tlsDecryptorMu.Lock()
	defer tlsDecryptorMu.Unlock()
	globalTLSDecryptor = decryptor
}

// GetTLSDecryptor returns the global TLS decryptor.
func GetTLSDecryptor() *TLSDecryptor {
	tlsDecryptorMu.RLock()
	defer tlsDecryptorMu.RUnlock()
	return globalTLSDecryptor
}

// ClearTLSDecryptor stops and clears the global TLS decryptor.
func ClearTLSDecryptor() {
	tlsDecryptorMu.Lock()
	defer tlsDecryptorMu.Unlock()
	if globalTLSDecryptor != nil {
		globalTLSDecryptor.Stop()
		globalTLSDecryptor = nil
	}
}

// InitTLSDecryptorFromConfig initializes the global TLS decryptor from viper config.
// Returns true if decryption is enabled and initialized successfully.
func InitTLSDecryptorFromConfig() bool {
	if !viper.GetBool("tui.tls_decryption_enabled") {
		return false
	}

	keylogPath := viper.GetString("tui.tls_keylog")
	if keylogPath == "" {
		return false
	}

	decryptor, err := NewTLSDecryptor(keylogPath)
	if err != nil {
		return false
	}

	SetTLSDecryptor(decryptor)
	return true
}

// extractTLSPayload attempts to extract the TLS payload from raw packet data.
// This is a simplified approach that looks for TLS record headers.
func extractTLSPayload(rawData []byte) []byte {
	if len(rawData) < 60 { // Minimum: Eth(14) + IP(20) + TCP(20) + TLS(5)
		return nil
	}

	// Skip Ethernet header (14 bytes)
	offset := 14

	// Check IP version and skip IP header
	if len(rawData) <= offset {
		return nil
	}

	ipVersion := (rawData[offset] >> 4) & 0x0F
	var ipHeaderLen int

	switch ipVersion {
	case 4:
		// IPv4: header length in lower 4 bits (words)
		ipHeaderLen = int(rawData[offset]&0x0F) * 4
	case 6:
		// IPv6: fixed 40 bytes
		ipHeaderLen = 40
	default:
		return nil
	}

	offset += ipHeaderLen
	if len(rawData) <= offset+20 { // Need at least TCP header
		return nil
	}

	// Skip TCP header (data offset is in upper 4 bits of byte 12)
	tcpDataOffset := int((rawData[offset+12]>>4)&0x0F) * 4
	offset += tcpDataOffset

	if len(rawData) <= offset+5 { // Need at least TLS record header
		return nil
	}

	// Verify this looks like TLS (content type 20-23, version 0x0301-0x0303)
	contentType := rawData[offset]
	if contentType < 20 || contentType > 23 {
		return nil
	}

	version := uint16(rawData[offset+1])<<8 | uint16(rawData[offset+2])
	if version < 0x0301 || version > 0x0304 {
		return nil
	}

	return rawData[offset:]
}
