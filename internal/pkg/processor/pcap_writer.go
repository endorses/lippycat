//go:build processor || tap || all

package processor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ErrCallPcapWriterClosed indicates use of a retained writer after finalization.
var ErrCallPcapWriterClosed = errors.New("per-call PCAP writer is closed")

const (
	// completedCallTombstoneTTL preserves the historical one-hour closed-call
	// retention window. After expiry a Call-ID may represent a new generation.
	completedCallTombstoneTTL = time.Hour
	// completedCallTombstoneLimit bounds terminal lifecycle memory. At pressure,
	// the oldest tombstones are discarded; collision-safe file creation still
	// protects finalized artifacts if such a Call-ID is subsequently reused.
	completedCallTombstoneLimit   = 100_000
	latePacketWarningInterval     = time.Minute
	writerCapacityWarningInterval = time.Minute
)

// FinalizedCallError is the expected, non-fatal result when a late packet
// attempts to recreate a writer for a call that has reached terminal state.
type FinalizedCallError struct {
	CallID      string
	FinalizedAt time.Time
}

// CallFinalizationReason identifies why a live per-call writer was finalized.
type CallFinalizationReason string

const (
	CallFinalizationProtocolComplete CallFinalizationReason = "protocol_complete"
	CallFinalizationIdleTimeout      CallFinalizationReason = "idle_timeout"
	CallFinalizationCapacityEviction CallFinalizationReason = "capacity_eviction"
	CallFinalizationManual           CallFinalizationReason = "manual"
	CallFinalizationShutdown         CallFinalizationReason = "shutdown"
)

// CallFinalizationResult describes the manager's terminal lifecycle decision.
// Finalized is false when another caller already finalized the same Call-ID.
type CallFinalizationResult struct {
	CallID      string
	Reason      CallFinalizationReason
	FinalizedAt time.Time
	Finalized   bool
	HadWriter   bool
}

// PcapWriterTelemetry is a snapshot of per-call output lifecycle state.
// Gauges are current values; counters are monotonic for the manager lifetime.
type PcapWriterTelemetry struct {
	ActiveWriters              uint64
	Tombstones                 uint64
	ProtocolFinalizations      uint64
	IdleFinalizations          uint64
	CapacityFinalizations      uint64
	ManualFinalizations        uint64
	SuppressedLatePackets      uint64
	TombstoneCapacityEvictions uint64
	FilenameCollisions         uint64
	CallbackFailures           uint64
}

func (e *FinalizedCallError) Error() string {
	return fmt.Sprintf("call %q was finalized at %s", e.CallID, e.FinalizedAt.Format(time.RFC3339Nano))
}

// IsCallFinalized reports whether err represents intentional late-packet suppression.
func IsCallFinalized(err error) bool {
	var finalizedErr *FinalizedCallError
	return errors.As(err, &finalizedErr)
}

// PcapWriterConfig configures per-call PCAP writing
type PcapWriterConfig struct {
	Enabled         bool          // Enable per-call PCAP writing
	OutputDir       string        // Directory for PCAP files
	FilePattern     string        // File naming pattern (supports {callid}, {from}, {to}, {timestamp})
	MaxFileSize     int64         // Max PCAP file size in bytes (0 = unlimited)
	MaxFilesPerCall int           // Max number of PCAP files per call (for rotation)
	MaxIdle         time.Duration // Max idle time before a call writer is reclaimed (0 = disabled)
	MaxWriters      int           // Soft active-writer pressure threshold (0 = disabled)
	BufferSize      int           // Write buffer size
	SyncInterval    time.Duration // How often to sync to disk

	// Callbacks for command hooks
	OnFileClose    func(filePath string)   // Called when any PCAP file is closed
	OnCallComplete func(meta CallMetadata) // Called when a VoIP call is complete
}

// DefaultPcapWriterConfig returns default configuration
func DefaultPcapWriterConfig() *PcapWriterConfig {
	return &PcapWriterConfig{
		Enabled:         false,
		OutputDir:       "./pcaps",
		FilePattern:     "{timestamp}_{callid}.pcap",
		MaxFileSize:     constants.DefaultPCAPMaxFileSize,
		MaxFilesPerCall: constants.DefaultMaxFilesPerCall,
		MaxIdle:         10 * time.Minute,
		MaxWriters:      0,
		BufferSize:      constants.DefaultPCAPBufferSize,
		SyncInterval:    constants.DefaultPCAPSyncInterval,
	}
}

// CallPcapWriter writes packets for a specific call to separate SIP and RTP PCAP files
type CallPcapWriter struct {
	manager    *PcapWriterManager
	generation uint64
	config     *PcapWriterConfig
	callID     string
	from       string
	to         string
	startTime  time.Time
	lastWrite  time.Time
	linkType   layers.LinkType // Link type for PCAP files (set from first packet)
	// SIP file
	sipFile        *os.File
	sipWriter      *pcapgo.Writer
	sipFilePath    string
	sipSize        int64
	sipFileIndex   int
	sipPacketCount int
	// RTP file
	rtpFile        *os.File
	rtpWriter      *pcapgo.Writer
	rtpFilePath    string
	rtpSize        int64
	rtpFileIndex   int
	rtpPacketCount int
	// Synchronization
	mu              sync.Mutex
	callbackMu      sync.Mutex
	callbackCond    *sync.Cond
	callbacksActive int
	syncTicker      *time.Ticker
	stopSync        chan struct{}
	syncErrors      int // Count of sync errors during periodic sync
	closed          bool
	complete        bool
}

// PcapWriterManager manages PCAP writers for multiple calls
type PcapWriterManager struct {
	config              *PcapWriterConfig
	writers             map[string]*CallPcapWriter
	lifecycle           *CallLifecycleRegistry
	shutdown            bool
	beforeFinalize      func(string, CallFinalizationReason)
	finalizationWaiters map[string][]chan pcapFinalizationOutcome
	mu                  sync.RWMutex
	finalizationWG      sync.WaitGroup

	suppressedLatePackets  atomic.Uint64
	lastLateWarning        atomic.Int64
	lastCapacityWarning    atomic.Int64
	protocolFinalizations  atomic.Uint64
	idleFinalizations      atomic.Uint64
	capacityFinalizations  atomic.Uint64
	manualFinalizations    atomic.Uint64
	filenameCollisions     atomic.Uint64
	callbackFailures       atomic.Uint64
	capacityPressureEvents atomic.Uint64
}

type pcapFinalizationOutcome struct {
	hadWriter bool
	err       error
}

// SetBeforeFinalize installs the lifecycle cleanup hook. It runs at most once
// for each terminal Call-ID, after manager locks are released and before files
// and completion callbacks are finalized.
func (pwm *PcapWriterManager) SetBeforeFinalize(hook func(string, CallFinalizationReason)) {
	if pwm == nil {
		return
	}
	pwm.mu.Lock()
	pwm.beforeFinalize = hook
	pwm.mu.Unlock()
}

// IsFinalized reports whether callID is protected by a live tombstone.
func (pwm *PcapWriterManager) IsFinalized(callID string) bool {
	if pwm == nil {
		return false
	}
	return pwm.lifecycle.IsFinalized(callID)
}

// NewPcapWriterManager creates a new PCAP writer manager
func NewPcapWriterManager(config *PcapWriterConfig) (*PcapWriterManager, error) {
	return NewPcapWriterManagerWithLifecycle(config, nil)
}

// NewPcapWriterManagerWithLifecycle creates a PCAP manager using lifecycle as
// the shared call-finalization authority. When lifecycle is nil, the manager
// creates and owns a private registry for backwards compatibility.
func NewPcapWriterManagerWithLifecycle(config *PcapWriterConfig, lifecycle *CallLifecycleRegistry) (*PcapWriterManager, error) {
	if config == nil {
		config = DefaultPcapWriterConfig()
	}

	// Create output directory if it doesn't exist
	if config.Enabled {
		if err := os.MkdirAll(config.OutputDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if lifecycle == nil {
		lifecycle = NewCallLifecycleRegistry(CallLifecycleConfig{
			TombstoneTTL: completedCallTombstoneTTL, TombstoneLimit: completedCallTombstoneLimit,
		})
	}
	manager := &PcapWriterManager{
		config:              config,
		writers:             make(map[string]*CallPcapWriter),
		lifecycle:           lifecycle,
		finalizationWaiters: make(map[string][]chan pcapFinalizationOutcome),
	}
	lifecycle.Subscribe(manager.handleLifecycleFinalization)
	return manager, nil
}

// Lifecycle returns the lifecycle registry used by this manager.
func (pwm *PcapWriterManager) Lifecycle() *CallLifecycleRegistry {
	if pwm == nil {
		return nil
	}
	return pwm.lifecycle
}

// Call lifecycle is registry-owned: absent -> live -> finalizing -> tombstoned.
// Each write holds a generation-specific admission through packet serialization
// and rotation callbacks. Registry finalization drains those admissions before
// this manager detaches and closes the corresponding writer. Expired or pruned
// tombstones admit a new generation whose files remain collision-safe. Manager
// shutdown flushes live writers without creating semantic call tombstones.

// GetOrCreateWriter gets or creates a writer for a call
func (pwm *PcapWriterManager) GetOrCreateWriter(callID, from, to string) (*CallPcapWriter, error) {
	if !pwm.config.Enabled {
		return nil, nil
	}
	admission, err := pwm.lifecycle.Admit(callID)
	if err != nil {
		if finalized := new(FinalizedCallError); errors.As(err, &finalized) {
			pwm.recordSuppressedLatePacket(callID, finalized.FinalizedAt)
		}
		return nil, err
	}
	defer admission.Release()
	return pwm.getOrCreateWriter(callID, from, to, admission.Generation())
}

func (pwm *PcapWriterManager) getOrCreateWriter(callID, from, to string, generation uint64) (*CallPcapWriter, error) {
	for {
		pwm.mu.Lock()
		if pwm.shutdown {
			pwm.mu.Unlock()
			return nil, fmt.Errorf("per-call PCAP writer manager is shut down")
		}
		if writer, exists := pwm.writers[callID]; exists && writer.generation == generation {
			pwm.mu.Unlock()
			return writer, nil
		}

		if pwm.config.MaxWriters > 0 && len(pwm.writers) >= pwm.config.MaxWriters {
			// A live call has no safe eviction point: finalizing it would discard
			// subsequent packets (and tombstoning would suppress them for the full
			// retention window). Treat MaxWriters as a pressure threshold and keep
			// capture lossless until an idle or completed call is reclaimed.
			pwm.recordWriterCapacityPressureLocked(callID)
		}

		writer, err := pwm.createWriter(callID, from, to, generation)
		if err == nil {
			pwm.writers[callID] = writer
		}
		pwm.mu.Unlock()
		return writer, err
	}
}

// WritePacket obtains a manager lifecycle lease for the complete lookup/create
// and write operation. Finalization takes the exclusive manager lock, so a
// writer cannot be detached or closed between lookup and packet serialization.
func (pwm *PcapWriterManager) WritePacket(callID, from, to string, timestamp time.Time, data []byte, linkType layers.LinkType, isRTP bool) error {
	return pwm.writePacketGeneration(callID, from, to, timestamp, data, linkType, isRTP, 0)
}

// writePacketGeneration rejects work submitted through a retained writer handle
// when its generation no longer owns callID. Direct manager writes pass zero and
// intentionally target the current generation.
func (pwm *PcapWriterManager) writePacketGeneration(callID, from, to string, timestamp time.Time, data []byte, linkType layers.LinkType, isRTP bool, requiredGeneration uint64) error {
	if pwm == nil || !pwm.config.Enabled {
		return nil
	}

	// Creation and capacity eviction require the write lock. Once the writer
	// exists, retain a read lease through the writer operation.
	admission, err := pwm.lifecycle.Admit(callID)
	if err != nil {
		if finalized := new(FinalizedCallError); errors.As(err, &finalized) {
			pwm.recordSuppressedLatePacket(callID, finalized.FinalizedAt)
		}
		return err
	}
	defer admission.Release()
	if requiredGeneration != 0 && admission.Generation() != requiredGeneration {
		return fmt.Errorf("%w: call %q generation %d is no longer current", ErrCallPcapWriterClosed, callID, requiredGeneration)
	}
	return pwm.writePacketWithAdmission(admission, callID, from, to, timestamp, data, linkType, isRTP)
}

// writePacketWithAdmission performs the irreversible PCAP acceptance step under
// a packet-scoped admission already held by the processor pipeline. This keeps
// LI and PCAP on the same side of a concurrent finalization boundary.
func (pwm *PcapWriterManager) writePacketWithAdmission(admission *CallAdmission, callID, from, to string, timestamp time.Time, data []byte, linkType layers.LinkType, isRTP bool) error {
	if pwm == nil || !pwm.config.Enabled || admission == nil {
		return nil
	}
	writer, err := pwm.getOrCreateWriter(callID, from, to, admission.Generation())
	if err != nil || writer == nil {
		return err
	}
	pwm.mu.RLock()
	current, live := pwm.writers[callID]
	if !live || current != writer || writer.generation != admission.Generation() {
		finalizedAt := time.Now()
		pwm.mu.RUnlock()
		pwm.recordSuppressedLatePacket(callID, finalizedAt)
		return &FinalizedCallError{CallID: callID, FinalizedAt: finalizedAt}
	}
	var closedPath string
	var writeErr error
	if isRTP {
		closedPath, writeErr = writer.writeRTPPacket(timestamp, data, linkType)
	} else {
		closedPath, writeErr = writer.writeSIPPacket(timestamp, data, linkType)
	}
	// Claim callback order while the manager lease still prevents finalization.
	// The callback itself runs after the manager lock is released.
	writer.reserveCallback()
	pwm.mu.RUnlock()
	writer.notifyFileClosed(closedPath)
	writer.completeCallback()
	if writeErr != nil {
		return fmt.Errorf("write per-call PCAP packet for call %q: %w", callID, writeErr)
	}
	return nil
}

// SuppressedLatePackets returns the process-lifetime count of packets rejected
// because their Call-ID remained tombstoned. The counter is monotonic.
func (pwm *PcapWriterManager) SuppressedLatePackets() uint64 {
	if pwm == nil {
		return 0
	}
	return pwm.suppressedLatePackets.Load()
}

// Telemetry returns current gauges and process-lifetime counters.
func (pwm *PcapWriterManager) Telemetry() PcapWriterTelemetry {
	if pwm == nil {
		return PcapWriterTelemetry{}
	}
	pwm.mu.RLock()
	activeWriters := len(pwm.writers)
	pwm.mu.RUnlock()
	lifecycleTelemetry := pwm.lifecycle.Telemetry()
	return PcapWriterTelemetry{
		ActiveWriters:              uint64(activeWriters), // #nosec G115 -- map sizes cannot be negative
		Tombstones:                 lifecycleTelemetry.Tombstones,
		ProtocolFinalizations:      pwm.protocolFinalizations.Load(),
		IdleFinalizations:          pwm.idleFinalizations.Load(),
		CapacityFinalizations:      pwm.capacityFinalizations.Load(),
		ManualFinalizations:        pwm.manualFinalizations.Load(),
		SuppressedLatePackets:      pwm.suppressedLatePackets.Load(),
		TombstoneCapacityEvictions: lifecycleTelemetry.TombstoneCapacityEvictions,
		FilenameCollisions:         pwm.filenameCollisions.Load(),
		CallbackFailures:           pwm.callbackFailures.Load(),
	}
}

func (pwm *PcapWriterManager) recordSuppressedLatePacket(callID string, finalizedAt time.Time) {
	total := pwm.suppressedLatePackets.Add(1)
	now := time.Now().UnixNano()
	last := pwm.lastLateWarning.Load()
	if now-last < latePacketWarningInterval.Nanoseconds() ||
		!pwm.lastLateWarning.CompareAndSwap(last, now) {
		return
	}
	logger.Warn("Suppressing late packet for finalized call",
		"call_id", callID, "finalized_at", finalizedAt, "suppressed_total", total)
}

func (pwm *PcapWriterManager) recordWriterCapacityPressureLocked(callID string) {
	total := pwm.capacityPressureEvents.Add(1)
	now := time.Now().UnixNano()
	last := pwm.lastCapacityWarning.Load()
	if now-last < writerCapacityWarningInterval.Nanoseconds() ||
		!pwm.lastCapacityWarning.CompareAndSwap(last, now) {
		return
	}
	logger.Warn("Per-call PCAP writer pressure threshold exceeded; preserving active calls",
		"call_id", callID, "active_writers", len(pwm.writers),
		"max_writers", pwm.config.MaxWriters, "pressure_events", total)
}

// createWriter creates a new PCAP writer for a call with separate SIP and RTP files
func (pwm *PcapWriterManager) createWriter(callID, from, to string, generation uint64) (*CallPcapWriter, error) {
	now := time.Now()
	writer := &CallPcapWriter{
		manager:    pwm,
		generation: generation,
		config:     pwm.config,
		callID:     callID,
		from:       from,
		to:         to,
		startTime:  now,
		lastWrite:  now,
		stopSync:   make(chan struct{}),
	}
	writer.callbackCond = sync.NewCond(&writer.callbackMu)

	// Create initial SIP and RTP PCAP files
	if err := writer.createInitialFiles(); err != nil {
		return nil, err
	}

	// Start sync ticker
	writer.syncTicker = time.NewTicker(pwm.config.SyncInterval)
	go writer.syncLoop()

	logger.Info("Created PCAP writers for call", "call_id", callID, "from", from, "to", to)

	return writer, nil
}

// createInitialFiles is a no-op; files are created lazily on first packet
// to ensure we have the correct link type from the actual captured packets.
// This prevents the bug where PCAP files were hardcoded to LinkTypeEthernet
// regardless of the actual capture interface type (e.g., Linux cooked, raw IP).
func (writer *CallPcapWriter) createInitialFiles() error {
	// Files are created in WriteSIPPacket/WriteRTPPacket on first packet
	return nil
}

// WriteSIPPacket writes a SIP packet to the SIP PCAP file
func (writer *CallPcapWriter) WriteSIPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) error {
	if writer == nil {
		return nil
	}
	if writer.manager != nil {
		return writer.manager.writePacketGeneration(writer.callID, writer.from, writer.to, timestamp, data, linkType, false, writer.generation)
	}
	writer.reserveCallback()
	defer writer.completeCallback()
	closedPath, err := writer.writeSIPPacket(timestamp, data, linkType)
	writer.notifyFileClosed(closedPath)
	return err
}

func (writer *CallPcapWriter) writeSIPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) (string, error) {
	if writer == nil {
		return "", nil
	}

	writer.mu.Lock()
	if writer.closed {
		writer.mu.Unlock()
		return "", fmt.Errorf("%w: call %q", ErrCallPcapWriterClosed, writer.callID)
	}
	var closedPath string
	defer writer.mu.Unlock()

	// Store link type from first packet (used for all files in this call)
	if writer.linkType == 0 {
		writer.linkType = linkType
		logger.Debug("Set PCAP link type for call", "call_id", writer.callID, "link_type", linkType)
	}

	// Create SIP file on first SIP packet (deferred from createInitialFiles)
	if writer.sipWriter == nil {
		var err error
		closedPath, err = writer.rotateSIPFile()
		if err != nil {
			return closedPath, fmt.Errorf("failed to create SIP PCAP file: %w", err)
		}
	}

	// Check if we need to rotate SIP file
	if writer.config.MaxFileSize > 0 && writer.sipSize >= writer.config.MaxFileSize {
		var err error
		closedPath, err = writer.rotateSIPFile()
		if err != nil {
			return closedPath, fmt.Errorf("failed to rotate SIP PCAP file: %w", err)
		}
	}

	// Create CaptureInfo for raw packet
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Write packet to SIP file
	if err := writer.sipWriter.WritePacket(ci, data); err != nil {
		return closedPath, fmt.Errorf("failed to write SIP packet: %w", err)
	}

	writer.sipSize += int64(len(data))
	writer.sipPacketCount++
	writer.lastWrite = time.Now()

	return closedPath, nil
}

// WriteRTPPacket writes an RTP packet to the RTP PCAP file
func (writer *CallPcapWriter) WriteRTPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) error {
	if writer == nil {
		return nil
	}
	if writer.manager != nil {
		return writer.manager.writePacketGeneration(writer.callID, writer.from, writer.to, timestamp, data, linkType, true, writer.generation)
	}
	writer.reserveCallback()
	defer writer.completeCallback()
	closedPath, err := writer.writeRTPPacket(timestamp, data, linkType)
	writer.notifyFileClosed(closedPath)
	return err
}

func (writer *CallPcapWriter) writeRTPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) (string, error) {
	if writer == nil {
		return "", nil
	}

	writer.mu.Lock()
	if writer.closed {
		writer.mu.Unlock()
		return "", fmt.Errorf("%w: call %q", ErrCallPcapWriterClosed, writer.callID)
	}
	var closedPath string
	defer writer.mu.Unlock()

	// Store link type from first packet (used for all files in this call)
	if writer.linkType == 0 {
		writer.linkType = linkType
		logger.Debug("Set PCAP link type for call", "call_id", writer.callID, "link_type", linkType)
	}

	// Create RTP file on first RTP packet (deferred from createInitialFiles)
	if writer.rtpWriter == nil {
		var err error
		closedPath, err = writer.rotateRTPFile()
		if err != nil {
			return closedPath, fmt.Errorf("failed to create RTP PCAP file: %w", err)
		}
	}

	// Check if we need to rotate RTP file
	if writer.config.MaxFileSize > 0 && writer.rtpSize >= writer.config.MaxFileSize {
		var err error
		closedPath, err = writer.rotateRTPFile()
		if err != nil {
			return closedPath, fmt.Errorf("failed to rotate RTP PCAP file: %w", err)
		}
	}

	// Create CaptureInfo for raw packet
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Write packet to RTP file
	if err := writer.rtpWriter.WritePacket(ci, data); err != nil {
		return closedPath, fmt.Errorf("failed to write RTP packet: %w", err)
	}

	writer.rtpSize += int64(len(data))
	writer.rtpPacketCount++
	writer.lastWrite = time.Now()

	return closedPath, nil
}

// SweepIdle closes writers that have not received SIP or RTP packets within maxIdle.
func (pwm *PcapWriterManager) SweepIdle(maxIdle time.Duration) int {
	if pwm == nil || maxIdle <= 0 {
		return 0
	}

	pwm.mu.RLock()
	toClose := make([]string, 0, len(pwm.writers))
	for callID := range pwm.writers {
		toClose = append(toClose, callID)
	}
	pwm.mu.RUnlock()

	closed := 0
	for _, callID := range toClose {
		result, err := pwm.finalizeCallIfIdle(callID, maxIdle)
		if err != nil {
			logger.Warn("Failed to close idle per-call PCAP writer",
				"call_id", callID,
				"error", err)
			continue
		}
		if result.Finalized {
			logger.Warn("Closed idle per-call PCAP writer",
				"call_id", callID,
				"max_idle", maxIdle)
			closed++
		}
	}

	return closed
}

func (pwm *PcapWriterManager) finalizeCallIfIdle(callID string, maxIdle time.Duration) (CallFinalizationResult, error) {
	result := CallFinalizationResult{CallID: callID, Reason: CallFinalizationIdleTimeout}
	pwm.mu.Lock()
	if pwm.shutdown {
		pwm.mu.Unlock()
		return result, nil
	}
	writer, exists := pwm.writers[callID]
	if !exists {
		pwm.mu.Unlock()
		return result, nil
	}
	writer.mu.Lock()
	idle := time.Since(writer.lastWrite) >= maxIdle
	writer.mu.Unlock()
	if !idle {
		pwm.mu.Unlock()
		return result, nil
	}
	generation := writer.generation
	pwm.mu.Unlock()
	return pwm.finalizeCallGeneration(callID, generation, CallFinalizationIdleTimeout)
}

// openCallPcapFile creates a new standalone PCAP without replacing or appending
// to an existing artifact. Manager-owned live state, never filesystem mtime,
// is the authority for continuation. A collision receives a generation suffix
// so Call-ID reuse after tombstone expiry cannot mutate finalized output.
func (writer *CallPcapWriter) openCallPcapFile(filePath string) (*os.File, *pcapgo.Writer, string, error) {
	linkType := writer.linkType
	if linkType == 0 {
		linkType = layers.LinkTypeEthernet
	}

	actualPath := filePath
	var file *os.File
	for attempt := 0; ; attempt++ {
		// #nosec G304 -- Path is safe: config OutputDir + generateFilename() with sanitization
		created, err := os.OpenFile(actualPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			file = created
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, nil, "", err
		}
		if writer.manager != nil {
			writer.manager.filenameCollisions.Add(1)
		}
		actualPath = generationFilePath(filePath, time.Now().UnixNano(), attempt)
	}

	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(constants.DefaultPCAPSnapLen, linkType); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file during error cleanup", "error", closeErr, "file", actualPath)
		}
		return nil, nil, "", err
	}

	return file, pcapWriter, actualPath, nil
}

func generationFilePath(filePath string, generation int64, attempt int) string {
	ext := filepath.Ext(filePath)
	base := strings.TrimSuffix(filePath, ext)
	if attempt == 0 {
		return fmt.Sprintf("%s_gen_%d%s", base, generation, ext)
	}
	return fmt.Sprintf("%s_gen_%d_%d%s", base, generation, attempt, ext)
}

// rotateSIPFile creates a new SIP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateSIPFile() (string, error) {
	var closedPath string
	// Close existing file and fire callback
	if writer.sipFile != nil {
		closedPath = writer.sipFilePath
		if err := writer.sipFile.Close(); err != nil {
			logger.Error("Failed to close SIP file during rotation", "error", err, "call_id", writer.callID)
		}
		// Fire callback after successful close
		writer.sipFile = nil
		writer.sipWriter = nil
		writer.sipFilePath = ""
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.sipFileIndex >= writer.config.MaxFilesPerCall {
		return closedPath, fmt.Errorf("max SIP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("sip", writer.sipFileIndex)
	filePath := filepath.Join(writer.config.OutputDir, filename)

	file, pcapWriter, actualPath, err := writer.openCallPcapFile(filePath)
	if err != nil {
		return closedPath, fmt.Errorf("failed to create SIP PCAP file: %w", err)
	}

	writer.sipFile = file
	writer.sipWriter = pcapWriter
	writer.sipFilePath = actualPath
	writer.sipSize = 0
	writer.sipFileIndex++

	logger.Info("Opened SIP PCAP file for call", "call_id", writer.callID, "file", actualPath)

	return closedPath, nil
}

// rotateRTPFile creates a new RTP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateRTPFile() (string, error) {
	var closedPath string
	// Close existing file and fire callback
	if writer.rtpFile != nil {
		closedPath = writer.rtpFilePath
		if err := writer.rtpFile.Close(); err != nil {
			logger.Error("Failed to close RTP file during rotation", "error", err, "call_id", writer.callID)
		}
		// Fire callback after successful close
		writer.rtpFile = nil
		writer.rtpWriter = nil
		writer.rtpFilePath = ""
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.rtpFileIndex >= writer.config.MaxFilesPerCall {
		return closedPath, fmt.Errorf("max RTP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("rtp", writer.rtpFileIndex)
	filePath := filepath.Join(writer.config.OutputDir, filename)

	file, pcapWriter, actualPath, err := writer.openCallPcapFile(filePath)
	if err != nil {
		return closedPath, fmt.Errorf("failed to create RTP PCAP file: %w", err)
	}

	writer.rtpFile = file
	writer.rtpWriter = pcapWriter
	writer.rtpFilePath = actualPath
	writer.rtpSize = 0
	writer.rtpFileIndex++

	logger.Info("Opened RTP PCAP file for call", "call_id", writer.callID, "file", actualPath)

	return closedPath, nil
}

// generateFilename generates a filename for the PCAP file (SIP or RTP)
func (writer *CallPcapWriter) generateFilename(packetType string, fileIndex int) string {
	pattern := writer.config.FilePattern

	// Replace placeholders
	pattern = strings.ReplaceAll(pattern, "{callid}", sanitizeFilename(writer.callID))
	pattern = strings.ReplaceAll(pattern, "{from}", sanitizeFilename(writer.from))
	pattern = strings.ReplaceAll(pattern, "{to}", sanitizeFilename(writer.to))
	pattern = strings.ReplaceAll(pattern, "{timestamp}", writer.startTime.Format("20060102_150405"))

	// Add packet type (sip or rtp) before extension
	ext := filepath.Ext(pattern)
	base := pattern[:len(pattern)-len(ext)]
	pattern = fmt.Sprintf("%s_%s%s", base, packetType, ext)

	// Add index suffix if rotating
	if fileIndex > 0 {
		ext = filepath.Ext(pattern)
		base = pattern[:len(pattern)-len(ext)]
		pattern = fmt.Sprintf("%s_%d%s", base, fileIndex, ext)
	}

	return pattern
}

// syncLoop periodically syncs files to disk
func (writer *CallPcapWriter) syncLoop() {
	for {
		select {
		case <-writer.syncTicker.C:
			writer.mu.Lock()
			if writer.sipFile != nil {
				if err := writer.sipFile.Sync(); err != nil {
					writer.syncErrors++
					logger.Warn("Failed to sync SIP PCAP", "error", err, "call_id", writer.callID)
				}
			}
			if writer.rtpFile != nil {
				if err := writer.rtpFile.Sync(); err != nil {
					writer.syncErrors++
					logger.Warn("Failed to sync RTP PCAP", "error", err, "call_id", writer.callID)
				}
			}
			writer.mu.Unlock()
		case <-writer.stopSync:
			return
		}
	}
}

func (writer *CallPcapWriter) notifyFileClosed(path string) {
	if path != "" && writer.config.OnFileClose != nil {
		if invokeCallback("per-call PCAP file-close", func() {
			writer.config.OnFileClose(path)
		}, "call_id", writer.callID, "file", path) && writer.manager != nil {
			writer.manager.callbackFailures.Add(1)
		}
	}
}

func invokeCallback(name string, callback func(), context ...any) (failed bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failed = true
			fields := append([]any{"callback", name, "panic", recovered}, context...)
			logger.Error("Recovered panic from external callback", fields...)
		}
	}()
	callback()
	return false
}

func (writer *CallPcapWriter) reserveCallback() {
	writer.callbackMu.Lock()
	writer.callbacksActive++
	writer.callbackMu.Unlock()
}

func (writer *CallPcapWriter) completeCallback() {
	writer.callbackMu.Lock()
	writer.callbacksActive--
	writer.callbackCond.Broadcast()
	writer.callbackMu.Unlock()
}

func (writer *CallPcapWriter) waitForCallbacks() {
	writer.callbackMu.Lock()
	for writer.callbacksActive > 0 {
		writer.callbackCond.Wait()
	}
	writer.callbackMu.Unlock()
}

// Close closes the writer and flushes data for both SIP and RTP files
func (writer *CallPcapWriter) Close() error {
	if writer == nil {
		return nil
	}
	if writer.manager != nil {
		_, err := writer.manager.finalizeCallGeneration(writer.callID, writer.generation, CallFinalizationManual)
		return err
	}
	return writer.finalize(CallFinalizationManual)
}

func (writer *CallPcapWriter) finalize(reason CallFinalizationReason) error {
	return writer.finalizeWithBeforeCallbacks(reason, nil)
}

// finalizeWithBeforeCallbacks closes and clears all file resources before
// running beforeCallbacks and the externally supplied completion callbacks.
// The manager uses this boundary to mark resource finalization complete before
// a callback can re-enter manager shutdown and wait for finalization work.
func (writer *CallPcapWriter) finalizeWithBeforeCallbacks(reason CallFinalizationReason, beforeCallbacks func()) error {
	if writer == nil {
		if beforeCallbacks != nil {
			beforeCallbacks()
		}
		return nil
	}

	// A rotation callback may synchronously initiate manager shutdown. Waiting
	// for callbacks in that path would wait for the callback currently calling
	// Close and deadlock. Shutdown has no completion callback to order after a
	// rotation callback, so it may safely close the remaining live files while
	// that already-closed-file notification is still active.
	if reason != CallFinalizationShutdown {
		writer.waitForCallbacks()
	}

	writer.mu.Lock()
	if writer.closed {
		writer.mu.Unlock()
		if beforeCallbacks != nil {
			beforeCallbacks()
		}
		return nil
	}
	writer.closed = true
	var finalizationErrors []error

	// Stop sync loop
	close(writer.stopSync)
	writer.syncTicker.Stop()

	// Close SIP file
	var sipClosedPath string
	if writer.sipFile != nil {
		sipClosedPath = writer.sipFilePath
		if err := writer.sipFile.Sync(); err != nil {
			wrapped := fmt.Errorf("sync SIP PCAP for call %q file %q: %w", writer.callID, sipClosedPath, err)
			finalizationErrors = append(finalizationErrors, wrapped)
			logger.Warn("Failed to sync SIP PCAP file", "error", wrapped, "call_id", writer.callID, "file", sipClosedPath)
		}
		if err := writer.sipFile.Close(); err != nil {
			wrapped := fmt.Errorf("close SIP PCAP for call %q file %q: %w", writer.callID, sipClosedPath, err)
			finalizationErrors = append(finalizationErrors, wrapped)
			logger.Warn("Failed to close SIP PCAP file", "error", wrapped, "call_id", writer.callID, "file", sipClosedPath)
		}
		writer.sipFile = nil
		writer.sipWriter = nil
		writer.sipFilePath = ""
	}

	// Close RTP file
	var rtpClosedPath string
	if writer.rtpFile != nil {
		rtpClosedPath = writer.rtpFilePath
		if err := writer.rtpFile.Sync(); err != nil {
			wrapped := fmt.Errorf("sync RTP PCAP for call %q file %q: %w", writer.callID, rtpClosedPath, err)
			finalizationErrors = append(finalizationErrors, wrapped)
			logger.Warn("Failed to sync RTP PCAP file", "error", wrapped, "call_id", writer.callID, "file", rtpClosedPath)
		}
		if err := writer.rtpFile.Close(); err != nil {
			wrapped := fmt.Errorf("close RTP PCAP for call %q file %q: %w", writer.callID, rtpClosedPath, err)
			finalizationErrors = append(finalizationErrors, wrapped)
			logger.Warn("Failed to close RTP PCAP file", "error", wrapped, "call_id", writer.callID, "file", rtpClosedPath)
		}
		writer.rtpFile = nil
		writer.rtpWriter = nil
		writer.rtpFilePath = ""
	}

	logger.Info("Closed PCAP writers for call",
		"call_id", writer.callID,
		"sip_packets", writer.sipPacketCount,
		"rtp_packets", writer.rtpPacketCount,
		"sip_files", writer.sipFileIndex,
		"rtp_files", writer.rtpFileIndex,
		"sync_errors", writer.syncErrors)

	complete := reason == CallFinalizationProtocolComplete || reason == CallFinalizationIdleTimeout
	callComplete := complete && !writer.complete
	writer.complete = writer.complete || complete
	meta := CallMetadata{CallID: writer.callID, DirName: writer.config.OutputDir, Caller: writer.from, Called: writer.to, CallDate: writer.startTime}
	writer.mu.Unlock()
	if beforeCallbacks != nil {
		beforeCallbacks()
	}

	// Deterministic callback ordering: all file-close hooks, SIP before RTP,
	// followed by the call-completion hook. No writer lock is held here.
	writer.notifyFileClosed(sipClosedPath)
	writer.notifyFileClosed(rtpClosedPath)
	if callComplete && writer.config.OnCallComplete != nil {
		if invokeCallback("per-call completion", func() {
			writer.config.OnCallComplete(meta)
		}, "call_id", writer.callID) && writer.manager != nil {
			writer.manager.callbackFailures.Add(1)
		}
	}

	return errors.Join(finalizationErrors...)
}

// CloseCall closes both PCAP files and fires the OnCallComplete callback
// This should be called when a VoIP call is complete
func (writer *CallPcapWriter) CloseCall() error {
	if writer == nil {
		return nil
	}
	if writer.manager != nil {
		_, err := writer.manager.finalizeCallGeneration(writer.callID, writer.generation, CallFinalizationProtocolComplete)
		return err
	}
	return writer.finalize(CallFinalizationProtocolComplete)
}

// CloseWriter closes a specific call's writer (without firing OnCallComplete)
func (pwm *PcapWriterManager) CloseWriter(callID string) error {
	_, err := pwm.FinalizeCall(callID, CallFinalizationManual)
	return err
}

// CloseCallWriter closes a specific call's writer and fires OnCallComplete callback.
// Use this method when a VoIP call completes to trigger the voipcommand hook.
func (pwm *PcapWriterManager) CloseCallWriter(callID string) error {
	_, err := pwm.FinalizeCall(callID, CallFinalizationProtocolComplete)
	return err
}

// FinalizeCall performs the single live-to-terminal transition. Manager state
// changes atomically; cleanup, file closing, and callbacks run after unlocking.
func (pwm *PcapWriterManager) FinalizeCall(callID string, reason CallFinalizationReason) (CallFinalizationResult, error) {
	return pwm.finalizeCallGeneration(callID, 0, reason)
}

// finalizeCallGeneration performs a generation-conditional transition when
// generation is non-zero. Writer-bound operations use this path so a retained
// handle cannot finalize a newer reuse of the same Call-ID.
func (pwm *PcapWriterManager) finalizeCallGeneration(callID string, generation uint64, reason CallFinalizationReason) (CallFinalizationResult, error) {
	result := CallFinalizationResult{CallID: callID, Reason: reason}
	if pwm == nil || callID == "" {
		return result, nil
	}
	waiter := make(chan pcapFinalizationOutcome, 1)
	pwm.mu.Lock()
	if pwm.shutdown {
		pwm.mu.Unlock()
		return result, nil
	}
	writer := pwm.writers[callID]
	if generation != 0 && writer != nil && writer.generation != generation {
		writer = nil
	}
	pwm.finalizationWaiters[callID] = append(pwm.finalizationWaiters[callID], waiter)
	pwm.mu.Unlock()
	if generation == 0 {
		result = pwm.lifecycle.Finalize(callID, reason)
	} else {
		result = pwm.lifecycle.FinalizeGeneration(callID, generation, reason)
	}
	if result.Finalized {
		outcome := <-waiter
		result.HadWriter = outcome.hadWriter
		return result, outcome.err
	}
	pwm.removeFinalizationWaiter(callID, waiter)
	return result, nil
}

func (pwm *PcapWriterManager) handleLifecycleFinalization(event CallFinalizationEvent) {
	pwm.mu.Lock()
	writer := pwm.writers[event.CallID]
	if writer != nil && writer.generation == event.Generation {
		delete(pwm.writers, event.CallID)
		pwm.finalizationWG.Add(1)
	} else {
		writer = nil
	}
	hook := pwm.beforeFinalize
	waiters := pwm.finalizationWaiters[event.CallID]
	delete(pwm.finalizationWaiters, event.CallID)
	pwm.mu.Unlock()

	result := CallFinalizationResult{CallID: event.CallID, Reason: event.Reason, FinalizedAt: event.FinalizedAt, Finalized: true, HadWriter: writer != nil}
	_, err := pwm.completeFinalization(result, writer, hook)
	outcome := pcapFinalizationOutcome{hadWriter: writer != nil, err: err}
	for _, waiter := range waiters {
		waiter <- outcome
	}
}

func (pwm *PcapWriterManager) removeFinalizationWaiter(callID string, target chan pcapFinalizationOutcome) {
	pwm.mu.Lock()
	defer pwm.mu.Unlock()
	waiters := pwm.finalizationWaiters[callID]
	for i, waiter := range waiters {
		if waiter != target {
			continue
		}
		waiters = append(waiters[:i], waiters[i+1:]...)
		if len(waiters) == 0 {
			delete(pwm.finalizationWaiters, callID)
		} else {
			pwm.finalizationWaiters[callID] = waiters
		}
		return
	}
}

// completeFinalization performs slow resource work and externally supplied
// hooks after the manager transition lock has been released.
func (pwm *PcapWriterManager) completeFinalization(result CallFinalizationResult, writer *CallPcapWriter, hook func(string, CallFinalizationReason)) (CallFinalizationResult, error) {
	if !result.Finalized {
		return result, nil
	}
	reason := result.Reason
	callID := result.CallID
	if reason != CallFinalizationShutdown && hook != nil {
		if invokeCallback("per-call pre-finalization", func() {
			hook(callID, reason)
		}, "call_id", callID, "reason", reason) {
			pwm.callbackFailures.Add(1)
		}
	}
	switch reason {
	case CallFinalizationProtocolComplete:
		pwm.protocolFinalizations.Add(1)
	case CallFinalizationIdleTimeout:
		pwm.idleFinalizations.Add(1)
	case CallFinalizationCapacityEviction:
		pwm.capacityFinalizations.Add(1)
	case CallFinalizationManual:
		pwm.manualFinalizations.Add(1)
	}
	if writer == nil {
		return result, nil
	}
	released := false
	releaseFinalization := func() {
		pwm.finalizationWG.Done()
		released = true
	}
	defer func() {
		if !released {
			pwm.finalizationWG.Done()
		}
	}()
	return result, writer.finalizeWithBeforeCallbacks(reason, releaseFinalization)
}

// HasRTPPackets returns true if the call has received any RTP packets.
// Used by CallCompletionMonitor to wait for RTP before firing voipcommand.
func (pwm *PcapWriterManager) HasRTPPackets(callID string) bool {
	pwm.mu.RLock()
	defer pwm.mu.RUnlock()

	writer, exists := pwm.writers[callID]
	if !exists {
		return false
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.rtpPacketCount > 0
}

// HasSIPPackets returns true if the call has received any SIP packets.
func (pwm *PcapWriterManager) HasSIPPackets(callID string) bool {
	pwm.mu.RLock()
	defer pwm.mu.RUnlock()

	writer, exists := pwm.writers[callID]
	if !exists {
		return false
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.sipPacketCount > 0
}

// Close closes all writers
func (pwm *PcapWriterManager) Close() error {
	pwm.mu.Lock()
	if pwm.shutdown {
		pwm.mu.Unlock()
		return nil
	}
	pwm.shutdown = true
	writers := pwm.writers
	pwm.writers = make(map[string]*CallPcapWriter)
	pwm.mu.Unlock()
	pwm.finalizationWG.Wait()

	var lastErr error
	for callID, writer := range writers {
		if err := writer.finalize(CallFinalizationShutdown); err != nil {
			logger.Warn("Failed to close PCAP writer", "call_id", callID, "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// Helper functions

func sanitizeFilename(s string) string {
	// Replace unsafe characters
	replacements := map[rune]rune{
		'/':  '_',
		'\\': '_',
		':':  '_',
		'*':  '_',
		'?':  '_',
		'"':  '_',
		'<':  '_',
		'>':  '_',
		'|':  '_',
		'@':  '_',
		' ':  '_',
	}

	runes := []rune(s)
	for i, r := range runes {
		if replacement, ok := replacements[r]; ok {
			runes[i] = replacement
		}
	}

	return string(runes)
}
