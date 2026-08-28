package voip

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// CallOutput owns all output resources associated with tracked calls.
type CallOutput interface {
	OpenSession(callID string, linkType layers.LinkType) error
	WritePacket(callID string, packet gopacket.Packet, packetType PacketType) error
	CloseSession(callID string) error
	Shutdown() error
}

type NoopCallOutput struct{}

func (NoopCallOutput) OpenSession(string, layers.LinkType) error { return nil }
func (NoopCallOutput) WritePacket(string, gopacket.Packet, PacketType) error {
	return ErrWriterNotInitialized
}
func (NoopCallOutput) CloseSession(string) error { return nil }
func (NoopCallOutput) Shutdown() error           { return nil }

type sessionFiles struct {
	mu                   sync.Mutex
	closed               bool
	sipFile, rtpFile     *os.File
	sipWriter, rtpWriter *pcapgo.Writer
}

// SessionOutputManager is the legacy per-call PCAP output service.
type SessionOutputManager struct {
	mu       sync.RWMutex
	config   Config
	sessions map[string]*sessionFiles
	closed   bool
}

func NewSessionOutputManager(config *Config) *SessionOutputManager {
	if config == nil {
		config = DefaultConfig()
	}
	cfg := *config
	return &SessionOutputManager{config: cfg, sessions: make(map[string]*sessionFiles)}
}

func (m *SessionOutputManager) OpenSession(callID string, linkType layers.LinkType) error {
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return ErrOutputManagerClosed
	}
	name := sanitizeWithMaxLength(callID, m.config.MaxFilenameLength)
	var sipPath, rtpPath string
	if m.config.OutputFile != "" {
		base := strings.TrimSuffix(m.config.OutputFile, filepath.Ext(m.config.OutputFile))
		sipPath, rtpPath = fmt.Sprintf("%s_sip_%s.pcap", base, name), fmt.Sprintf("%s_rtp_%s.pcap", base, name)
	} else {
		dir, err := getCapturesDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create captures directory: %w", err)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("stat captures directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("captures directory is a symlink, refusing to use it for security")
		}
		sipPath, rtpPath = filepath.Join(dir, "sip_"+name+".pcap"), filepath.Join(dir, "rtp_"+name+".pcap")
	}
	s := &sessionFiles{}
	var err error
	s.sipFile, err = os.OpenFile(sipPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create SIP file: %w", err)
	}
	s.rtpFile, err = os.OpenFile(rtpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		if closeErr := s.sipFile.Close(); closeErr != nil {
			logger.Error("close SIP output after RTP open failure", "call_id", SanitizeCallIDForLogging(callID), "error", closeErr)
		}
		return fmt.Errorf("create RTP file: %w", err)
	}
	s.sipWriter, s.rtpWriter = pcapgo.NewWriter(s.sipFile), pcapgo.NewWriter(s.rtpFile)
	if err = s.sipWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, linkType); err == nil {
		err = s.rtpWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, linkType)
	}
	if err != nil {
		if closeErr := s.sipFile.Close(); closeErr != nil {
			logger.Error("close SIP output after header failure", "call_id", SanitizeCallIDForLogging(callID), "error", closeErr)
		}
		if closeErr := s.rtpFile.Close(); closeErr != nil {
			logger.Error("close RTP output after header failure", "call_id", SanitizeCallIDForLogging(callID), "error", closeErr)
		}
		return fmt.Errorf("write PCAP header: %w", err)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = closeSessionFiles(s)
		return ErrOutputManagerClosed
	}
	old := m.sessions[callID]
	m.sessions[callID] = s
	m.mu.Unlock()
	if old != nil {
		if err := closeSessionFiles(old); err != nil {
			logger.Error("close replaced call output", "call_id", SanitizeCallIDForLogging(callID), "error", err)
		}
	}
	return nil
}

func (m *SessionOutputManager) WritePacket(callID string, packet gopacket.Packet, typ PacketType) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrOutputManagerClosed
	}
	s := m.sessions[callID]
	m.mu.RUnlock()
	if s == nil {
		return ErrWriterNotInitialized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrWriterNotInitialized
	}
	if typ == PacketTypeSIP {
		return s.sipWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	if typ == PacketTypeRTP {
		return s.rtpWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
	return ErrInvalidPacketType
}

func (m *SessionOutputManager) CloseSession(callID string) error {
	m.mu.Lock()
	s := m.sessions[callID]
	delete(m.sessions, callID)
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	return closeSessionFiles(s)
}
func closeSessionFiles(s *sessionFiles) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var first error
	if err := s.sipFile.Close(); err != nil {
		first = err
	}
	if err := s.rtpFile.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
func (m *SessionOutputManager) Shutdown() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	all := m.sessions
	m.sessions = make(map[string]*sessionFiles)
	m.mu.Unlock()
	var first error
	for id, s := range all {
		if err := closeSessionFiles(s); err != nil && first == nil {
			first = err
			logger.Error("close call output", "call_id", SanitizeCallIDForLogging(id), "error", err)
		}
	}
	return first
}
