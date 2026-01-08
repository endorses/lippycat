//go:build cli || all

package email

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// MultiProtocolFactory routes TCP streams to the appropriate email protocol handler.
type MultiProtocolFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	maxGoroutines    int
	cleanupTicker    *time.Ticker
	allWorkers       sync.WaitGroup
	closed           int32

	// Protocol-specific handlers
	handler *cliEmailHandler

	// Port maps for protocol detection
	smtpPorts map[uint16]bool
	imapPorts map[uint16]bool
	pop3Ports map[uint16]bool

	// Configuration
	protocol    string
	captureBody bool
	maxBodySize int
}

// MultiProtocolFactoryConfig holds configuration for the factory.
type MultiProtocolFactoryConfig struct {
	Protocol    string
	CaptureBody bool
	MaxBodySize int
	SMTPPorts   map[uint16]bool
	IMAPPorts   map[uint16]bool
	POP3Ports   map[uint16]bool
}

// NewMultiProtocolFactory creates a new multi-protocol stream factory.
func NewMultiProtocolFactory(ctx context.Context, handler *cliEmailHandler, config MultiProtocolFactoryConfig) *MultiProtocolFactory {
	ctx, cancel := context.WithCancel(ctx)

	maxGoroutines := 3000 // Higher limit for multi-protocol
	maxBodySize := config.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = 64 * 1024
	}

	factory := &MultiProtocolFactory{
		ctx:           ctx,
		cancel:        cancel,
		maxGoroutines: maxGoroutines,
		cleanupTicker: time.NewTicker(30 * time.Second),
		handler:       handler,
		smtpPorts:     config.SMTPPorts,
		imapPorts:     config.IMAPPorts,
		pop3Ports:     config.POP3Ports,
		protocol:      config.Protocol,
		captureBody:   config.CaptureBody,
		maxBodySize:   maxBodySize,
	}

	// Start cleanup routine
	factory.allWorkers.Add(1)
	go factory.cleanupRoutine()

	return factory
}

// New creates a new stream based on the port (implements tcpassembly.StreamFactory).
func (f *MultiProtocolFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()

	// Check goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.maxGoroutines) {
		logger.Warn("Email stream dropped: goroutine limit reached",
			"active", current,
			"max", f.maxGoroutines)
		return &r
	}

	// Determine protocol from port
	srcPort := uint16(transport.Src().Raw()[0])<<8 | uint16(transport.Src().Raw()[1])
	dstPort := uint16(transport.Dst().Raw()[0])<<8 | uint16(transport.Dst().Raw()[1])

	protocol := f.detectProtocol(srcPort, dstPort)
	if protocol == "" {
		// Unknown protocol - still consume the stream but don't process
		return &r
	}

	// Determine if this is from server
	isFromServer := f.isServerPort(srcPort)

	// Create session ID from flow
	sessionID := createSessionID(net, transport)

	// Create and start appropriate stream
	atomic.AddInt64(&f.activeGoroutines, 1)

	switch protocol {
	case "SMTP":
		stream := f.createSMTPStream(&r, net, transport, isFromServer, sessionID)
		go stream.run()
	case "IMAP":
		stream := f.createIMAPStream(&r, net, transport, isFromServer, sessionID)
		go stream.run()
	case "POP3":
		stream := f.createPOP3Stream(&r, net, transport, isFromServer, sessionID)
		go stream.run()
	default:
		atomic.AddInt64(&f.activeGoroutines, -1)
	}

	return &r
}

// detectProtocol determines the email protocol based on ports.
func (f *MultiProtocolFactory) detectProtocol(srcPort, dstPort uint16) string {
	// Check source port first (server response), then destination (client request)
	if f.smtpPorts[srcPort] || f.smtpPorts[dstPort] {
		return "SMTP"
	}
	if f.imapPorts[srcPort] || f.imapPorts[dstPort] {
		return "IMAP"
	}
	if f.pop3Ports[srcPort] || f.pop3Ports[dstPort] {
		return "POP3"
	}
	return ""
}

// isServerPort checks if a port is a known server port.
func (f *MultiProtocolFactory) isServerPort(port uint16) bool {
	return f.smtpPorts[port] || f.imapPorts[port] || f.pop3Ports[port]
}

// createSMTPStream creates an SMTP stream.
func (f *MultiProtocolFactory) createSMTPStream(
	reader *tcpreader.ReaderStream,
	net, transport gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *smtpStreamWrapper {
	return &smtpStreamWrapper{
		reader:       reader,
		ctx:          f.ctx,
		factory:      f,
		flow:         net,
		reverseFlow:  transport.Reverse(),
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewParser(),
		captureBody:  f.captureBody,
		maxBodySize:  f.maxBodySize,
	}
}

// createIMAPStream creates an IMAP stream.
func (f *MultiProtocolFactory) createIMAPStream(
	reader *tcpreader.ReaderStream,
	net, transport gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *imapStreamWrapper {
	return &imapStreamWrapper{
		reader:       reader,
		ctx:          f.ctx,
		factory:      f,
		flow:         net,
		reverseFlow:  transport.Reverse(),
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewIMAPParser(),
	}
}

// createPOP3Stream creates a POP3 stream.
func (f *MultiProtocolFactory) createPOP3Stream(
	reader *tcpreader.ReaderStream,
	net, transport gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *pop3StreamWrapper {
	return &pop3StreamWrapper{
		reader:       reader,
		ctx:          f.ctx,
		factory:      f,
		flow:         net,
		reverseFlow:  transport.Reverse(),
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewPOP3Parser(),
		captureBody:  f.captureBody,
		maxBodySize:  f.maxBodySize,
	}
}

// cleanupRoutine periodically performs cleanup tasks.
func (f *MultiProtocolFactory) cleanupRoutine() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.cleanupTicker.C:
			active := atomic.LoadInt64(&f.activeGoroutines)
			if active > 0 {
				logger.Debug("Email stream stats",
					"active_streams", active,
					"max_goroutines", f.maxGoroutines)
			}
		}
	}
}

// Close shuts down the factory.
func (f *MultiProtocolFactory) Close() {
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return
	}

	f.cancel()
	f.cleanupTicker.Stop()
	f.allWorkers.Wait()

	logger.Info("Multi-protocol email factory closed")
}

// GetActiveGoroutines returns the current number of active goroutines.
func (f *MultiProtocolFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// smtpStreamWrapper wraps an SMTP stream for the multi-protocol factory.
type smtpStreamWrapper struct {
	reader       *tcpreader.ReaderStream
	ctx          context.Context
	factory      *MultiProtocolFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *Parser

	captureBody bool
	maxBodySize int
}

func (s *smtpStreamWrapper) run() {
	defer func() {
		atomic.AddInt64(&s.factory.activeGoroutines, -1)
	}()

	sr := newSafeSMTPReader(s.reader, s.ctx)
	defer sr.close()

	inData := false

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		line, err := sr.ReadLine()
		if err != nil {
			return
		}

		line = trimLine(line)

		// Handle DATA mode
		if inData {
			if line == "." {
				inData = false
			}
			continue
		}

		// Parse SMTP line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			if s.isFromServer && metadata.ResponseCode == 354 {
				inData = true
			}

			if s.factory.handler != nil {
				s.factory.handler.HandleSMTPLine(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// imapStreamWrapper wraps an IMAP stream for the multi-protocol factory.
type imapStreamWrapper struct {
	reader       *tcpreader.ReaderStream
	ctx          context.Context
	factory      *MultiProtocolFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *IMAPParser
}

func (s *imapStreamWrapper) run() {
	defer func() {
		atomic.AddInt64(&s.factory.activeGoroutines, -1)
	}()

	sr := newSafeIMAPReader(s.reader, s.ctx)
	defer sr.close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		line, err := sr.ReadLine()
		if err != nil {
			return
		}

		line = trimLine(line)

		// Parse IMAP line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			if s.factory.handler != nil {
				s.factory.handler.HandleIMAPLine(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// pop3StreamWrapper wraps a POP3 stream for the multi-protocol factory.
type pop3StreamWrapper struct {
	reader       *tcpreader.ReaderStream
	ctx          context.Context
	factory      *MultiProtocolFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *POP3Parser

	captureBody bool
	maxBodySize int
}

func (s *pop3StreamWrapper) run() {
	defer func() {
		atomic.AddInt64(&s.factory.activeGoroutines, -1)
	}()

	sr := newSafePOP3Reader(s.reader, s.ctx)
	defer sr.close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		line, err := sr.ReadLine()
		if err != nil {
			return
		}

		line = trimLine(line)

		// Parse POP3 line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			if s.factory.handler != nil {
				s.factory.handler.HandlePOP3Line(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// trimLine removes trailing CRLF from a line.
func trimLine(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		line = line[:len(line)-1]
	}
	return line
}
