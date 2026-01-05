package email

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// SMTPMessageHandler processes SMTP lines after TCP reassembly.
type SMTPMessageHandler interface {
	// HandleSMTPLine is called for each complete SMTP line.
	// Parameters:
	//   - line: complete SMTP line (command or response)
	//   - metadata: parsed SMTP metadata
	//   - sessionID: session identifier for correlation
	//   - flow: network flow identifier
	HandleSMTPLine(line string, metadata *types.EmailMetadata, sessionID string, flow gopacket.Flow)
}

// SMTPStream represents a TCP stream that processes SMTP protocol.
type SMTPStream struct {
	reader       *tcpreader.ReaderStream
	safeReader   *safeSMTPReader
	ctx          context.Context
	factory      *smtpStreamFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *Parser

	// Body capture state
	bodyBuffer     strings.Builder      // Accumulated body content
	bodySize       int                  // Total body size seen
	bodyTruncated  bool                 // Body exceeded max size
	inBodyMode     bool                 // True when past headers in DATA
	headerMetadata *types.EmailMetadata // Parsed header metadata (before body)
}

// safeSMTPReader wraps a tcpreader.ReaderStream to provide interruptible reads.
type safeSMTPReader struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	bufReader  *bufio.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	copyDone   chan struct{}
	closeOnce  sync.Once
}

func newSafeSMTPReader(reader *tcpreader.ReaderStream, ctx context.Context) *safeSMTPReader {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)

	sr := &safeSMTPReader{
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		bufReader:  bufio.NewReader(pipeReader),
		ctx:        ctx,
		cancel:     cancel,
		copyDone:   make(chan struct{}),
	}

	// Start copy goroutine
	go func() {
		defer close(sr.copyDone)
		defer pipeWriter.Close()

		if reader == nil {
			pipeWriter.CloseWithError(io.ErrClosedPipe)
			return
		}
		defer reader.Close()

		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := reader.Read(buf)
			if n > 0 {
				if _, writeErr := pipeWriter.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					pipeWriter.CloseWithError(err)
				}
				return
			}
		}
	}()

	return sr
}

func (sr *safeSMTPReader) ReadLine() (string, error) {
	if sr.ctx.Err() != nil {
		return "", sr.ctx.Err()
	}
	return sr.bufReader.ReadString('\n')
}

func (sr *safeSMTPReader) close() {
	sr.closeOnce.Do(func() {
		sr.cancel()
		sr.pipeReader.Close()
	})
}

func (s *SMTPStream) run() {
	logger.Debug("SMTP stream starting",
		"flow", s.flow.String(),
		"is_from_server", s.isFromServer)

	s.safeReader = newSafeSMTPReader(s.reader, s.ctx)

	defer func() {
		s.safeReader.close()

		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		logger.Debug("SMTP stream completed",
			"flow", s.flow.String(),
			"duration", time.Since(s.createdAt))
	}()

	// Process lines
	inData := false
	var dataLines []string

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		line, err := s.safeReader.ReadLine()
		if err != nil {
			if err != io.EOF && s.ctx.Err() == nil {
				logger.Debug("SMTP stream read error", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Handle DATA mode
		if inData {
			if line == "." {
				// End of DATA - finalize message with body
				inData = false
				s.processDataContent(dataLines)
				dataLines = nil
				s.resetBodyCapture()
			} else if s.inBodyMode {
				// We're in body mode - capture body content
				s.captureBodyLine(line)
			} else {
				// Still in headers
				dataLines = append(dataLines, line)
				// Check for empty line (end of headers)
				if line == "" {
					s.inBodyMode = true
					// Process headers now, body will follow
					s.processDataHeaders(dataLines)
				}
			}
			continue
		}

		// Parse SMTP line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			// Check for DATA command
			if !s.isFromServer && metadata.Command == "DATA" {
				// Wait for 354 response to enter data mode
			}
			// Check for 354 response (ready for data)
			if s.isFromServer && metadata.ResponseCode == 354 {
				inData = true
				s.inBodyMode = false // Start in header mode
			}

			// Notify handler
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandleSMTPLine(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// captureBodyLine adds a line to the body buffer if body capture is enabled.
func (s *SMTPStream) captureBodyLine(line string) {
	// Track total body size (including line separators)
	lineLen := len(line) + 1 // +1 for newline
	s.bodySize += lineLen

	// Skip capture if factory doesn't have body capture enabled
	if s.factory == nil || !s.factory.captureBody {
		return
	}

	// Check if we've exceeded the max body size
	if s.bodyTruncated {
		return // Already truncated, don't add more
	}

	maxBodySize := s.factory.maxBodySize
	if s.bodyBuffer.Len()+lineLen > maxBodySize {
		// Would exceed limit - truncate
		remaining := maxBodySize - s.bodyBuffer.Len()
		if remaining > 0 {
			s.bodyBuffer.WriteString(line[:remaining])
		}
		s.bodyTruncated = true
		return
	}

	// Add line to buffer
	if s.bodyBuffer.Len() > 0 {
		s.bodyBuffer.WriteString("\n")
	}
	s.bodyBuffer.WriteString(line)
}

// resetBodyCapture resets the body capture state for the next message.
func (s *SMTPStream) resetBodyCapture() {
	s.bodyBuffer.Reset()
	s.bodySize = 0
	s.bodyTruncated = false
	s.inBodyMode = false
}

// processDataHeaders parses header lines but does not emit.
// Headers are stored in headerMetadata for later use by processDataContent.
func (s *SMTPStream) processDataHeaders(lines []string) {
	s.headerMetadata = &types.EmailMetadata{
		Protocol: "SMTP",
		IsServer: false,
		Command:  "DATA_HEADERS",
	}

	for _, line := range lines {
		s.parser.ParseDataHeader(line, s.headerMetadata)
	}
}

// processDataContent emits the complete message with headers and body.
func (s *SMTPStream) processDataContent(headerLines []string) {
	if s.factory == nil || s.factory.handler == nil {
		return
	}

	// Use previously parsed headers or parse now if not available
	var metadata *types.EmailMetadata
	if s.headerMetadata != nil {
		metadata = s.headerMetadata
	} else {
		// Parse headers now (fallback)
		metadata = &types.EmailMetadata{
			Protocol: "SMTP",
			IsServer: false,
		}
		for _, line := range headerLines {
			s.parser.ParseDataHeader(line, metadata)
		}
	}

	// Update command to indicate complete message
	metadata.Command = "DATA_COMPLETE"

	// Add body content if captured
	if s.factory.captureBody && s.bodyBuffer.Len() > 0 {
		metadata.BodyPreview = s.bodyBuffer.String()
	}
	metadata.BodySize = s.bodySize
	metadata.BodyTruncated = s.bodyTruncated

	// Emit if we have meaningful content
	if metadata.MessageID != "" || metadata.Subject != "" || metadata.BodyPreview != "" {
		s.factory.handler.HandleSMTPLine("", metadata, s.sessionID, s.flow)
	}

	// Clear header metadata for next message
	s.headerMetadata = nil
}

// createSMTPStream creates a new SMTP stream.
func createSMTPStream(
	reader *tcpreader.ReaderStream,
	ctx context.Context,
	factory *smtpStreamFactory,
	flow gopacket.Flow,
	reverseFlow gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *SMTPStream {
	return &SMTPStream{
		reader:       reader,
		ctx:          ctx,
		factory:      factory,
		flow:         flow,
		reverseFlow:  reverseFlow,
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewParser(),
	}
}
