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

// POP3MessageHandler processes POP3 lines after TCP reassembly.
type POP3MessageHandler interface {
	// HandlePOP3Line is called for each complete POP3 line.
	HandlePOP3Line(line string, metadata *types.EmailMetadata, sessionID string, flow gopacket.Flow)
}

// POP3Stream represents a TCP stream that processes POP3 protocol.
type POP3Stream struct {
	reader       *tcpreader.ReaderStream
	safeReader   *safePOP3Reader
	ctx          context.Context
	factory      *pop3StreamFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *POP3Parser

	// Multi-line response state
	inMultiline bool            // In multi-line response (LIST, UIDL, RETR, TOP, CAPA)
	lastCommand string          // Last command from client
	bodyBuffer  strings.Builder // Buffer for message body (RETR/TOP)
	bodySize    int             // Total body size
	inHeaders   bool            // Still in headers section (RETR/TOP)
}

// safePOP3Reader wraps a tcpreader.ReaderStream to provide interruptible reads.
type safePOP3Reader struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	bufReader  *bufio.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	copyDone   chan struct{}
	closeOnce  sync.Once
}

func newSafePOP3Reader(reader *tcpreader.ReaderStream, ctx context.Context) *safePOP3Reader {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)

	sr := &safePOP3Reader{
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

func (sr *safePOP3Reader) ReadLine() (string, error) {
	if sr.ctx.Err() != nil {
		return "", sr.ctx.Err()
	}
	return sr.bufReader.ReadString('\n')
}

func (sr *safePOP3Reader) close() {
	sr.closeOnce.Do(func() {
		sr.cancel()
		sr.pipeReader.Close()
	})
}

func (s *POP3Stream) run() {
	logger.Debug("POP3 stream starting",
		"flow", s.flow.String(),
		"is_from_server", s.isFromServer)

	s.safeReader = newSafePOP3Reader(s.reader, s.ctx)

	defer func() {
		s.safeReader.close()

		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		logger.Debug("POP3 stream completed",
			"flow", s.flow.String(),
			"duration", time.Since(s.createdAt))
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		line, err := s.safeReader.ReadLine()
		if err != nil {
			if err != io.EOF && s.ctx.Err() == nil {
				logger.Debug("POP3 stream read error", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Handle multi-line response
		if s.inMultiline && s.isFromServer {
			s.handleMultilineLine(line)
			continue
		}

		// Parse POP3 line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			// Track client commands for multi-line detection
			if !s.isFromServer {
				s.lastCommand = metadata.POP3Command
			}

			// Check for +OK responses that start multi-line
			if s.isFromServer && metadata.POP3Status == "+OK" {
				switch s.lastCommand {
				case "LIST", "UIDL", "CAPA":
					// These return multi-line without message body
					s.inMultiline = true
					s.inHeaders = false
				case "RETR", "TOP":
					// These return multi-line with message content
					s.inMultiline = true
					s.inHeaders = true
					s.bodyBuffer.Reset()
					s.bodySize = 0
				}
			}

			// Notify handler
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandlePOP3Line(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// handleMultilineLine handles lines in a multi-line response.
func (s *POP3Stream) handleMultilineLine(line string) {
	// Check for terminator
	if line == "." {
		s.inMultiline = false

		// If we were in RETR/TOP, emit the completed message
		if s.lastCommand == "RETR" || s.lastCommand == "TOP" {
			metadata := &types.EmailMetadata{
				Protocol:   "POP3",
				IsServer:   true,
				POP3Status: "+OK",
			}

			// Parse captured body for headers
			bodyContent := s.bodyBuffer.String()
			s.extractHeadersFromBody(bodyContent, metadata)

			metadata.BodyPreview = sanitizeUTF8(bodyContent)
			metadata.BodySize = s.bodySize
			metadata.BodyTruncated = s.bodySize > s.factory.maxBodySize

			// Emit complete message
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandlePOP3Line("", metadata, s.sessionID, s.flow)
			}
		}

		s.bodyBuffer.Reset()
		s.bodySize = 0
		s.inHeaders = false
		return
	}

	// Handle byte-stuffed lines (leading . is doubled)
	if strings.HasPrefix(line, "..") {
		line = line[1:]
	}

	s.bodySize += len(line) + 1 // +1 for newline

	// For RETR/TOP, capture the content
	if s.lastCommand == "RETR" || s.lastCommand == "TOP" {
		// Check for header/body boundary
		if s.inHeaders && line == "" {
			s.inHeaders = false
		}

		// Capture body if enabled
		if s.factory.captureBody {
			if s.bodyBuffer.Len() < s.factory.maxBodySize {
				if s.bodyBuffer.Len() > 0 {
					s.bodyBuffer.WriteString("\n")
				}
				remaining := s.factory.maxBodySize - s.bodyBuffer.Len()
				if len(line) <= remaining {
					s.bodyBuffer.WriteString(line)
				} else {
					s.bodyBuffer.WriteString(line[:remaining])
				}
			}
		}

		// Parse headers in real-time
		if s.inHeaders {
			metadata := &types.EmailMetadata{
				Protocol: "POP3",
				IsServer: true,
			}
			s.parser.ParseLine(line, metadata, true)

			// Emit header lines with partial metadata
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandlePOP3Line(line, metadata, s.sessionID, s.flow)
			}
		}
	} else {
		// For LIST/UIDL/CAPA, emit each line
		metadata := &types.EmailMetadata{
			Protocol: "POP3",
			IsServer: true,
		}
		s.parser.ParseLine(line, metadata, true)

		if s.factory != nil && s.factory.handler != nil {
			s.factory.handler.HandlePOP3Line(line, metadata, s.sessionID, s.flow)
		}
	}
}

// extractHeadersFromBody parses email headers from message body content.
func (s *POP3Stream) extractHeadersFromBody(body string, metadata *types.EmailMetadata) {
	lines := strings.Split(body, "\n")

	for _, line := range lines {
		if line == "" {
			break // End of headers
		}
		// Use POP3 parser's regex patterns
		s.parser.ParseLine(line, metadata, true)
	}
}

// createPOP3Stream creates a new POP3 stream.
func createPOP3Stream(
	reader *tcpreader.ReaderStream,
	ctx context.Context,
	factory *pop3StreamFactory,
	flow gopacket.Flow,
	reverseFlow gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *POP3Stream {
	return &POP3Stream{
		reader:       reader,
		ctx:          ctx,
		factory:      factory,
		flow:         flow,
		reverseFlow:  reverseFlow,
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewPOP3Parser(),
	}
}
