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
				// End of DATA
				inData = false
				// Process accumulated data headers
				s.processDataHeaders(dataLines)
				dataLines = nil
			} else {
				// Accumulate data lines (only headers for now)
				if len(dataLines) < 100 && (len(line) == 0 || len(dataLines) == 0 || !strings.HasPrefix(line, " ")) {
					dataLines = append(dataLines, line)
					// Stop accumulating after empty line (end of headers)
					if line == "" {
						s.processDataHeaders(dataLines)
						dataLines = nil
					}
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
			}

			// Notify handler
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandleSMTPLine(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

func (s *SMTPStream) processDataHeaders(lines []string) {
	if s.factory == nil || s.factory.handler == nil {
		return
	}

	metadata := &types.EmailMetadata{
		Protocol: "SMTP",
		IsServer: false,
		Command:  "DATA_HEADERS",
	}

	for _, line := range lines {
		s.parser.ParseDataHeader(line, metadata)
	}

	if metadata.MessageID != "" || metadata.Subject != "" {
		s.factory.handler.HandleSMTPLine("", metadata, s.sessionID, s.flow)
	}
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
