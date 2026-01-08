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

// IMAPMessageHandler processes IMAP lines after TCP reassembly.
type IMAPMessageHandler interface {
	// HandleIMAPLine is called for each complete IMAP line.
	HandleIMAPLine(line string, metadata *types.EmailMetadata, sessionID string, flow gopacket.Flow)
}

// IMAPStream represents a TCP stream that processes IMAP protocol.
type IMAPStream struct {
	reader       *tcpreader.ReaderStream
	safeReader   *safeIMAPReader
	ctx          context.Context
	factory      *imapStreamFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *IMAPParser

	// Literal handling state (IMAP uses {n} literals)
	expectingLiteral bool
	literalSize      int
	literalBuffer    strings.Builder
}

// safeIMAPReader wraps a tcpreader.ReaderStream to provide interruptible reads.
type safeIMAPReader struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	bufReader  *bufio.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	copyDone   chan struct{}
	closeOnce  sync.Once
}

func newSafeIMAPReader(reader *tcpreader.ReaderStream, ctx context.Context) *safeIMAPReader {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)

	sr := &safeIMAPReader{
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

func (sr *safeIMAPReader) ReadLine() (string, error) {
	if sr.ctx.Err() != nil {
		return "", sr.ctx.Err()
	}
	return sr.bufReader.ReadString('\n')
}

func (sr *safeIMAPReader) ReadBytes(n int) ([]byte, error) {
	if sr.ctx.Err() != nil {
		return nil, sr.ctx.Err()
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(sr.bufReader, buf)
	return buf, err
}

func (sr *safeIMAPReader) close() {
	sr.closeOnce.Do(func() {
		sr.cancel()
		sr.pipeReader.Close()
	})
}

func (s *IMAPStream) run() {
	logger.Debug("IMAP stream starting",
		"flow", s.flow.String(),
		"is_from_server", s.isFromServer)

	s.safeReader = newSafeIMAPReader(s.reader, s.ctx)

	defer func() {
		s.safeReader.close()

		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		logger.Debug("IMAP stream completed",
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
				logger.Debug("IMAP stream read error", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Handle literal continuation
		if s.expectingLiteral {
			s.handleLiteralData(line)
			continue
		}

		// Check for literal marker {n} at end of line
		if s.checkForLiteral(line) {
			continue
		}

		// Parse IMAP line
		metadata := &types.EmailMetadata{}
		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			// Notify handler
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandleIMAPLine(line, metadata, s.sessionID, s.flow)
			}
		}
	}
}

// checkForLiteral checks if the line ends with a literal marker {n}.
func (s *IMAPStream) checkForLiteral(line string) bool {
	// Look for {n} or {n+} at end of line
	if len(line) < 3 {
		return false
	}
	lastBrace := strings.LastIndex(line, "}")
	if lastBrace == -1 || lastBrace != len(line)-1 {
		return false
	}
	openBrace := strings.LastIndex(line[:lastBrace], "{")
	if openBrace == -1 {
		return false
	}

	sizeStr := line[openBrace+1 : lastBrace]
	// Remove + if present (non-synchronizing literal)
	sizeStr = strings.TrimSuffix(sizeStr, "+")

	var size int
	_, err := scanInt(sizeStr, &size)
	if err != nil || size <= 0 {
		return false
	}

	s.expectingLiteral = true
	s.literalSize = size
	s.literalBuffer.Reset()

	// Parse the line part before literal and emit
	metadata := &types.EmailMetadata{}
	if s.parser.ParseLine(line[:openBrace], metadata, s.isFromServer) {
		if s.factory != nil && s.factory.handler != nil {
			s.factory.handler.HandleIMAPLine(line[:openBrace], metadata, s.sessionID, s.flow)
		}
	}

	return true
}

// handleLiteralData handles literal data continuation.
func (s *IMAPStream) handleLiteralData(line string) {
	s.literalBuffer.WriteString(line)
	s.literalBuffer.WriteString("\n")

	// Check if we've received enough data
	if s.literalBuffer.Len() >= s.literalSize {
		// Literal complete - process remaining content
		s.expectingLiteral = false

		// The literal data might contain headers (for FETCH BODY)
		literalContent := s.literalBuffer.String()
		metadata := &types.EmailMetadata{
			Protocol: "IMAP",
			IsServer: s.isFromServer,
		}

		// Try to extract email headers from literal
		s.parser.ParseLine(literalContent, metadata, s.isFromServer)

		// Emit the literal content
		if s.factory != nil && s.factory.handler != nil {
			s.factory.handler.HandleIMAPLine(literalContent, metadata, s.sessionID, s.flow)
		}

		s.literalBuffer.Reset()
	}
}

// scanInt parses an integer from a string.
func scanInt(s string, result *int) (int, error) {
	var v int
	n, err := sscanf(s, "%d", &v)
	if err == nil && n == 1 {
		*result = v
	}
	return n, err
}

// sscanf is a simple scanf implementation for integers.
func sscanf(s string, format string, args ...interface{}) (int, error) {
	if format != "%d" || len(args) != 1 {
		return 0, nil
	}
	var v int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		} else {
			break
		}
	}
	if ptr, ok := args[0].(*int); ok {
		*ptr = v
		return 1, nil
	}
	return 0, nil
}

// createIMAPStream creates a new IMAP stream.
func createIMAPStream(
	reader *tcpreader.ReaderStream,
	ctx context.Context,
	factory *imapStreamFactory,
	flow gopacket.Flow,
	reverseFlow gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *IMAPStream {
	return &IMAPStream{
		reader:       reader,
		ctx:          ctx,
		factory:      factory,
		flow:         flow,
		reverseFlow:  reverseFlow,
		isFromServer: isFromServer,
		sessionID:    sessionID,
		createdAt:    time.Now(),
		parser:       NewIMAPParser(),
	}
}
