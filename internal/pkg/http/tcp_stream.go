//go:build cli || all

package http

import (
	"bufio"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// HTTPStream represents a TCP stream that processes HTTP protocol.
type HTTPStream struct {
	reader       *tcpreader.ReaderStream
	safeReader   *safeHTTPReader
	ctx          context.Context
	factory      *httpStreamFactory
	flow         gopacket.Flow
	reverseFlow  gopacket.Flow
	createdAt    time.Time
	isFromServer bool
	sessionID    string
	parser       *Parser

	// Body capture state
	bodyBuffer     strings.Builder     // Accumulated body content
	bodySize       int                 // Total body size seen
	bodyTruncated  bool                // Body exceeded max size
	inBodyMode     bool                // True when past headers
	contentLength  int64               // Expected body size (from Content-Length)
	chunkedMode    bool                // True if Transfer-Encoding: chunked
	headerMetadata *types.HTTPMetadata // Metadata from headers
}

// safeHTTPReader wraps a tcpreader.ReaderStream to provide interruptible reads.
type safeHTTPReader struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	bufReader  *bufio.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	copyDone   chan struct{}
	closeOnce  sync.Once
}

func newSafeHTTPReader(reader *tcpreader.ReaderStream, ctx context.Context) *safeHTTPReader {
	pipeReader, pipeWriter := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)

	sr := &safeHTTPReader{
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

func (sr *safeHTTPReader) ReadLine() (string, error) {
	if sr.ctx.Err() != nil {
		return "", sr.ctx.Err()
	}
	return sr.bufReader.ReadString('\n')
}

func (sr *safeHTTPReader) Read(p []byte) (int, error) {
	if sr.ctx.Err() != nil {
		return 0, sr.ctx.Err()
	}
	return sr.bufReader.Read(p)
}

func (sr *safeHTTPReader) close() {
	sr.closeOnce.Do(func() {
		sr.cancel()
		sr.pipeReader.Close()
	})
}

func (s *HTTPStream) run() {
	logger.Debug("HTTP stream starting",
		"flow", s.flow.String(),
		"is_from_server", s.isFromServer)

	s.safeReader = newSafeHTTPReader(s.reader, s.ctx)

	defer func() {
		s.safeReader.close()

		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		logger.Debug("HTTP stream completed",
			"flow", s.flow.String(),
			"duration", time.Since(s.createdAt))
	}()

	// Process HTTP messages
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read request/response line
		line, err := s.safeReader.ReadLine()
		if err != nil {
			if err != io.EOF && s.ctx.Err() == nil {
				logger.Debug("HTTP stream read error", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		// Parse as request or response
		metadata := &types.HTTPMetadata{
			SessionID: s.sessionID,
			Headers:   make(map[string]string),
		}

		if s.parser.ParseLine(line, metadata, s.isFromServer) {
			// Read headers
			s.readHeaders(metadata)

			// Check for body
			if s.shouldReadBody(metadata) && s.factory != nil && s.factory.captureBody {
				s.readBody(metadata)
			}

			// Notify handler
			if s.factory != nil && s.factory.handler != nil {
				s.factory.handler.HandleHTTPMessage(metadata, s.sessionID, s.flow)
			}
		}
	}
}

// readHeaders reads HTTP headers until empty line.
func (s *HTTPStream) readHeaders(metadata *types.HTTPMetadata) {
	for i := 0; i < 100; i++ { // Limit header count
		line, err := s.safeReader.ReadLine()
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// End of headers
			return
		}

		s.parser.ParseLine(line, metadata, s.isFromServer)
	}
}

// shouldReadBody determines if we should read the body.
func (s *HTTPStream) shouldReadBody(metadata *types.HTTPMetadata) bool {
	// Only read body for responses with content
	if metadata.Type == "response" {
		// No body for 1xx, 204, 304
		if metadata.StatusCode < 200 || metadata.StatusCode == 204 || metadata.StatusCode == 304 {
			return false
		}
	}

	// Check Content-Length or Transfer-Encoding
	if metadata.ContentLength > 0 {
		return true
	}

	if te, ok := metadata.Headers["transfer-encoding"]; ok {
		if strings.Contains(strings.ToLower(te), "chunked") {
			return true
		}
	}

	return false
}

// readBody reads the HTTP body.
func (s *HTTPStream) readBody(metadata *types.HTTPMetadata) {
	maxBodySize := 64 * 1024 // Default 64KB
	if s.factory != nil && s.factory.maxBodySize > 0 {
		maxBodySize = s.factory.maxBodySize
	}

	var bodyBuilder strings.Builder
	var totalSize int

	// Check for chunked encoding
	if te, ok := metadata.Headers["transfer-encoding"]; ok && strings.Contains(strings.ToLower(te), "chunked") {
		s.readChunkedBody(&bodyBuilder, &totalSize, maxBodySize)
	} else if metadata.ContentLength > 0 {
		s.readFixedBody(&bodyBuilder, &totalSize, maxBodySize, metadata.ContentLength)
	}

	metadata.BodyPreview = bodyBuilder.String()
	metadata.BodySize = totalSize
	metadata.BodyTruncated = totalSize > maxBodySize
}

// readFixedBody reads a fixed-length body.
func (s *HTTPStream) readFixedBody(builder *strings.Builder, totalSize *int, maxSize int, length int64) {
	remaining := length
	buf := make([]byte, 4096)

	for remaining > 0 {
		toRead := int(remaining)
		if toRead > len(buf) {
			toRead = len(buf)
		}

		n, err := s.safeReader.Read(buf[:toRead])
		if n > 0 {
			*totalSize += n
			remaining -= int64(n)

			if builder.Len() < maxSize {
				toWrite := n
				if builder.Len()+toWrite > maxSize {
					toWrite = maxSize - builder.Len()
				}
				builder.Write(buf[:toWrite])
			}
		}
		if err != nil {
			return
		}
	}
}

// readChunkedBody reads a chunked transfer-encoded body.
func (s *HTTPStream) readChunkedBody(builder *strings.Builder, totalSize *int, maxSize int) {
	for {
		// Read chunk size line
		line, err := s.safeReader.ReadLine()
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		// Parse chunk size (hex)
		size, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil || size < 0 {
			return
		}

		if size == 0 {
			// Last chunk
			// Read trailing CRLF
			_, _ = s.safeReader.ReadLine()
			return
		}

		// Read chunk data
		remaining := size
		buf := make([]byte, 4096)
		for remaining > 0 {
			toRead := int(remaining)
			if toRead > len(buf) {
				toRead = len(buf)
			}

			n, err := s.safeReader.Read(buf[:toRead])
			if n > 0 {
				*totalSize += n
				remaining -= int64(n)

				if builder.Len() < maxSize {
					toWrite := n
					if builder.Len()+toWrite > maxSize {
						toWrite = maxSize - builder.Len()
					}
					builder.Write(buf[:toWrite])
				}
			}
			if err != nil {
				return
			}
		}

		// Read trailing CRLF after chunk
		_, _ = s.safeReader.ReadLine()
	}
}

// createHTTPStream creates a new HTTP stream.
func createHTTPStream(
	reader *tcpreader.ReaderStream,
	ctx context.Context,
	factory *httpStreamFactory,
	flow gopacket.Flow,
	reverseFlow gopacket.Flow,
	isFromServer bool,
	sessionID string,
) *HTTPStream {
	return &HTTPStream{
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
