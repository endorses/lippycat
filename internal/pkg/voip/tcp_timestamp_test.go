package voip

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

type fragmentReader struct {
	reader *bytes.Reader
	limit  int
}

func (r *fragmentReader) Read(p []byte) (int, error) {
	if len(p) > r.limit {
		p = p[:r.limit]
	}
	return r.reader.Read(p)
}

func TestStreamChunkReaderPreservesPerMessageTimestamp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstTime, secondTime := time.Unix(10, 0), time.Unix(20, 0)
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 2)}
	stream.dataChan <- streamChunk{data: []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: one\r\nContent-Length: 0\r\n\r\n"), timestamp: firstTime}
	stream.dataChan <- streamChunk{data: []byte("PUBLISH sip:a@b SIP/2.0\r\nCall-ID: two\r\nContent-Length: 0\r\n\r\n"), timestamp: secondTime}
	close(stream.dataChan)
	reader := &streamChunkReader{stream: stream, state: TCPStateOpening}
	buffered := bufio.NewReader(reader)
	for i, want := range []time.Time{firstTime, secondTime} {
		if _, err := stream.readCompleteSipMessageFromReader(buffered); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if got := reader.Timestamp(); got != want {
			t.Fatalf("message %d timestamp = %v, want %v", i, got, want)
		}
	}
}

func TestTCPFramingAcrossFragments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx}
	first := "MESSAGE sip:b@example.test SIP/2.0\r\ni: fragmented-one\r\nl: 3\r\n\r\nabc"
	second := "PUBLISH sip:b@example.test SIP/2.0\r\ni: fragmented-two\r\nl: 0\r\n\r\n"
	reader := bufio.NewReader(&fragmentReader{reader: bytes.NewReader([]byte(first + second)), limit: 7})

	for index, wantCallID := range []string{"fragmented-one", "fragmented-two"} {
		message, err := stream.readCompleteSipMessageFromReader(reader)
		if err != nil {
			t.Fatalf("message %d: %v", index, err)
		}
		event, err := sharedsip.Parse(message, sharedsip.ParseOptions{})
		if err != nil {
			t.Fatalf("message %d parse: %v", index, err)
		}
		if event.CallID != wantCallID {
			t.Fatalf("message %d Call-ID = %q, want %q", index, event.CallID, wantCallID)
		}
	}
	if _, err := reader.Peek(1); err != io.EOF {
		t.Fatalf("reader has trailing data: %v", err)
	}
}
