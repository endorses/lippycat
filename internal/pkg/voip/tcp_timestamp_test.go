package voip

import (
	"bufio"
	"context"
	"testing"
	"time"
)

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
