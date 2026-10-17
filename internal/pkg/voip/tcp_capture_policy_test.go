package voip

import (
	"bufio"
	"context"
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestTCPFramingCannotCombineCapturePolicyGenerations(t *testing.T) {
	for _, generations := range [][2]uint64{{1, 2}, {0, 1}, {1, 0}} {
		t.Run(fmt.Sprintf("%d-to-%d", generations[0], generations[1]), func(t *testing.T) {
			stream := &bufferedSIPStream{ctx: context.Background(), dataChan: make(chan streamChunk, 2)}
			first := []byte("OPTIONS sip:a@example.invalid SIP/2.0\r\nCall-ID: old")
			second := []byte("-tail\r\nContent-Length: 0\r\n\r\nOPTIONS sip:a@example.invalid SIP/2.0\r\nCall-ID: current\r\nContent-Length: 0\r\n\r\n")
			stream.dataChan <- streamChunk{data: first, spans: []streamCaptureSpan{{end: len(first), source: pipeline.SourceProvenance{CapturePolicyGeneration: generations[0]}}}}
			stream.dataChan <- streamChunk{data: second, spans: []streamCaptureSpan{{end: len(second), source: pipeline.SourceProvenance{CapturePolicyGeneration: generations[1]}}}}
			close(stream.dataChan)
			reader := &streamChunkReader{stream: stream, state: TCPStateOpening}
			_, err := stream.readCompleteSipMessageFromReader(bufio.NewReader(reader))
			var gap *recoverableFramingError
			require.ErrorAs(t, err, &gap)
			require.Equal(t, "capture policy boundary", gap.reason)
			message, err := stream.readCompleteSipMessageFromReader(bufio.NewReader(reader))
			require.NoError(t, err)
			require.Contains(t, string(message), "Call-ID: current")
			require.NotContains(t, string(message), "old")
			require.Equal(t, generations[1], reader.Source().CapturePolicyGeneration)
		})
	}
}
