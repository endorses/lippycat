package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSniffSIPFlowRegistersAndDrainsOutputSink(t *testing.T) {
	flow := newSniffSIPFlow(&CallTracker{}, false, false)

	analysis := flow.Analyze(sipflow.Message{
		Payload: []byte("INVITE sip:bob@example.com SIP/2.0\r\n" +
			"From: <sip:alice@example.com>;tag=from\r\n" +
			"To: <sip:bob@example.com>\r\n" +
			"Call-ID: sniff-sink-test\r\n" +
			"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"),
		ParseOptions:     sharedsip.ParseOptions{},
		FilterConfigured: true,
		DirectMatch:      true,
	})
	require.Equal(t, pipeline.OutcomeAccepted, analysis.Stage.Outcome)

	dispatched := flow.Dispatch(analysis)
	require.Equal(t, pipeline.OutcomeAccepted, dispatched.Sinks[sniffSIPSinkName].Outcome)

	// Close drains accepted work before returning, making the sink result and
	// its metrics observable synchronously to sniff callers.
	flow.Close()
	stats := flow.Stats()[sniffSIPSinkName]
	assert.Equal(t, uint64(1), stats.PermanentFailures)
	assert.Zero(t, stats.Accepted)

	// The sniff lifecycle owns a normal idempotent close.
	flow.Close()
}
