package pipeline

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func TestSIPResultFromEventPreservesDuplicateReliableHeaders(t *testing.T) {
	event, err := sip.Parse([]byte("SIP/2.0 183 Progress\r\nCSeq: 1 INVITE\r\ncSeQ: 1 INVITE\r\nRequire: timer\r\nRequire: 100rel\r\nRSeq: 101\r\nrSeQ: 101\r\nRAck: 101 1 INVITE\r\nrAcK: 101 1 INVITE\r\nContent-Length: 0\r\n\r\n"), sip.ParseOptions{})
	require.NoError(t, err)
	result := SIPResultFromEvent(event, nil)
	require.Equal(t, sip.ReliableHeaderDuplicates{CSeq: true, RSeq: true, RAck: true}, result.DuplicateReliableHeaders)
	require.Equal(t, "INVITE", result.CSeqMethod)
	require.Equal(t, uint64(1), result.CSeqNumber)
	require.Equal(t, "1 INVITE", result.Headers["cseq"])
	require.Equal(t, "timer, 100rel", result.Headers["require"])
	require.False(t, sip.ParseReliableHeaders(result.Headers, result.DuplicateReliableHeaders).ResponseValid)
	event.Headers["cseq"] = "2 BYE"
	require.Equal(t, "1 INVITE", result.Headers["cseq"])
}
