package sip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReliableHeaderEvidenceValidatedSemanticDuplicates(t *testing.T) {
	for _, test := range []struct {
		name, headers    string
		response, answer bool
		conflicts        ReliableHeaderConflicts
	}{
		{"identical response", "CSeq: 1 INVITE\r\ncSeQ: 01\tINVITE\r\nRequire: timer\r\nRequire: 100rel\r\nRSeq: 101\r\nrSeQ: 0101\r\n", true, false, ReliableHeaderConflicts{}},
		{"identical answer", "CSeq: 2 PRACK\r\nCSeq: 02 PRACK\r\nRAck: 101 1 INVITE\r\nRAck: 0101\t01 INVITE\r\n", false, true, ReliableHeaderConflicts{}},
		{"folded identical", "CSeq: 1\r\n INVITE\r\nCSeq: 01 INVITE\r\nRequire: timer,\r\n 100rel\r\nRSeq: 101\r\nRSeq: 0101\r\n", true, false, ReliableHeaderConflicts{}},
		{"conflicting response", "CSeq: 1 INVITE\r\nRequire: 100rel\r\nRSeq: 9\r\nRSeq: 101\r\n", false, false, ReliableHeaderConflicts{RSeq: true}},
		{"conflicting answer", "CSeq: 2 PRACK\r\nRAck: 101 1 INVITE\r\nRAck: 101 2 INVITE\r\n", false, false, ReliableHeaderConflicts{RAck: true}},
		{"invalid earlier rseq", "CSeq: 1 INVITE\r\nRequire: 100rel\r\nRSeq: +101\r\nRSeq: 101\r\n", false, false, ReliableHeaderConflicts{RSeq: true}},
		{"invalid earlier rack", "CSeq: 2 PRACK\r\nRAck: 101 1 INVITE extra\r\nRAck: 101 1 INVITE\r\n", false, false, ReliableHeaderConflicts{RAck: true}},
		{"invalid identical", "CSeq: 1 INVITE\r\nRequire: 100rel\r\nRSeq: 0\r\nRSeq: 0\r\n", false, false, ReliableHeaderConflicts{RSeq: true}},
		{"case sensitive method", "CSeq: 1 invite\r\nCSeq: 1 INVITE\r\nRequire: 100rel\r\nRSeq: 101\r\n", false, false, ReliableHeaderConflicts{CSeq: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := "SIP/2.0 183 Progress"
			if test.answer || test.conflicts.RAck {
				start = "PRACK sip:peer@example.invalid SIP/2.0"
			}
			event, err := Parse([]byte(start+"\r\n"+test.headers+"Content-Length: 0\r\n\r\n"), ParseOptions{})
			require.NoError(t, err)
			require.Equal(t, test.conflicts, event.ReliableHeaderEvidence.Conflicts)
			proof := ParseReliableHeadersWithEvidence(event.Headers, event.ReliableHeaderEvidence)
			require.Equal(t, test.response, proof.ResponseValid)
			require.Equal(t, test.answer, proof.RAckValid)
		})
	}
}

func TestCSeqEvidenceBoundsAndLastLineClassification(t *testing.T) {
	for _, test := range []struct {
		name, first, last                                  string
		min, max                                           uint32
		valid, bounds, conflict, methodConflict, malformed bool
	}{
		{"same number", "001 INVITE", "1 INVITE", 1, 1, true, true, false, false, false},
		{"ascending", "3 INVITE", "9 INVITE", 3, 9, false, true, true, false, false},
		{"descending", "9 INVITE", "3 INVITE", 3, 9, false, true, true, false, false},
		{"method conflict", "3 INVITE", "9 UPDATE", 3, 9, false, false, true, true, false},
		{"invalid first", "+3 INVITE", "9 BYE", 9, 9, false, false, true, false, true},
		{"invalid last", "3 INVITE", "2147483648 BYE", 3, 3, false, false, true, false, true},
		{"invalid both", "-3 INVITE", "+9 BYE", 0, 0, false, false, true, false, true},
		{"extra field", "3 INVITE extra", "9 BYE", 9, 9, false, false, true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			event, err := Parse([]byte("SIP/2.0 200 OK\r\nCSeq: "+test.first+"\r\nCSeq: "+test.last+"\r\nContent-Length: 0\r\n\r\n"), ParseOptions{})
			require.NoError(t, err)
			evidence := event.ReliableHeaderEvidence
			require.Equal(t, test.last, event.Headers["cseq"])
			require.Equal(t, CSeqMethod(test.last), event.CSeqMethod)
			require.True(t, event.DuplicateReliableHeaders.CSeq)
			require.Equal(t, test.min, evidence.CSeqMin)
			require.Equal(t, test.max, evidence.CSeqMax)
			require.Equal(t, test.valid, evidence.CSeqValid)
			require.Equal(t, test.bounds, evidence.CSeqBoundsValid)
			require.Equal(t, test.conflict, evidence.Conflicts.CSeq)
			require.Equal(t, test.methodConflict, evidence.CSeqMethodConflict)
			require.Equal(t, test.malformed, evidence.CSeqMalformed)
		})
	}
}
