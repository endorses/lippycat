package sip

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReliableHeadersNumericAndMethodBounds(t *testing.T) {
	for _, test := range []struct {
		name, cseq, require, rseq, rack string
		response, answer                bool
	}{
		{"response", "1 INVITE", "timer, 100rel", "101", "", true, false},
		{"zero cseq", "0 INVITE", "100rel", "1", "", true, false},
		{"max initial", "2147483647 INVITE", "100rel", "2147483647", "", true, false},
		{"subsequent uint32", "1 INVITE", "100rel", "4294967295", "", true, false},
		{"missing require", "1 INVITE", "", "101", "", false, false},
		{"malformed require", "1 INVITE", "100rel,", "101", "", false, false},
		{"zero rseq", "1 INVITE", "100rel", "0", "", false, false},
		{"overflow rseq", "1 INVITE", "100rel", "4294967296", "", false, false},
		{"signed rseq", "1 INVITE", "100rel", "+101", "", false, false},
		{"duplicate rseq", "1 INVITE", "100rel", "101, 101", "", false, false},
		{"overflow cseq", "2147483648 INVITE", "100rel", "101", "", false, false},
		{"lowercase method", "1 invite", "100rel", "101", "", false, false},
		{"answer", "2 PRACK", "", "", "101 1 INVITE", false, true},
		{"zero referenced cseq", "1 PRACK", "", "", "1 0 INVITE", false, true},
		{"max referenced cseq", "2147483647 PRACK", "", "", "4294967295 2147483647 INVITE", false, true},
		{"wrong referenced method", "2 PRACK", "", "", "101 1 UPDATE", false, false},
		{"lowercase referenced method", "2 PRACK", "", "", "101 1 invite", false, false},
		{"missing rack", "2 PRACK", "", "", "", false, false},
		{"extra rack fields", "2 PRACK", "", "", "101 1 INVITE extra", false, false},
		{"overflow rack cseq", "2 PRACK", "", "", "101 2147483648 INVITE", false, false},
		{"overflow own cseq", "2147483648 PRACK", "", "", "101 1 INVITE", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := ParseReliableHeaders(map[string]string{"cseq": test.cseq, "require": test.require, "rseq": test.rseq, "rack": test.rack})
			require.Equal(t, test.response, proof.ResponseValid)
			require.Equal(t, test.answer, proof.RAckValid)
		})
	}
}

func TestReliableHeadersParserPreservesAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name, extra      string
		response, answer bool
	}{
		{"require list", "Require: timer\r\nRequire: 100rel\r\nRSeq: 101\r\n", true, false},
		{"folded require", "Require: timer,\r\n 100rel\r\nRSeq: 101\r\n", true, false},
		{"duplicate rseq", "Require: 100rel\r\nRSeq: 9\r\nRSeq: 101\r\n", false, false},
		{"duplicate cseq", "Require: 100rel\r\nRSeq: 101\r\nCSeq: 1 INVITE\r\n", false, false},
		{"duplicate rack", "RAck: 9 1 INVITE\r\nRAck: 101 1 INVITE\r\n", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			start, cseq := "SIP/2.0 183 Progress", "1 INVITE"
			if test.name == "duplicate rack" {
				start, cseq = "PRACK sip:peer@example.invalid SIP/2.0", "2 PRACK"
			}
			event, err := Parse([]byte(fmt.Sprintf("%s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n", start, cseq, test.extra)), ParseOptions{})
			require.NoError(t, err)
			proof := ParseReliableHeaders(event.Headers)
			require.Equal(t, test.response, proof.ResponseValid)
			require.Equal(t, test.answer, proof.RAckValid)
		})
	}
}

func TestSDPHighestRTPPortExplicitRTCPAndMux(t *testing.T) {
	for _, attribute := range []string{"a=rtcp-mux", "a=rtcp-mux-only", "a=rtcp:65534", "a=rtcp:65534 IN IP4 192.0.2.2"} {
		t.Run(attribute, func(t *testing.T) {
			parsed := ParseSDPResult("c=IN IP4 192.0.2.1\r\nm=audio 65535 RTP/AVP 0\r\n"+attribute+"\r\n", 32)
			require.True(t, parsed.Complete)
			require.Equal(t, "192.0.2.1:65535", parsed.Endpoints[0].Address.String())
			if attribute == "a=rtcp-mux" || attribute == "a=rtcp-mux-only" {
				require.Len(t, parsed.Endpoints, 1)
			} else {
				require.Len(t, parsed.Endpoints, 2)
			}
		})
	}
}
