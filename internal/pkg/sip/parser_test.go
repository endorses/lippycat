package sip

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestParseCorpus(t *testing.T) {
	ts := time.Unix(123, 456)
	sdp := "v=0\r\nm=audio 49170 RTP/AVP 0\r\n"
	msg := "PUBLISH sip:alice@example.test SIP/2.0\r\ni: call-1\r\nf: <sip:alice@example.test>;tag=from-tag\r\nt: <sips:bob@example.test>;tag=to-tag\r\nCSeq: 9 PUBLISH\r\nc: application/sdp\r\nl: " + strconv.Itoa(len(sdp)) + "\r\n\r\n" + sdp
	ev, err := Parse([]byte(msg), ParseOptions{Timestamp: ts, SourceIP: "192.0.2.1", SourcePort: 5060})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Method != "PUBLISH" || ev.CallID != "call-1" || ev.CSeqMethod != "PUBLISH" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.FromUser != "alice" || ev.ToUser != "bob" || ev.FromTag != "from-tag" || ev.ToTag != "to-tag" {
		t.Fatalf("bad identity extraction: %+v", ev)
	}
	if ev.ContentType != "application/sdp" || string(ev.Body) != sdp || ev.Timestamp != ts {
		t.Fatalf("body/provenance lost: %+v", ev)
	}
}

func TestResponses(t *testing.T) {
	for _, tc := range []struct {
		line string
		code int
	}{{"SIP/2.0 180 Ringing", 180}, {"SIP/2.0 200 OK", 200}} {
		ev, err := Parse([]byte(tc.line+"\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"), ParseOptions{})
		if err != nil || ev.ResponseCode != tc.code || ev.CSeqMethod != "INVITE" {
			t.Fatalf("%q: %+v, %v", tc.line, ev, err)
		}
	}
}

func TestMalformedLength(t *testing.T) {
	_, err := Parse([]byte("MESSAGE sip:a@b SIP/2.0\r\nContent-Length: 5\r\n\r\nabc"), ParseOptions{})
	if !errors.Is(err, ErrMalformedContentLength) {
		t.Fatalf("got %v", err)
	}
}

func TestMethodTableIncludesPublish(t *testing.T) {
	if !IsStartLine("PUBLISH sip:a@b SIP/2.0") {
		t.Fatal("PUBLISH rejected")
	}
}

func TestUDPAndReassembledTCPEquivalent(t *testing.T) {
	msg := []byte("INVITE sip:bob@example.test SIP/2.0\r\nf: <sip:alice@example.test>;tag=a\r\nt: <sip:bob@example.test>\r\ni: equivalent-call\r\nCSeq: 7 INVITE\r\nl: 0\r\n\r\n")
	udp, err := Parse(msg, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fragmented := append(append([]byte(nil), msg[:31]...), msg[31:]...)
	tcp, err := Parse(fragmented, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if udp.CallID != tcp.CallID || udp.Method != tcp.Method || udp.CSeqMethod != tcp.CSeqMethod || udp.FromURI != tcp.FromURI || udp.FromTag != tcp.FromTag {
		t.Fatalf("UDP/TCP metadata differ: udp=%+v tcp=%+v", udp, tcp)
	}
}

func TestPipelinedInputHonorsFirstContentLength(t *testing.T) {
	first := "MESSAGE sip:b@example.test SIP/2.0\r\nCall-ID: one\r\nContent-Length: 3\r\n\r\nabc"
	second := "BYE sip:b@example.test SIP/2.0\r\nCall-ID: two\r\nContent-Length: 0\r\n\r\n"
	event, err := Parse([]byte(first+second), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if event.CallID != "one" || string(event.Body) != "abc" {
		t.Fatalf("pipelined parse leaked messages: %+v", event)
	}
}
