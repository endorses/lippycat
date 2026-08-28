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
	ev, err := Parse([]byte(msg), ParseOptions{
		Timestamp: ts, SourceIP: "192.0.2.1", DestinationIP: "198.51.100.2",
		SourcePort: 5060, DestinationPort: 5061,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Method != "PUBLISH" || ev.CallID != "call-1" || ev.CSeqMethod != "PUBLISH" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.FromUser != "alice" || ev.ToUser != "bob" || ev.FromTag != "from-tag" || ev.ToTag != "to-tag" {
		t.Fatalf("bad identity extraction: %+v", ev)
	}
	if ev.ContentType != "application/sdp" || string(ev.Body) != sdp || string(ev.SDP) != sdp || ev.Timestamp != ts {
		t.Fatalf("body/provenance lost: %+v", ev)
	}
	if ev.SourceIP != "192.0.2.1" || ev.DestinationIP != "198.51.100.2" || ev.SourcePort != 5060 || ev.DestinationPort != 5061 {
		t.Fatalf("endpoint provenance lost: %+v", ev)
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

func TestRejectsInvalidResponseStatus(t *testing.T) {
	for _, code := range []string{"099", "700", "999"} {
		_, err := Parse([]byte("SIP/2.0 "+code+" Invalid\r\nContent-Length: 0\r\n\r\n"), ParseOptions{})
		if !errors.Is(err, ErrNotSIP) {
			t.Fatalf("status %s: got %v", code, err)
		}
	}
}

func TestMalformedLength(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length string
		body   string
	}{
		{"truncated", "5", "abc"},
		{"nonnumeric", "abc", ""},
		{"negative", "-1", ""},
		{"oversized", strconv.Itoa(MaxMessageSize + 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte("MESSAGE sip:a@b SIP/2.0\r\nContent-Length: "+tc.length+"\r\n\r\n"+tc.body), ParseOptions{})
			if !errors.Is(err, ErrMalformedContentLength) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDuplicateContentLengthPolicy(t *testing.T) {
	equal := []byte("MESSAGE sip:a@b SIP/2.0\r\nContent-Length: 3\r\nl: 3\r\n\r\nabc")
	ev, err := Parse(equal, ParseOptions{})
	if err != nil || string(ev.Body) != "abc" {
		t.Fatalf("equal duplicate lengths: event=%+v err=%v", ev, err)
	}

	conflicting := []byte("MESSAGE sip:a@b SIP/2.0\r\nContent-Length: 3\r\nl: 2\r\n\r\nabc")
	_, err = Parse(conflicting, ParseOptions{})
	if !errors.Is(err, ErrMalformedContentLength) {
		t.Fatalf("conflicting duplicate lengths: got %v", err)
	}
}

func TestFoldedHeadersAreUnfolded(t *testing.T) {
	msg := []byte("INVITE sip:b@x SIP/2.0\r\nFrom: <sip:alice@example.test>;\r\n\ttag=folded\r\nTo: <sip:bob@example.test>\r\nP-Asserted-Identity: <sip:alice@\r\n example.test>\r\nContent-Length: 0\r\n\r\n")
	ev, err := Parse(msg, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.FromTag != "folded" || ev.PAssertedIdentity != "<sip:alice@ example.test>" {
		t.Fatalf("folded headers not unfolded: %+v", ev)
	}
}

func TestSDPClassificationUsesContentType(t *testing.T) {
	sdp := "v=0\r\nm=audio 49170 RTP/AVP 0\r\n"
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		wantSDP     bool
	}{
		{"parameters and case", "Application/SDP; charset=UTF-8", sdp, true},
		{"SDP without media line", "application/sdp", "v=0\r\ns=session\r\n", true},
		{"non-SDP with media-like text", "text/plain", "m=not-sdp", false},
		{"missing content type", "", sdp, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := ""
			if tc.contentType != "" {
				header = "Content-Type: " + tc.contentType + "\r\n"
			}
			msg := "MESSAGE sip:a@b SIP/2.0\r\n" + header + "Content-Length: " + strconv.Itoa(len(tc.body)) + "\r\n\r\n" + tc.body
			ev, err := Parse([]byte(msg), ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if (len(ev.SDP) > 0) != tc.wantSDP {
				t.Fatalf("SDP=%q, want classified=%v", ev.SDP, tc.wantSDP)
			}
		})
	}
}

func TestMethodTableIncludesPublish(t *testing.T) {
	if !IsStartLine("PUBLISH sip:a@b SIP/2.0") {
		t.Fatal("PUBLISH rejected")
	}
}

func TestIdentityCompactHeader(t *testing.T) {
	msg := []byte("INVITE sip:b@x SIP/2.0\r\ny: signed-identity\r\nContent-Length: 0\r\n\r\n")
	event, err := Parse(msg, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if event.Headers["identity"] != "signed-identity" {
		t.Fatalf("identity compact header not normalized: %+v", event.Headers)
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
