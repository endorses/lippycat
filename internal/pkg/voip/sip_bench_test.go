package voip

import (
	"testing"
)

// BenchmarkParseSipHeaders benchmarks the optimized SIP header parsing
func BenchmarkParseSipHeaders(b *testing.B) {
	sipMessage := []byte(`INVITE sip:robb@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Robb <sip:robb@biloxi.com>
From: Alicent <sip:alicent@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alicent@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alicent 2890844526 2890844526 IN IP4 pc33.atlanta.com
s=Session SDP
c=IN IP4 pc33.atlanta.com
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseSipHeaders(sipMessage)
	}
}

// BenchmarkParseSipHeaders_LargeMessage benchmarks parsing of large SIP messages
func BenchmarkParseSipHeaders_LargeMessage(b *testing.B) {
	// Build a large SIP message with many headers
	base := `INVITE sip:robb@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Robb <sip:robb@biloxi.com>
From: Alicent <sip:alicent@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alicent@pc33.atlanta.com>
Content-Type: application/sdp
User-Agent: lippycat/1.0
Allow: INVITE, ACK, CANCEL, BYE, OPTIONS
Supported: replaces, timer
Session-Expires: 1800
Min-SE: 90
Accept: application/sdp
Accept-Encoding: gzip
Accept-Language: en
P-Asserted-Identity: "Alicent" <sip:alicent@atlanta.com>
Privacy: none
Require: timer
Proxy-Require: sec-agree
Security-Client: digest
Security-Server: digest
Security-Verify: digest
Content-Length: 300

v=0
o=alicent 2890844526 2890844526 IN IP4 pc33.atlanta.com
s=Session SDP
c=IN IP4 pc33.atlanta.com
t=0 0
m=audio 49170 RTP/AVP 0 8 97
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:97 iLBC/8000
a=sendrecv
a=ptime:20
m=video 51372 RTP/AVP 31 32
a=rtpmap:31 H261/90000
a=rtpmap:32 MPV/90000`

	sipMessage := []byte(base)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseSipHeaders(sipMessage)
	}
}

// BenchmarkParseHeaderLineBytes benchmarks the byte-based header parsing
func BenchmarkParseHeaderLineBytes(b *testing.B) {
	header := []byte("Call-ID: a84b4c76e66710@pc33.atlanta.com")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseHeaderLineBytes(header)
	}
}

// BenchmarkParseHeaderLine_CompactForm benchmarks compact header normalization
func BenchmarkParseHeaderLine_CompactForm(b *testing.B) {
	header := []byte("i: a84b4c76e66710@pc33.atlanta.com")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseHeaderLineBytes(header)
	}
}
