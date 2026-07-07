package x2x3

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

// X2/X3 golden conformance vectors (ETSI TS 103 221-2). lippycat must encode
// to exactly these bytes and decode them back into equivalent PDUs, which keeps
// the wire format stable for standards-compliant peers.

func loadVector(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "x2x3", name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()

	var hexStr strings.Builder
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hexStr.WriteString(line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	raw, err := hex.DecodeString(hexStr.String())
	if err != nil {
		t.Fatalf("decode hex %s: %v", name, err)
	}
	return raw
}

var (
	goldenXID  = uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	goldenCorr = uint64(0x1111111111111111)
	goldenTS   = time.Unix(1700000000, 0)
)

// addGoldenCommonAttrs appends the standard conditional attributes in the exact
// order lippycat's encoders + processor emit them.
func addGoldenCommonAttrs(pdu *PDU, seq uint32) {
	b := NewAttributeBuilder()
	pdu.AddAttribute(b.Timestamp(goldenTS))
	pdu.AddAttribute(b.SequenceNumber(seq))
	src, _ := b.SourceIPv4(mustAddr("192.168.1.10"))
	pdu.AddAttribute(src)
	dst, _ := b.DestIPv4(mustAddr("10.0.0.5"))
	pdu.AddAttribute(dst)
	pdu.AddAttribute(b.SourcePort(5060))
	pdu.AddAttribute(b.DestPort(5060))
	pdu.AddAttribute(b.NFID("proc-01"))
	pdu.AddAttribute(b.IPID("hunter-01"))
	pdu.AddAttribute(b.MatchedTargetIdentifier("sip:alice@example.com"))
}

const (
	goldenINVITE = "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Call-ID: call-abc-123@example.com\r\n" +
		"From: <sip:alice@example.com>;tag=aaa\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"CSeq: 1 INVITE\r\n\r\n"
	goldenBYE = "BYE sip:bob@example.com SIP/2.0\r\n" +
		"Call-ID: call-abc-123@example.com\r\n" +
		"From: <sip:alice@example.com>;tag=aaa\r\n" +
		"To: <sip:bob@example.com>;tag=bbb\r\n" +
		"CSeq: 2 BYE\r\n\r\n"
	goldenMESSAGE = "MESSAGE sip:bob@example.com SIP/2.0\r\n" +
		"Call-ID: msg-xyz-789@example.com\r\n" +
		"From: <sip:alice@example.com>;tag=aaa\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 12\r\n\r\n" +
		"Hello world!"
)

var goldenRTP = []byte{
	0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
}

func buildGoldenX2(seq uint32, dir PayloadDirection, sip string) *PDU {
	pdu := NewX2SIPPDU(goldenXID, goldenCorr)
	pdu.Header.PayloadDirection = dir
	addGoldenCommonAttrs(pdu, seq)
	pdu.SetPayload([]byte(sip))
	return pdu
}

func buildGoldenX3(seq uint32, dir PayloadDirection, rtp []byte) *PDU {
	pdu := NewX3RTPPDU(goldenXID, goldenCorr)
	pdu.Header.PayloadDirection = dir
	addGoldenCommonAttrs(pdu, seq)
	pdu.SetPayload(rtp)
	return pdu
}

func TestGoldenVectors_Encode(t *testing.T) {
	cases := []struct {
		name string
		pdu  *PDU
	}{
		{"x2_sip_invite.hex", buildGoldenX2(1, PayloadDirectionFromTarget, goldenINVITE)},
		{"x2_sip_bye.hex", buildGoldenX2(2, PayloadDirectionToTarget, goldenBYE)},
		{"x2_sip_message.hex", buildGoldenX2(3, PayloadDirectionFromTarget, goldenMESSAGE)},
		{"x3_rtp.hex", buildGoldenX3(4, PayloadDirectionFromTarget, goldenRTP)},
		{"keepalive.hex", NewKeepalivePDU()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := loadVector(t, tc.name)
			got, err := tc.pdu.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytesEqual(got, want) {
				t.Fatalf("byte mismatch for %s\n got (%d): %x\nwant (%d): %x",
					tc.name, len(got), got, len(want), want)
			}
		})
	}
}

func TestGoldenVectors_Decode(t *testing.T) {
	raw := loadVector(t, "x2_sip_invite.hex")
	var pdu PDU
	if err := pdu.UnmarshalBinary(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pdu.Header.Type != PDUTypeX2 {
		t.Errorf("pdu type = %v, want X2", pdu.Header.Type)
	}
	if pdu.Header.PayloadFormat != PayloadFormatSIP {
		t.Errorf("payload format = %v, want SIP", pdu.Header.PayloadFormat)
	}
	if pdu.Header.PayloadDirection != PayloadDirectionFromTarget {
		t.Errorf("direction = %v, want FromTarget", pdu.Header.PayloadDirection)
	}
	if pdu.Header.XID != goldenXID {
		t.Errorf("xid = %v, want %v", pdu.Header.XID, goldenXID)
	}
	if pdu.Header.CorrelationID != goldenCorr {
		t.Errorf("corr = %x, want %x", pdu.Header.CorrelationID, goldenCorr)
	}
	if got := string(pdu.Payload); got != goldenINVITE {
		t.Errorf("payload = %q, want INVITE", got)
	}
	if tgt := FindAttribute(pdu.Attributes, AttrMatchedTargetIdentifier); tgt == nil {
		t.Error("missing matched target identifier attribute")
	} else if string(tgt.Value) != "sip:alice@example.com" {
		t.Errorf("matched target = %q", tgt.Value)
	}

	// Keepalive decode.
	kaRaw := loadVector(t, "keepalive.hex")
	var ka PDU
	if err := ka.UnmarshalBinary(kaRaw); err != nil {
		t.Fatalf("unmarshal keepalive: %v", err)
	}
	if ka.Header.Type != PDUTypeKeepalive {
		t.Errorf("keepalive type = %v, want Keepalive", ka.Header.Type)
	}
	if ka.Header.XID != uuid.Nil {
		t.Errorf("keepalive xid = %v, want nil", ka.Header.XID)
	}
}
