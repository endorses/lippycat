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

// This literal is intentionally independent of the encoder constants. It is a
// 48-byte keepalive-ack header with a sole sequence-number attribute (42).
var goldenKeepaliveAck42 = []byte{
	0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x30,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2a,
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
		want []byte
	}{
		{"x2_sip_invite.hex", buildGoldenX2(1, PayloadDirectionFromTarget, goldenINVITE), nil},
		{"x2_sip_bye.hex", buildGoldenX2(2, PayloadDirectionToTarget, goldenBYE), nil},
		{"x2_sip_message.hex", buildGoldenX2(3, PayloadDirectionFromTarget, goldenMESSAGE), nil},
		{"x3_rtp.hex", buildGoldenX3(4, PayloadDirectionFromTarget, goldenRTP), nil},
		{"keepalive.hex", NewKeepalivePDU(), nil},
		{"keepalive_ack_literal", NewKeepaliveAckPDU(42), goldenKeepaliveAck42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == nil {
				want = loadVector(t, tc.name)
			}
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
	cases := []struct {
		name        string
		wire        []byte
		wantType    PDUType
		wantFormat  PayloadFormat
		wantDir     PayloadDirection
		wantXID     uuid.UUID
		wantCorr    uint64
		wantPayload []byte
	}{
		{"x2_sip_invite.hex", nil, PDUTypeX2, PayloadFormatSIP, PayloadDirectionFromTarget, goldenXID, goldenCorr, []byte(goldenINVITE)},
		{"x2_sip_bye.hex", nil, PDUTypeX2, PayloadFormatSIP, PayloadDirectionToTarget, goldenXID, goldenCorr, []byte(goldenBYE)},
		{"x2_sip_message.hex", nil, PDUTypeX2, PayloadFormatSIP, PayloadDirectionFromTarget, goldenXID, goldenCorr, []byte(goldenMESSAGE)},
		{"x3_rtp.hex", nil, PDUTypeX3, PayloadFormatRTP, PayloadDirectionFromTarget, goldenXID, goldenCorr, goldenRTP},
		{"keepalive.hex", nil, PDUTypeKeepalive, PayloadFormatKeepalive, PayloadDirectionKeepalive, uuid.Nil, 0, nil},
		{"keepalive_ack_literal", goldenKeepaliveAck42, PDUTypeKeepaliveAck, PayloadFormatKeepalive, PayloadDirectionKeepalive, uuid.Nil, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.wire
			if wire == nil {
				wire = loadVector(t, tc.name)
			}
			var pdu PDU
			if err := pdu.UnmarshalBinary(wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if pdu.Header.Version != 0x0005 {
				t.Errorf("version = %#04x, want 0x0005", pdu.Header.Version)
			}
			if pdu.Header.Type != tc.wantType {
				t.Errorf("pdu type = %v, want %v", pdu.Header.Type, tc.wantType)
			}
			if pdu.Header.PayloadFormat != tc.wantFormat {
				t.Errorf("payload format = %v, want %v", pdu.Header.PayloadFormat, tc.wantFormat)
			}
			if pdu.Header.PayloadDirection != tc.wantDir {
				t.Errorf("payload direction = %v, want %v", pdu.Header.PayloadDirection, tc.wantDir)
			}
			if pdu.Header.XID != tc.wantXID {
				t.Errorf("xid = %v, want %v", pdu.Header.XID, tc.wantXID)
			}
			if pdu.Header.CorrelationID != tc.wantCorr {
				t.Errorf("correlation ID = %x, want %x", pdu.Header.CorrelationID, tc.wantCorr)
			}
			if !bytesEqual(pdu.Payload, tc.wantPayload) {
				t.Errorf("payload = %x, want %x", pdu.Payload, tc.wantPayload)
			}
			if tc.wantType == PDUTypeX2 {
				target := FindAttribute(pdu.Attributes, AttrMatchedTargetIdentifier)
				if target == nil || string(target.Value) != "sip:alice@example.com" {
					t.Errorf("matched target = %v, want sip:alice@example.com", target)
				}
			}
		})
	}

	var ack PDU
	if err := ack.UnmarshalBinary(goldenKeepaliveAck42); err != nil {
		t.Fatalf("decode keepalive ack sequence: %v", err)
	}
	if seq, err := ack.KeepaliveSequence(); err != nil || seq != 42 {
		t.Errorf("keepalive ack sequence = %d, err = %v; want 42", seq, err)
	}
}
