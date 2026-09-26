//go:build ignore

// This frozen fixture encoder deliberately does not import production packages.
// Fixed nonces are safe only for this public synthetic fixture key.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

const xid = "11111111-1111-4111-8111-111111111111"
const did = "22222222-2222-4222-8222-222222222222"
const zeroTime = "0001-01-01T00:00:00Z"

// Field order and names are the LCX2 v1 JournalRecord JSON schema at 77f7abfe.
type record struct {
	ID                                                    uint64
	DID, XID                                              string
	TaskGeneration, DestinationGeneration, CallGeneration uint64
	CallID                                                string
	AdmittedAt, CapturedAt                                string
	Data                                                  []byte
}

type sequenceContext struct {
	PDUType       uint16
	XID           string
	DomainID      string
	NFID          string
	IPID          string
	CorrelationID uint64
}

func main() {
	out := flag.String("out", "", "explicit fixture output directory")
	flag.Parse()
	if *out == "" {
		panic("-out is required")
	}
	must(os.MkdirAll(filepath.Join(*out, "objects"), 0700))
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	write(*out, "fixture.key", key)

	// Frozen ETSI v0.5 X2 header with Domain/NFID/IPID and sequence 41.
	context := sequenceContext{1, xid, "fixture-domain", "fixture-nf", "fixture-ip", 23}
	pdu := make([]byte, 40)
	binary.BigEndian.PutUint16(pdu[0:2], 5)
	binary.BigEndian.PutUint16(pdu[2:4], 1)
	binary.BigEndian.PutUint16(pdu[12:14], 9) // SIP payload.
	binary.BigEndian.PutUint16(pdu[14:16], 3) // Unknown direction.
	xidBytes, err := hex.DecodeString("11111111111141118111111111111111")
	must(err)
	copy(pdu[16:32], xidBytes)
	binary.BigEndian.PutUint64(pdu[32:40], context.CorrelationID)
	for i, value := range []string{context.DomainID, context.NFID, context.IPID, "\x00\x00\x00\x29"} {
		pdu = binary.BigEndian.AppendUint16(pdu, uint16(5+i))
		pdu = binary.BigEndian.AppendUint16(pdu, uint16(len(value)))
		pdu = append(pdu, value...)
	}
	payload := []byte("BYE sip:fixture@example.invalid SIP/2.0\r\nCall-ID: synthetic-call@example.invalid\r\n\r\n")
	binary.BigEndian.PutUint32(pdu[4:8], uint32(len(pdu)))
	binary.BigEndian.PutUint32(pdu[8:12], uint32(len(payload)))
	pdu = append(pdu, payload...)
	write(*out, "product.hex", []byte(hex.EncodeToString(pdu)+"\n"))

	product := record{7, did, xid, 3, 5, 9, "synthetic-call@example.invalid", "2026-01-02T03:04:05.006Z", "2026-01-02T03:04:04.005Z", pdu}
	write(*out, "objects/00000000000000000007.x2", seal(aead, product, 1))
	checkpoint := struct {
		Context sequenceContext
		Next    uint32
	}{context, 42}
	contextHash := sha256.Sum256(marshal(context))
	sequence := emptyRecord()
	sequence.Data = marshal(checkpoint)
	write(*out, "objects/"+hex.EncodeToString(contextHash[:])+".seq", seal(aead, sequence, 2))
	state := emptyRecord()
	state.ID = 11 // Deleted records must not let the next record reuse this ID.
	write(*out, "objects/.state", seal(aead, state, 3))
}

func emptyRecord() record {
	return record{DID: "00000000-0000-0000-0000-000000000000", XID: "00000000-0000-0000-0000-000000000000", AdmittedAt: zeroTime, CapturedAt: zeroTime}
}

func seal(aead cipher.AEAD, r record, nonceByte byte) []byte {
	nonce := make([]byte, 12)
	nonce[11] = nonceByte
	header := []byte("LCX2\x01")
	result := append(append([]byte(nil), header...), nonce...)
	result = aead.Seal(result, nonce, marshal(r), header)
	return binary.BigEndian.AppendUint32(result, crc32.ChecksumIEEE(result))
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	must(err)
	return b
}

func write(dir, name string, b []byte) {
	must(os.WriteFile(filepath.Join(dir, name), b, 0600))
	fmt.Printf("%x  %s\n", sha256.Sum256(b), name)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
