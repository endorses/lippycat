//go:build li

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
)

const journalRecordDomain = "lippycat/li-record/v2\x00"
const journalMetadataMax = 80 << 10

var errJournalSchema = errors.New("invalid journal logical version-2 schema")

type recordEncoder struct {
	bytes.Buffer
	err error
}

func (w *recordEncoder) u8(n byte) { w.WriteByte(n) }
func (w *recordEncoder) u16(n uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	w.Write(b[:])
}
func (w *recordEncoder) u32(n uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	w.Write(b[:])
}
func (w *recordEncoder) u64(n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	w.Write(b[:])
}
func (w *recordEncoder) text(s string, limit int) {
	if len(s) > limit || !utf8.ValidString(s) {
		w.err = errJournalSchema
		return
	}
	w.u32(uint32(len(s)))
	w.WriteString(s)
}
func (w *recordEncoder) id(id uuid.UUID) { w.Write(id[:]) }
func (w *recordEncoder) optionalID(id uuid.UUID) {
	if id == uuid.Nil {
		w.u8(0)
	} else {
		w.u8(1)
		w.id(id)
	}
}
func (w *recordEncoder) timestamp(t time.Time) {
	if t.IsZero() {
		w.u8(0)
		return
	}
	if t.Year() < 1 || t.Year() > 9999 {
		w.err = errJournalSchema
		return
	}
	w.u8(1)
	w.u64(uint64(t.Unix()))
	w.u32(uint32(t.Nanosecond()))
}

type recordDecoder struct {
	b   []byte
	err error
}

func (r *recordDecoder) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = errJournalSchema
		return make([]byte, max(0, min(n, 16)))
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *recordDecoder) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *recordDecoder) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *recordDecoder) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *recordDecoder) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *recordDecoder) text(limit int) string {
	n := r.u32()
	if n > uint32(limit) || uint64(n) > uint64(len(r.b)) {
		r.err = errJournalSchema
		return ""
	}
	b := r.take(int(n))
	if !utf8.Valid(b) {
		r.err = errJournalSchema
	}
	return string(b)
}
func (r *recordDecoder) id() (id uuid.UUID) { copy(id[:], r.take(16)); return }
func (r *recordDecoder) optionalID() uuid.UUID {
	switch r.u8() {
	case 0:
		return uuid.Nil
	case 1:
		id := r.id()
		if id == uuid.Nil {
			r.err = errJournalSchema
		}
		return id
	default:
		r.err = errJournalSchema
		return uuid.Nil
	}
}
func (r *recordDecoder) timestamp() time.Time {
	switch r.u8() {
	case 0:
		return time.Time{}
	case 1:
		sec, nano := int64(r.u64()), r.u32()
		t := time.Unix(sec, int64(nano)).UTC()
		if nano >= 1e9 || t.Year() < 1 || t.Year() > 9999 || t.IsZero() {
			r.err = errJournalSchema
		}
		return t
	default:
		r.err = errJournalSchema
		return time.Time{}
	}
}

func provenanceBytes(p li.DeliveryProvenance, iface PDUType) ([]byte, error) {
	var w recordEncoder
	var allowed li.DeliveryProvenance
	switch p.Kind {
	case "legacy_x2":
		if iface != PDUTypeX2 {
			return nil, errJournalSchema
		}
		allowed = li.DeliveryProvenance{Kind: p.Kind, CallID: p.CallID, CallGeneration: p.CallGeneration}
		w.u8(0)
		w.text(p.CallID, 64<<10)
		w.u64(p.CallGeneration)
	case "call":
		if p.CallIncarnation == uuid.Nil || p.CallGeneration == 0 || p.CallID == "" {
			return nil, errJournalSchema
		}
		allowed = li.DeliveryProvenance{Kind: p.Kind, CallIncarnation: p.CallIncarnation, CallGeneration: p.CallGeneration, CallID: p.CallID}
		w.u8(1)
		w.id(p.CallIncarnation)
		w.u64(p.CallGeneration)
		w.text(p.CallID, 64<<10)
	case "non_call":
		if p.OriginNodeID == "" || p.SourceID == "" || p.CaptureEpoch == uuid.Nil || p.ObservationSequence == 0 {
			return nil, errJournalSchema
		}
		allowed = li.DeliveryProvenance{Kind: p.Kind, SourceKind: p.SourceKind, OriginNodeID: p.OriginNodeID, SourceID: p.SourceID, CaptureEpoch: p.CaptureEpoch, ObservationSequence: p.ObservationSequence}
		if p.SourceKind == "rtp" && iface == PDUTypeX3 {
			w.u8(2)
			allowed.Transport = p.Transport
			allowed.SourceAddress = p.SourceAddress
			allowed.DestinationAddress = p.DestinationAddress
			allowed.SourcePort = p.SourcePort
			allowed.DestinationPort = p.DestinationPort
			allowed.SSRC = p.SSRC
			for _, s := range []string{p.SourceAddress, p.DestinationAddress} {
				a, err := netip.ParseAddr(s)
				if err != nil || a.Zone() != "" || a.Unmap().String() != s {
					return nil, errJournalSchema
				}
			}
		} else if p.SourceKind == "radius" && iface == PDUTypeX2 {
			w.u8(3)
			allowed.OperatorScope = p.OperatorScope
			allowed.ProfileRevision = p.ProfileRevision
			allowed.NFID = p.NFID
			allowed.IPID = p.IPID
			allowed.CorrelationID = p.CorrelationID
			if p.OperatorScope == "" || p.ProfileRevision == "" {
				return nil, errJournalSchema
			}
		} else {
			return nil, errJournalSchema
		}
		w.text(p.OriginNodeID, 4096)
		w.text(p.SourceID, 4096)
		w.id(p.CaptureEpoch)
		w.u64(p.ObservationSequence)
		if p.SourceKind == "rtp" {
			w.u8(p.Transport)
			w.text(p.SourceAddress, 64)
			w.text(p.DestinationAddress, 64)
			w.u16(p.SourcePort)
			w.u16(p.DestinationPort)
			w.u32(p.SSRC)
		} else {
			w.text(p.OperatorScope, 4096)
			w.text(p.ProfileRevision, 4096)
			w.text(p.NFID, 4096)
			w.text(p.IPID, 4096)
			w.u64(p.CorrelationID)
		}
	default:
		return nil, errJournalSchema
	}
	if allowed != p || w.err != nil {
		return nil, errJournalSchema
	}
	return w.Bytes(), nil
}
func readProvenance(r *recordDecoder) li.DeliveryProvenance {
	var p li.DeliveryProvenance
	switch r.u8() {
	case 0:
		p.Kind = "legacy_x2"
		p.CallID = r.text(64 << 10)
		p.CallGeneration = r.u64()
	case 1:
		p.Kind = "call"
		p.CallIncarnation = r.id()
		p.CallGeneration = r.u64()
		p.CallID = r.text(64 << 10)
	case 2, 3:
		// The tag was consumed; obtain it from the caller-preserved prefix instead.
		r.err = errJournalSchema
	default:
		r.err = errJournalSchema
	}
	return p
}
func decodeProvenance(r *recordDecoder) li.DeliveryProvenance {
	if len(r.b) == 0 {
		r.err = errJournalSchema
		return li.DeliveryProvenance{}
	}
	tag := r.b[0]
	if tag < 2 {
		return readProvenance(r)
	}
	r.u8()
	p := li.DeliveryProvenance{Kind: "non_call", OriginNodeID: r.text(4096), SourceID: r.text(4096), CaptureEpoch: r.id(), ObservationSequence: r.u64()}
	if tag == 2 {
		p.SourceKind = "rtp"
		p.Transport = r.u8()
		p.SourceAddress = r.text(64)
		p.DestinationAddress = r.text(64)
		p.SourcePort = r.u16()
		p.DestinationPort = r.u16()
		p.SSRC = r.u32()
	} else if tag == 3 {
		p.SourceKind = "radius"
		p.OperatorScope = r.text(4096)
		p.ProfileRevision = r.text(4096)
		p.NFID = r.text(4096)
		p.IPID = r.text(4096)
		p.CorrelationID = r.u64()
	} else {
		r.err = errJournalSchema
	}
	return p
}
func recordPrefix(rec JournalRecord, dataBytes uint64) ([]byte, error) {
	if (rec.Interface != PDUTypeX2 && rec.Interface != PDUTypeX3) || rec.JournalUUID == uuid.Nil || rec.ID == 0 || rec.XID == uuid.Nil || rec.DID == uuid.Nil || dataBytes > uint64(journalMaxRecord) {
		return nil, errJournalSchema
	}
	if rec.Interface == PDUTypeX3 && (rec.StateIncarnation == uuid.Nil || rec.TaskGeneration == 0 || rec.DestinationGeneration == 0 || rec.AdmittedAt.IsZero() || rec.CapturedAt.IsZero() || rec.Deadline.IsZero() || !rec.Deadline.After(rec.AdmittedAt)) {
		return nil, errJournalSchema
	}
	if !rec.Deadline.IsZero() && (rec.AdmittedAt.IsZero() || !rec.Deadline.After(rec.AdmittedAt)) {
		return nil, errJournalSchema
	}
	prov, err := provenanceBytes(rec.Provenance, rec.Interface)
	if err != nil {
		return nil, err
	}
	var w recordEncoder
	w.WriteString(journalRecordDomain)
	w.u16(uint16(rec.Interface))
	w.id(rec.JournalUUID)
	w.u64(rec.ID)
	w.optionalID(rec.StateIncarnation)
	w.id(rec.XID)
	w.u64(rec.TaskGeneration)
	w.id(rec.DID)
	w.u64(rec.DestinationGeneration)
	w.timestamp(rec.AdmittedAt)
	w.timestamp(rec.CapturedAt)
	w.timestamp(rec.Deadline)
	w.Write(prov)
	w.u64(dataBytes)
	if w.err != nil || w.Len() > journalMetadataMax {
		return nil, errJournalSchema
	}
	return w.Bytes(), nil
}
func recordContentHash(prefix, data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(prefix)
	_, _ = h.Write(data)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func encodeRecordMetadata(rec JournalRecord) ([]byte, error) {
	prefix, err := recordPrefix(rec, uint64(len(rec.Data)))
	if err != nil {
		return nil, err
	}
	sum := recordContentHash(prefix, rec.Data)
	if rec.ContentSHA256 != [32]byte{} && rec.ContentSHA256 != sum {
		return nil, errJournalSchema
	}
	return append(prefix, sum[:]...), nil
}
func decodeRecordMetadata(data []byte) (JournalRecord, uint64, error) {
	var rec JournalRecord
	if len(data) < len(journalRecordDomain)+32 || len(data) > journalMetadataMax+32 || string(data[:len(journalRecordDomain)]) != journalRecordDomain {
		return rec, 0, errJournalSchema
	}
	r := recordDecoder{b: data[len(journalRecordDomain):]}
	rec.Interface = PDUType(r.u16())
	rec.JournalUUID = r.id()
	rec.ID = r.u64()
	rec.StateIncarnation = r.optionalID()
	rec.XID = r.id()
	rec.TaskGeneration = r.u64()
	rec.DID = r.id()
	rec.DestinationGeneration = r.u64()
	rec.AdmittedAt = r.timestamp()
	rec.CapturedAt = r.timestamp()
	rec.Deadline = r.timestamp()
	rec.Provenance = decodeProvenance(&r)
	n := r.u64()
	copy(rec.ContentSHA256[:], r.take(32))
	if r.err != nil || len(r.b) != 0 {
		return JournalRecord{}, 0, errJournalSchema
	}
	rec.CallIncarnation = rec.Provenance.CallIncarnation
	rec.CallGeneration = rec.Provenance.CallGeneration
	rec.CallID = rec.Provenance.CallID
	prefix, err := recordPrefix(rec, n)
	if err != nil || !bytes.Equal(prefix, data[:len(data)-32]) {
		return JournalRecord{}, 0, errJournalSchema
	}
	return rec, n, nil
}

// Inspect actual framing without allocating/copying the PDU payload or TLVs.
func journalPDUCheckpoint(data []byte, iface PDUType, xid uuid.UUID, sequenceRequired bool) (x2x3.SequenceCheckpoint, error) {
	var head x2x3.PDUHeader
	if err := head.UnmarshalBinary(data); err != nil {
		return x2x3.SequenceCheckpoint{}, err
	}
	if PDUType(head.Type) != iface || head.XID != xid || uint64(head.HeaderLength)+uint64(head.PayloadLength) != uint64(len(data)) {
		return x2x3.SequenceCheckpoint{}, errJournalSchema
	}
	cp := x2x3.SequenceCheckpoint{Context: x2x3.SequenceContext{PDUType: head.Type, XID: head.XID, CorrelationID: head.CorrelationID}}
	seen := map[x2x3.AttributeType]bool{}
	seq := false
	for offset := x2x3.HeaderMinSize; offset < int(head.HeaderLength); {
		if int(head.HeaderLength)-offset < 4 {
			return cp, errJournalSchema
		}
		kind := x2x3.AttributeType(binary.BigEndian.Uint16(data[offset:]))
		n := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4
		if n > int(head.HeaderLength)-offset {
			return cp, errJournalSchema
		}
		b := data[offset : offset+n]
		offset += n
		switch kind {
		case x2x3.AttrDomainID, x2x3.AttrNFID, x2x3.AttrIPID, x2x3.AttrSequenceNumber:
			if seen[kind] {
				return cp, errJournalSchema
			}
			seen[kind] = true
		}
		switch kind {
		case x2x3.AttrDomainID:
			cp.Context.DomainID = string(b)
		case x2x3.AttrNFID:
			cp.Context.NFID = string(b)
		case x2x3.AttrIPID:
			cp.Context.IPID = string(b)
		case x2x3.AttrSequenceNumber:
			if n != 4 {
				return cp, errJournalSchema
			}
			cp.Next = binary.BigEndian.Uint32(b) + 1
			seq = true
		}
	}
	if sequenceRequired && !seq {
		return cp, errJournalSchema
	}
	if err := validateSequenceIdentity(cp.Context); err != nil {
		return cp, err
	}
	return cp, nil
}
func productionSequenceKey(c x2x3.SequenceContext) (string, error) {
	var w recordEncoder
	w.WriteString("lippycat/li-sequence/v1\x00")
	w.u16(uint16(c.PDUType))
	w.id(c.XID)
	w.text(c.DomainID, 512)
	w.text(c.NFID, 512)
	w.text(c.IPID, 512)
	w.u64(c.CorrelationID)
	if w.err != nil {
		return "", w.err
	}
	sum := sha256.Sum256(w.Bytes())
	return string(sum[:]), nil
}
