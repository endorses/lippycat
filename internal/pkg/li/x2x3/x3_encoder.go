// Package x2x3 implements ETSI TS 103 221-2 X2/X3 binary TLV encoding.
package x2x3

import (
	"errors"
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// X3 Encoder errors.
var (
	// ErrNotRTP is returned when the packet is not an RTP packet.
	ErrNotRTP = errors.New("packet is not RTP")

	// ErrNoSSRC is returned when the RTP packet has no SSRC.
	ErrNoSSRC = errors.New("RTP packet has no SSRC")

	// ErrNoPayload is returned when the packet has no raw data payload.
	ErrNoPayload = errors.New("packet has no payload data")
)

// X3Encoder encodes RTP media packets into X3 CC (Content of Communication) PDUs.
//
// X3 carries the actual content of intercepted communications:
//   - RTP audio/video packets
//   - Other real-time media
//
// The encoder is optimized for high-volume streaming with:
//   - Atomic sequence number generation
//   - Buffer pooling for reduced allocations
//   - Efficient PDU construction
//
// The encoder is safe for concurrent use.
type X3Encoder struct {
	// seqNum is the global sequence number for X3 PDUs.
	seqNum atomic.Uint32

	// attrBuilder is used to construct TLV attributes.
	attrBuilder *AttributeBuilder

	// bufPool provides reusable buffers for PDU encoding.
	bufPool sync.Pool
}

// NewX3Encoder creates a new X3 encoder.
func NewX3Encoder() *X3Encoder {
	return &X3Encoder{
		attrBuilder: NewAttributeBuilder(),
		bufPool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate buffer for typical RTP packet + PDU overhead
				// RTP payload ~160 bytes (G.711) + PDU header ~100 bytes
				buf := make([]byte, 0, 512)
				return &buf
			},
		},
	}
}

// EncodeCC encodes an RTP packet into an X3 CC PDU.
//
// The packet must have VoIPMetadata with IsRTP=true and a valid SSRC.
// The XID identifies the intercept task this CC belongs to.
//
// For high-volume streaming, the encoder uses pooled buffers and
// efficient serialization to minimize allocations.
func (e *X3Encoder) EncodeCC(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil || !pkt.VoIPData.IsRTP {
		return nil, ErrNotRTP
	}

	voip := pkt.VoIPData
	if voip.SSRC == 0 {
		return nil, ErrNoSSRC
	}

	// Generate correlation ID from SSRC (deterministic hash)
	// This links all RTP packets from the same stream
	correlationID := e.generateCorrelationID(voip.SSRC, voip.CallID)

	// Create PDU carrying a raw RTP packet.
	pdu := NewX3RTPPDU(xid, correlationID)

	// Add standard conditional attributes (timestamp, sequence number).
	e.addCommonAttributes(pdu, pkt)

	// Add network layer attributes (5-tuple).
	e.addNetworkAttributes(pdu, pkt)

	// Set payload (raw RTP packet including header). The MDF reads SSRC /
	// sequence / timestamp / payload-type directly from the RTP header.
	if len(pkt.RawData) > 0 {
		pdu.SetPayload(pkt.RawData)
	}

	return pdu, nil
}

// NewX3RTPPDU creates an X3 PDU carrying a raw RTP packet: PDU Type 2,
// Payload Format 8 (RTP Packet), Payload Direction Unknown.
func NewX3RTPPDU(xid uuid.UUID, correlationID uint64) *PDU {
	pdu := NewPDU(PDUTypeX3, xid, correlationID)
	pdu.Header.PayloadFormat = PayloadFormatRTP
	pdu.Header.PayloadDirection = PayloadDirectionUnknown
	return pdu
}

// EncodeCCWithPayload encodes an RTP packet with an explicit payload.
// Use this when the RTP payload is separate from RawData.
func (e *X3Encoder) EncodeCCWithPayload(pkt *types.PacketDisplay, xid uuid.UUID, payload []byte) (*PDU, error) {
	if pkt.VoIPData == nil || !pkt.VoIPData.IsRTP {
		return nil, ErrNotRTP
	}

	voip := pkt.VoIPData
	if voip.SSRC == 0 {
		return nil, ErrNoSSRC
	}

	if len(payload) == 0 {
		return nil, ErrNoPayload
	}

	correlationID := e.generateCorrelationID(voip.SSRC, voip.CallID)
	pdu := NewX3RTPPDU(xid, correlationID)

	e.addCommonAttributes(pdu, pkt)
	e.addNetworkAttributes(pdu, pkt)
	pdu.SetPayload(payload)

	return pdu, nil
}

// generateCorrelationID creates a deterministic correlation ID for an X3 CC PDU.
// This links X3 CC PDUs to their corresponding X2 IRI PDUs.
//
// When a Call-ID is available, it takes precedence: the correlation ID is the
// FNV-1a hash of the Call-ID only (identical to X2Encoder.generateCorrelationID),
// so the X3 correlation ID equals the X2 correlation ID for the same call and the
// LEA/MDF can pair an IRI with its CC.
//
// Only when there is no Call-ID (RTP-only, no SIP signaling) do we fall back to a
// deterministic per-SSRC hash for stream-level correlation.
func (e *X3Encoder) generateCorrelationID(ssrc uint32, callID string) uint64 {
	h := fnv.New64a()

	// If we have a Call-ID, hash it alone so X3 corr == X2 corr for the same call.
	if callID != "" {
		h.Write([]byte(callID))
		return h.Sum64()
	}

	// No Call-ID: fall back to SSRC for stream-level correlation.
	buf := [4]byte{
		byte(ssrc >> 24),
		byte(ssrc >> 16),
		byte(ssrc >> 8),
		byte(ssrc),
	}
	h.Write(buf[:])

	return h.Sum64()
}

// addCommonAttributes adds standard attributes to the PDU.
func (e *X3Encoder) addCommonAttributes(pdu *PDU, pkt *types.PacketDisplay) {
	// Timestamp from packet capture
	pdu.AddAttribute(e.attrBuilder.Timestamp(pkt.Timestamp))

	// Sequence number (monotonically increasing)
	seq := e.seqNum.Add(1)
	pdu.AddAttribute(e.attrBuilder.SequenceNumber(seq))
}

// addNetworkAttributes adds network layer attributes to the PDU.
func (e *X3Encoder) addNetworkAttributes(pdu *PDU, pkt *types.PacketDisplay) {
	// Source IP
	if pkt.SrcIP != "" {
		if addr, err := netip.ParseAddr(pkt.SrcIP); err == nil {
			if attr, err := e.attrBuilder.SourceIP(addr); err == nil {
				pdu.AddAttribute(attr)
			}
		}
	}

	// Destination IP
	if pkt.DstIP != "" {
		if addr, err := netip.ParseAddr(pkt.DstIP); err == nil {
			if attr, err := e.attrBuilder.DestIP(addr); err == nil {
				pdu.AddAttribute(attr)
			}
		}
	}

	// Source port
	if pkt.SrcPort != "" {
		if port, ok := parsePort(pkt.SrcPort); ok {
			pdu.AddAttribute(e.attrBuilder.SourcePort(port))
		}
	}

	// Destination port
	if pkt.DstPort != "" {
		if port, ok := parsePort(pkt.DstPort); ok {
			pdu.AddAttribute(e.attrBuilder.DestPort(port))
		}
	}
}

// GetSequenceNumber returns the current sequence number (for testing/debugging).
func (e *X3Encoder) GetSequenceNumber() uint32 {
	return e.seqNum.Load()
}

// EncodeCCBatch encodes multiple RTP packets efficiently.
// This method is optimized for high-volume streaming by:
// - Reusing the same encoder state
// - Batching PDU creation
//
// Returns a slice of PDUs and any errors encountered.
// Packets that fail to encode are skipped and their errors collected.
func (e *X3Encoder) EncodeCCBatch(packets []*types.PacketDisplay, xid uuid.UUID) ([]*PDU, []error) {
	pdus := make([]*PDU, 0, len(packets))
	var errs []error

	for _, pkt := range packets {
		pdu, err := e.EncodeCC(pkt, xid)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		pdus = append(pdus, pdu)
	}

	return pdus, errs
}
