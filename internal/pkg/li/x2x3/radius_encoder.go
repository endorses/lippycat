package x2x3

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/radius"
)

var ErrInvalidRADIUSObservation = errors.New("invalid RADIUS X2 observation")

// RADIUSEncoder serializes already admitted observations. It owns neither target
// matching nor exchange correlation: the caller supplies the current task XID
// and a nonzero correlation allocation from the persistent radius-poi-v1
// allocator. All encoders in a delivery pipeline must share the Sequencer.
type RADIUSEncoder struct {
	sequencer *Sequencer
	builder   *AttributeBuilder
	domainID  string
	nfID      string
	ipID      string
}

func NewRADIUSEncoder(sequencer *Sequencer, domainID, nfID, ipID string) *RADIUSEncoder {
	if sequencer == nil {
		sequencer = NewSequencer(0)
	}
	return &RADIUSEncoder{sequencer: sequencer, builder: NewAttributeBuilder(), domainID: domainID, nfID: nfID, ipID: ipID}
}

// Encode preserves the validated wire message, including the Authenticator and
// unknown/repeated AVPs. UDP padding and packet encapsulation are excluded. The
// returned PDU owns its payload independently of the observation's storage.
// Transport roles do not establish subscriber direction, which remains Unknown.
func (e *RADIUSEncoder) Encode(observation *radius.Observation, xid uuid.UUID, correlationID uint64) (*PDU, error) {
	if observation == nil || observation.Message == nil || xid == uuid.Nil || correlationID == 0 {
		return nil, ErrInvalidRADIUSObservation
	}
	message, err := radius.Decode(observation.Message.Raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRADIUSObservation, err)
	}
	endpoints := observation.Endpoints
	src, dst := endpoints.Source, endpoints.Destination
	if !src.IsValid() || !dst.IsValid() || src.Addr().Zone() != "" || dst.Addr().Zone() != "" ||
		(endpoints.IPFamily != 4 && endpoints.IPFamily != 6) ||
		(endpoints.IPFamily == 4 && (!src.Addr().Is4() || !dst.Addr().Is4())) ||
		(endpoints.IPFamily == 6 && (!src.Addr().Is6() || !dst.Addr().Is6() || src.Addr().Is4In6() || dst.Addr().Is4In6())) {
		return nil, fmt.Errorf("%w: transport endpoints", ErrInvalidRADIUSObservation)
	}
	source, err := e.builder.SourceIP(src.Addr())
	if err != nil {
		return nil, fmt.Errorf("encode RADIUS source: %w", err)
	}
	destination, err := e.builder.DestIP(dst.Addr())
	if err != nil {
		return nil, fmt.Errorf("encode RADIUS destination: %w", err)
	}
	seq, err := e.sequencer.Next(SequenceContext{PDUType: PDUTypeX2, XID: xid, DomainID: e.domainID, NFID: e.nfID, IPID: e.ipID, CorrelationID: correlationID})
	if err != nil {
		return nil, fmt.Errorf("sequence RADIUS X2: %w", err)
	}
	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	pdu.Header.PayloadFormat = PayloadFormatRADIUS
	pdu.Header.PayloadDirection = PayloadDirectionUnknown
	pdu.AddAttribute(e.builder.Timestamp(observation.Capture.Timestamp))
	if e.domainID != "" {
		pdu.AddAttribute(e.builder.DomainID(e.domainID))
	}
	if e.nfID != "" {
		pdu.AddAttribute(e.builder.NFID(e.nfID))
	}
	if e.ipID != "" {
		pdu.AddAttribute(e.builder.IPID(e.ipID))
	}
	pdu.AddAttribute(e.builder.SequenceNumber(seq))
	pdu.AddAttribute(source)
	pdu.AddAttribute(destination)
	pdu.AddAttribute(e.builder.SourcePort(src.Port()))
	pdu.AddAttribute(e.builder.DestPort(dst.Port()))
	pdu.AddAttribute(e.builder.IPProtocol(17))
	pdu.SetPayload(message.Raw)
	return pdu, nil
}
