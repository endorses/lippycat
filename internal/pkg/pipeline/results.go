package pipeline

import "time"

// DomainResult is implemented by output-neutral analysis results.
type DomainResult interface {
	CapturedAt() time.Time
	domainResult()
}

type SIPResult struct {
	Timestamp                      time.Time
	CallID, Method, CSeqMethod     string
	ResponseCode                   int
	From, To, FromUser, ToUser     string
	FromURI, ToURI, FromTag, ToTag string
	PAssertedIdentity, ContentType string
	SourceIP, DestinationIP        string
	SourcePort, DestinationPort    uint16
	SDP                            []byte
	Body                           []byte
	Headers                        map[string]string
	Packet                         *PacketEnvelope
	MatchedFilterIDs               []string
	Lifecycle                      []CallLifecycleObservation
}

func (r SIPResult) CapturedAt() time.Time { return r.Timestamp }
func (SIPResult) domainResult()           {}

type CallLifecycle uint8

const (
	CallLifecycleUnknown CallLifecycle = iota
	CallLifecycleStarted
	CallLifecycleUpdated
	CallLifecycleCompleted
	CallLifecycleTimedOut
)

type CallLifecycleObservation struct {
	State     CallLifecycle
	Timestamp time.Time
	Reason    string
}

type RTPResult struct {
	Timestamp   time.Time
	CallID      string
	SSRC        uint32
	PayloadType uint8
	Sequence    uint16
	Packet      *PacketEnvelope
}

func (r RTPResult) CapturedAt() time.Time { return r.Timestamp }
func (RTPResult) domainResult()           {}

type DNSResult struct {
	Timestamp     time.Time
	TransactionID uint16
	Query         string
	QueryType     string
	IsResponse    bool
	ResponseCode  string
	Packet        *PacketEnvelope
}

func (r DNSResult) CapturedAt() time.Time { return r.Timestamp }
func (DNSResult) domainResult()           {}

type HTTPResult struct {
	Timestamp                       time.Time
	Method, Host, URI, Version      string
	StatusCode                      int
	SourceIP, DestinationIP         string
	SourcePort, DestinationPort     uint16
	RequestHeaders, ResponseHeaders map[string][]string
	Packet                          *PacketEnvelope
	MatchedFilterIDs                []string
}

func (r HTTPResult) CapturedAt() time.Time { return r.Timestamp }
func (HTTPResult) domainResult()           {}

type TLSResult struct {
	Timestamp                      time.Time
	Version, ServerName, JA3, JA3S string
	CipherSuite                    uint16
	SourceIP, DestinationIP        string
	SourcePort, DestinationPort    uint16
	Packet                         *PacketEnvelope
	MatchedFilterIDs               []string
}

func (r TLSResult) CapturedAt() time.Time { return r.Timestamp }
func (TLSResult) domainResult()           {}

type EmailResult struct {
	Timestamp                   time.Time
	Protocol, Command, Response string
	Sender                      string
	Recipients                  []string
	Subject                     string
	SourceIP, DestinationIP     string
	SourcePort, DestinationPort uint16
	Packet                      *PacketEnvelope
	MatchedFilterIDs            []string
}

func (r EmailResult) CapturedAt() time.Time { return r.Timestamp }
func (EmailResult) domainResult()           {}

type GenericPacketResult struct {
	Timestamp time.Time
	Protocol  string
	Packet    *PacketEnvelope
}

func (r GenericPacketResult) CapturedAt() time.Time { return r.Timestamp }
func (GenericPacketResult) domainResult()           {}
