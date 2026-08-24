// Package events defines output-neutral normalized protocol events.
package events

import (
	"context"
	"net/netip"
	"time"
)

// Kind is the stable wire label for a normalized event class.
type Kind string

const (
	KindDNS          Kind = "dns"
	KindSMTP         Kind = "smtp"
	KindTLS          Kind = "tls"
	KindHTTP         Kind = "http"
	KindConn         Kind = "conn"
	KindFileMetadata Kind = "file_metadata"
	KindFileContent  Kind = "file_content"
)

// CaptureScope describes whether capture configuration could observe the full flow.
type CaptureScope string

const (
	CaptureScopeFull     CaptureScope = "full"
	CaptureScopeFiltered CaptureScope = "filtered"
)

// FlowTuple preserves the observed direction. Flow identity code may normalize it.
// For ICMP, SourcePort and DestinationPort hold type and code respectively.
type FlowTuple struct {
	Protocol           uint8      `json:"protocol"`
	SourceAddress      netip.Addr `json:"source_address"`
	DestinationAddress netip.Addr `json:"destination_address"`
	SourcePort         uint16     `json:"source_port"`
	DestinationPort    uint16     `json:"destination_port"`
}

// Envelope contains provenance and flow identity shared by every event.
type Envelope struct {
	Timestamp    time.Time    `json:"timestamp"`
	UID          string       `json:"uid"`
	CommunityID  string       `json:"community_id"`
	NodeID       string       `json:"node_id"`
	Flow         FlowTuple    `json:"flow"`
	Partial      bool         `json:"partial"`
	CaptureScope CaptureScope `json:"capture_scope"`
}

// Event is implemented only by the typed normalized event classes in this package.
type Event interface {
	Kind() Kind
	Envelope() Envelope
	eventMarker()
}

// Sink consumes normalized events outside the packet processing path.
type Sink interface {
	HandleEvent(context.Context, Event) error
	Flush(context.Context) error
	Close(context.Context) error
}

type eventBase struct {
	EventEnvelope Envelope `json:"envelope"`
}

func (e eventBase) Envelope() Envelope { return e.EventEnvelope }

type DNSEvent struct {
	eventBase
	TransactionID                                                  uint16
	RTT                                                            time.Duration
	Query                                                          string
	QClass, QType, RCode                                           uint16
	Authoritative, Truncated, RecursionDesired, RecursionAvailable bool
	Z                                                              uint8
	Answers                                                        []string
	TTLs                                                           []time.Duration
	Rejected                                                       bool
}

func NewDNSEvent(env Envelope) DNSEvent { return DNSEvent{eventBase: eventBase{env}} }
func (DNSEvent) Kind() Kind             { return KindDNS }
func (DNSEvent) eventMarker()           {}

type SMTPEvent struct {
	eventBase
	TransactionDepth                       uint64
	HELO, MailFrom                         string
	Recipients                             []string
	Date, From                             string
	To, CC                                 []string
	ReplyTo, MessageID, InReplyTo, Subject string
	OriginatingIP                          netip.Addr
	Received                               []string
	LastReply                              string
	Path                                   []string
	UserAgent                              string
	TLS                                    bool
	FileIDs                                []string
	IsWebmail                              bool
}

func NewSMTPEvent(env Envelope) SMTPEvent { return SMTPEvent{eventBase: eventBase{env}} }
func (SMTPEvent) Kind() Kind              { return KindSMTP }
func (SMTPEvent) eventMarker()            {}

type TLSEvent struct {
	eventBase
	Version, Cipher, Curve, ServerName                             string
	Resumed                                                        bool
	LastAlert, NextProtocol                                        string
	Established                                                    bool
	CertificateFileIDs, ClientCertificateFileIDs                   []string
	Subject, Issuer, ClientSubject, ClientIssuer, ValidationStatus string
	JA3, JA3S, JA4                                                 string
}

func NewTLSEvent(env Envelope) TLSEvent { return TLSEvent{eventBase: eventBase{env}} }
func (TLSEvent) Kind() Kind             { return KindTLS }
func (TLSEvent) eventMarker()           {}

type HTTPEvent struct {
	eventBase
	TransactionDepth                                            uint64
	Method, Host, URI, Referrer, Version, UserAgent, Origin     string
	RequestBodyLength, ResponseBodyLength                       uint64
	StatusCode, InformationalCode                               uint16
	StatusMessage, InformationalMessage                         string
	Tags                                                        []string
	Username                                                    string
	Proxies, RequestFileIDs, RequestFilenames, RequestMIMETypes []string
	ResponseFileIDs, ResponseFilenames, ResponseMIMETypes       []string
	Headers                                                     map[string][]string
}

func NewHTTPEvent(env Envelope) HTTPEvent { return HTTPEvent{eventBase: eventBase{env}} }
func (HTTPEvent) Kind() Kind              { return KindHTTP }
func (HTTPEvent) eventMarker()            {}

type ConnEvent struct {
	eventBase
	Service                                                        string
	Duration                                                       time.Duration
	OriginBytes, ResponseBytes                                     uint64
	State                                                          string
	LocalOrigin, LocalResponse                                     bool
	MissedBytes                                                    uint64
	History                                                        string
	OriginPackets, OriginIPBytes, ResponsePackets, ResponseIPBytes uint64
}

func NewConnEvent(env Envelope) ConnEvent { return ConnEvent{eventBase: eventBase{env}} }
func (ConnEvent) Kind() Kind              { return KindConn }
func (ConnEvent) eventMarker()            {}

type FileMetadataEvent struct {
	eventBase
	FileID, Source                                     string
	Depth                                              uint64
	Analyzers                                          []string
	MIMEType, Filename                                 string
	Duration                                           time.Duration
	LocalOrigin, IsOrigin                              bool
	SeenBytes, TotalBytes, MissingBytes, OverflowBytes uint64
	TimedOut                                           bool
	ParentFileID, MD5, SHA1, SHA256, ExtractedPath     string
	HashComplete                                       bool
}

func NewFileMetadataEvent(env Envelope) FileMetadataEvent {
	return FileMetadataEvent{eventBase: eventBase{env}}
}
func (FileMetadataEvent) Kind() Kind   { return KindFileMetadata }
func (FileMetadataEvent) eventMarker() {}

// FileContentEvent is deliberately the only initial event capable of carrying content.
type FileContentEvent struct {
	eventBase
	FileID, MIMEType, Filename string
	Content                    []byte
}

func NewFileContentEvent(env Envelope) FileContentEvent {
	return FileContentEvent{eventBase: eventBase{env}}
}
func (FileContentEvent) Kind() Kind   { return KindFileContent }
func (FileContentEvent) eventMarker() {}
