package events

import (
	"net/netip"
	"time"
)

const (
	KindDHCP         Kind = "dhcp"
	KindNTP          Kind = "ntp"
	KindKnownHost    Kind = "known_host"
	KindKnownService Kind = "known_service"
)

// AssociationStatus describes observational correlation, never authentication.
type AssociationStatus string

const (
	AssociationRequest            AssociationStatus = "request"
	AssociationUnique             AssociationStatus = "unique"
	AssociationMissing            AssociationStatus = "missing"
	AssociationAmbiguous          AssociationStatus = "ambiguous"
	AssociationExpired            AssociationStatus = "expired"
	AssociationCapacitySuppressed AssociationStatus = "capacity_suppressed"
	AssociationNotApplicable      AssociationStatus = "not_applicable"
)

// DHCPEvent is one DHCPv4 message. The envelope is the observed UDP flow,
// even when an exchange spans broadcasts, relays or address changes. Nil
// options mean unavailable; zero is a valid value for a present lease.
type DHCPEvent struct {
	eventBase
	Operation, MessageType, HardwareType                           uint8
	TransactionID                                                  uint32
	HardwareAddress, ClientIdentifier                              []byte
	ClientAddress, OfferedAddress, NextServerAddress, RelayAddress netip.Addr
	ServerIdentifier, RequestedAddress                             netip.Addr
	Hostname, Domain                                               string
	LeaseSeconds                                                   *uint32
	Routers, DNSServers                                            []netip.Addr
	ParameterRequestList                                           []byte
	Association                                                    AssociationStatus
	AssociationID                                                  string
	Truncated                                                      bool
}

func NewDHCPEvent(env Envelope) DHCPEvent { return DHCPEvent{eventBase: eventBase{env}} }
func (DHCPEvent) Kind() Kind              { return KindDHCP }
func (DHCPEvent) eventMarker()            {}

// NTPTimestamp retains the exact 32.32 wire timestamp. Time is absent for
// wire zero; otherwise its era is resolved nearest the packet capture time.
type NTPTimestamp struct {
	Raw  uint64
	Time time.Time
}

// NTPEvent represents time-message modes 1–5. Fixed point quantities are raw
// wire values, preserving signedness and precision. No clock offset or
// authentication claim is derived from a sniffer's timestamps.
type NTPEvent struct {
	eventBase
	Version, Mode, LeapIndicator, Stratum uint8
	Poll, Precision                       int8
	RootDelay                             int32
	RootDispersion                        uint32
	ReferenceID                           [4]byte
	Reference, Origin, Receive, Transmit  NTPTimestamp
	Association                           AssociationStatus
	AssociationID                         string
	Truncated                             bool
}

func NewNTPEvent(env Envelope) NTPEvent { return NTPEvent{eventBase: eventBase{env}} }
func (NTPEvent) Kind() Kind             { return KindNTP }
func (NTPEvent) eventMarker()           {}

// InventoryEvidence is finite positive evidence, independent of summary labels.
type InventoryEvidence string

const (
	EvidenceTCPHandshake     InventoryEvidence = "tcp_handshake"
	EvidenceUDPBidirectional InventoryEvidence = "udp_bidirectional"
	EvidenceDNSExchange      InventoryEvidence = "dns_exchange"
	EvidenceNTPExchange      InventoryEvidence = "ntp_exchange"
	EvidenceDHCPExchange     InventoryEvidence = "dhcp_exchange"
)

// KnownHostEvent keeps the qualifying connection envelope separate from its
// subject. Multiple sensors observing a private address remain independent.
type KnownHostEvent struct {
	eventBase
	Host     netip.Addr
	Evidence InventoryEvidence
}

func NewKnownHostEvent(env Envelope) KnownHostEvent { return KnownHostEvent{eventBase: eventBase{env}} }
func (KnownHostEvent) Kind() Kind                   { return KindKnownHost }
func (KnownHostEvent) eventMarker()                 {}

type KnownServiceEvent struct {
	eventBase
	Host      netip.Addr
	Port      uint16
	Transport uint8
	Protocol  string
	Evidence  InventoryEvidence
}

func NewKnownServiceEvent(env Envelope) KnownServiceEvent {
	return KnownServiceEvent{eventBase: eventBase{env}}
}
func (KnownServiceEvent) Kind() Kind   { return KindKnownService }
func (KnownServiceEvent) eventMarker() {}

// Clone returns an independently owned observation for asynchronous consumers.
func (e DHCPEvent) Clone() DHCPEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	e.HardwareAddress = append([]byte(nil), e.HardwareAddress...)
	e.ClientIdentifier = append([]byte(nil), e.ClientIdentifier...)
	e.ParameterRequestList = append([]byte(nil), e.ParameterRequestList...)
	e.Routers = append([]netip.Addr(nil), e.Routers...)
	e.DNSServers = append([]netip.Addr(nil), e.DNSServers...)
	if e.LeaseSeconds != nil {
		lease := *e.LeaseSeconds
		e.LeaseSeconds = &lease
	}
	return e
}
func (e NTPEvent) Clone() NTPEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	return e
}
func (e KnownHostEvent) Clone() KnownHostEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	return e
}
func (e KnownServiceEvent) Clone() KnownServiceEvent {
	e.EventEnvelope.Provenance.ProcessorNodeIDs = append([]string(nil), e.EventEnvelope.Provenance.ProcessorNodeIDs...)
	return e
}
