package protoadapter

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/dhcp"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/ntp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var associations = []events.AssociationStatus{"", events.AssociationRequest, events.AssociationUnique, events.AssociationMissing, events.AssociationAmbiguous, events.AssociationExpired, events.AssociationCapacitySuppressed, events.AssociationNotApplicable}
var evidences = []events.InventoryEvidence{"", events.EvidenceTCPHandshake, events.EvidenceUDPBidirectional, events.EvidenceDNSExchange, events.EvidenceNTPExchange, events.EvidenceDHCPExchange}

func associationToWire(s events.AssociationStatus) eventsv1.AssociationStatus {
	for i, v := range associations {
		if v == s {
			return eventsv1.AssociationStatus(i)
		}
	}
	return 0
}
func evidenceToWire(s events.InventoryEvidence) eventsv1.InventoryEvidence {
	for i, v := range evidences {
		if v == s {
			return eventsv1.InventoryEvidence(i)
		}
	}
	return 0
}
func associationFromWire(s eventsv1.AssociationStatus) (events.AssociationStatus, error) {
	if s <= 0 || int(s) >= len(associations) {
		return "", errors.New("invalid association status")
	}
	return associations[s], nil
}
func evidenceFromWire(s eventsv1.InventoryEvidence) (events.InventoryEvidence, error) {
	if s <= 0 || int(s) >= len(evidences) {
		return "", errors.New("invalid inventory evidence")
	}
	return evidences[s], nil
}
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
func addrStrings(as []netip.Addr) []string {
	if as == nil {
		return nil
	}
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}
func decodeV4(s string, optional bool) (netip.Addr, error) {
	if s == "" && optional {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, errors.New("DHCP address must be IPv4")
	}
	return a, nil
}
func decodeV4List(ss []string) ([]netip.Addr, error) {
	if len(ss) > dhcp.MaxAddresses {
		return nil, errors.New("DHCP address list exceeds limit")
	}
	if ss == nil {
		return nil, nil
	}
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		var err error
		out[i], err = decodeV4(s, false)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func encodeNTPTimestamp(t events.NTPTimestamp) *eventsv1.NTPTimestamp {
	p := &eventsv1.NTPTimestamp{Raw: t.Raw}
	if !t.Time.IsZero() {
		p.Time = timestamppb.New(t.Time)
	}
	return p
}
func decodeNTPTimestamp(p *eventsv1.NTPTimestamp) (events.NTPTimestamp, error) {
	if p == nil {
		return events.NTPTimestamp{}, errors.New("missing NTP timestamp")
	}
	t := events.NTPTimestamp{Raw: p.Raw}
	if p.Time != nil {
		if err := p.Time.CheckValid(); err != nil {
			return t, err
		}
		t.Time = p.Time.AsTime()
	}
	return t, nil
}

func decodeNetwork(in *eventsv1.ProtocolEvent, env events.Envelope) (events.Event, error) {
	switch p := in.Payload.(type) {
	case *eventsv1.ProtocolEvent_Dhcp:
		if p == nil {
			return nil, errors.New("nil network payload wrapper")
		}
		v := p.Dhcp
		if v == nil || v.Operation > 255 || v.MessageType > 255 || v.HardwareType > 255 {
			return nil, errors.New("invalid DHCP payload or numeric range")
		}
		e := events.NewDHCPEvent(env)
		e.Operation, e.MessageType, e.HardwareType, e.TransactionID = uint8(v.Operation), uint8(v.MessageType), uint8(v.HardwareType), v.TransactionId
		e.HardwareAddress, e.ClientIdentifier, e.ParameterRequestList = bytes.Clone(v.HardwareAddress), bytes.Clone(v.ClientIdentifier), bytes.Clone(v.ParameterRequestList)
		e.Hostname, e.Domain, e.AssociationID, e.Truncated = v.Hostname, v.Domain, v.AssociationId, v.Truncated
		if v.LeaseSeconds != nil {
			n := *v.LeaseSeconds
			e.LeaseSeconds = &n
		}
		pairs := []struct {
			s        string
			a        *netip.Addr
			optional bool
		}{{v.ClientAddress, &e.ClientAddress, false}, {v.OfferedAddress, &e.OfferedAddress, false}, {v.NextServerAddress, &e.NextServerAddress, false}, {v.RelayAddress, &e.RelayAddress, false}, {v.ServerIdentifier, &e.ServerIdentifier, true}, {v.RequestedAddress, &e.RequestedAddress, true}}
		for _, p := range pairs {
			a, err := decodeV4(p.s, p.optional)
			if err != nil {
				return nil, err
			}
			*p.a = a
		}
		var err error
		if e.Routers, err = decodeV4List(v.Routers); err != nil {
			return nil, err
		}
		if e.DNSServers, err = decodeV4List(v.DnsServers); err != nil {
			return nil, err
		}
		if e.Association, err = associationFromWire(v.Association); err != nil {
			return nil, err
		}
		return e, nil
	case *eventsv1.ProtocolEvent_Ntp:
		if p == nil {
			return nil, errors.New("nil network payload wrapper")
		}
		v := p.Ntp
		if v == nil || v.Version > 255 || v.Mode > 255 || v.LeapIndicator > 255 || v.Stratum > 255 || v.Poll < -128 || v.Poll > 127 || v.Precision < -128 || v.Precision > 127 || len(v.ReferenceId) != 4 {
			return nil, errors.New("invalid NTP payload or numeric range")
		}
		e := events.NewNTPEvent(env)
		e.Version, e.Mode, e.LeapIndicator, e.Stratum = uint8(v.Version), uint8(v.Mode), uint8(v.LeapIndicator), uint8(v.Stratum)
		e.Poll, e.Precision = int8(v.Poll), int8(v.Precision)
		e.RootDelay, e.RootDispersion = v.RootDelay, v.RootDispersion
		copy(e.ReferenceID[:], v.ReferenceId)
		e.AssociationID, e.Truncated = v.AssociationId, v.Truncated
		pairs := []struct {
			p *eventsv1.NTPTimestamp
			t *events.NTPTimestamp
		}{{v.Reference, &e.Reference}, {v.Origin, &e.Origin}, {v.Receive, &e.Receive}, {v.Transmit, &e.Transmit}}
		for _, p := range pairs {
			t, err := decodeNTPTimestamp(p.p)
			if err != nil {
				return nil, err
			}
			*p.t = t
		}
		var err error
		e.Association, err = associationFromWire(v.Association)
		return e, err
	case *eventsv1.ProtocolEvent_KnownHost:
		if p == nil {
			return nil, errors.New("nil network payload wrapper")
		}
		v := p.KnownHost
		if v == nil {
			return nil, errors.New("nil known host payload")
		}
		e := events.NewKnownHostEvent(env)
		var err error
		if e.Host, err = netip.ParseAddr(v.Host); err != nil {
			return nil, err
		}
		e.Evidence, err = evidenceFromWire(v.Evidence)
		return e, err
	case *eventsv1.ProtocolEvent_KnownService:
		if p == nil {
			return nil, errors.New("nil network payload wrapper")
		}
		v := p.KnownService
		if v == nil || v.Port > 65535 || v.Transport > 255 {
			return nil, errors.New("invalid known service payload or numeric range")
		}
		e := events.NewKnownServiceEvent(env)
		var err error
		if e.Host, err = netip.ParseAddr(v.Host); err != nil {
			return nil, err
		}
		e.Port, e.Transport, e.Protocol = uint16(v.Port), uint8(v.Transport), v.Protocol
		e.Evidence, err = evidenceFromWire(v.Evidence)
		return e, err
	}
	return nil, fmt.Errorf("unsupported network payload %T", in.Payload)
}

func encodeNetwork(out *eventsv1.ProtocolEvent, ev events.Event) {
	switch e := ev.(type) {
	case events.DHCPEvent:
		e = e.Clone()
		out.Payload = &eventsv1.ProtocolEvent_Dhcp{Dhcp: &eventsv1.DHCPEvent{Operation: uint32(e.Operation), MessageType: uint32(e.MessageType), HardwareType: uint32(e.HardwareType), TransactionId: e.TransactionID, HardwareAddress: e.HardwareAddress, ClientIdentifier: e.ClientIdentifier, ClientAddress: addrString(e.ClientAddress), OfferedAddress: addrString(e.OfferedAddress), NextServerAddress: addrString(e.NextServerAddress), RelayAddress: addrString(e.RelayAddress), ServerIdentifier: addrString(e.ServerIdentifier), RequestedAddress: addrString(e.RequestedAddress), Hostname: e.Hostname, Domain: e.Domain, LeaseSeconds: e.LeaseSeconds, Routers: addrStrings(e.Routers), DnsServers: addrStrings(e.DNSServers), ParameterRequestList: e.ParameterRequestList, Association: associationToWire(e.Association), AssociationId: e.AssociationID, Truncated: e.Truncated}}
	case events.NTPEvent:
		out.Payload = &eventsv1.ProtocolEvent_Ntp{Ntp: &eventsv1.NTPEvent{Version: uint32(e.Version), Mode: uint32(e.Mode), LeapIndicator: uint32(e.LeapIndicator), Stratum: uint32(e.Stratum), Poll: int32(e.Poll), Precision: int32(e.Precision), RootDelay: e.RootDelay, RootDispersion: e.RootDispersion, ReferenceId: bytes.Clone(e.ReferenceID[:]), Reference: encodeNTPTimestamp(e.Reference), Origin: encodeNTPTimestamp(e.Origin), Receive: encodeNTPTimestamp(e.Receive), Transmit: encodeNTPTimestamp(e.Transmit), Association: associationToWire(e.Association), AssociationId: e.AssociationID, Truncated: e.Truncated}}
	case events.KnownHostEvent:
		out.Payload = &eventsv1.ProtocolEvent_KnownHost{KnownHost: &eventsv1.KnownHostEvent{Host: e.Host.String(), Evidence: evidenceToWire(e.Evidence)}}
	case events.KnownServiceEvent:
		out.Payload = &eventsv1.ProtocolEvent_KnownService{KnownService: &eventsv1.KnownServiceEvent{Host: e.Host.String(), Port: uint32(e.Port), Transport: uint32(e.Transport), Protocol: e.Protocol, Evidence: evidenceToWire(e.Evidence)}}
	}
}

func validateAssociation(a events.AssociationStatus, id string) error {
	if associationToWire(a) == 0 {
		return errors.New("invalid association status")
	}
	if len(id) > 256 || !utf8.ValidString(id) {
		return errors.New("invalid association identifier")
	}
	if a == events.AssociationUnique && id == "" {
		return errors.New("unique association requires an identifier")
	}
	return nil
}
func safeName(s string) bool { return dhcp.ValidName(s) }
func validateSubject(a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") {
		return errors.New("invalid inventory subject")
	}
	return nil
}
func validateEvidence(e events.InventoryEvidence, transport uint8) error {
	if evidenceToWire(e) == 0 {
		return errors.New("invalid inventory evidence")
	}
	if (e == events.EvidenceTCPHandshake && transport != 6) || (e != events.EvidenceTCPHandshake && transport != 17) {
		return errors.New("inventory evidence does not match transport")
	}
	return nil
}
func validateNetwork(ev events.Event) error {
	switch e := ev.(type) {
	case events.DHCPEvent:
		if e.Envelope().Flow.Protocol != 17 || (e.Operation != 1 && e.Operation != 2) || e.MessageType < 1 || e.MessageType > 8 || e.HardwareType == 0 {
			return errors.New("invalid DHCP header or transport")
		}
		if len(e.HardwareAddress) > 16 || len(e.ClientIdentifier) > dhcp.MaxIdentifierBytes || len(e.ParameterRequestList) > dhcp.MaxParameterRequestBytes || len(e.Routers) > dhcp.MaxAddresses || len(e.DNSServers) > dhcp.MaxAddresses {
			return errors.New("DHCP field exceeds limit")
		}
		if !safeName(e.Hostname) || !safeName(e.Domain) {
			return errors.New("invalid DHCP name")
		}
		for _, a := range []netip.Addr{e.ClientAddress, e.OfferedAddress, e.NextServerAddress, e.RelayAddress} {
			if !a.Is4() {
				return errors.New("DHCP header address must be IPv4")
			}
		}
		for _, a := range []netip.Addr{e.ServerIdentifier, e.RequestedAddress} {
			if a.IsValid() && !a.Is4() {
				return errors.New("DHCP option address must be IPv4")
			}
		}
		for _, as := range [][]netip.Addr{e.Routers, e.DNSServers} {
			for _, a := range as {
				if !a.Is4() {
					return errors.New("DHCP list address must be IPv4")
				}
			}
		}
		if e.Truncated && !e.Envelope().Partial {
			return errors.New("truncated DHCP event must be partial")
		}
		return validateAssociation(e.Association, e.AssociationID)
	case events.NTPEvent:
		if e.Envelope().Flow.Protocol != 17 || e.Version < 1 || e.Version > 4 || e.Mode < 1 || e.Mode > 5 || e.LeapIndicator > 3 {
			return errors.New("invalid NTP header or transport")
		}
		for _, t := range []events.NTPTimestamp{e.Reference, e.Origin, e.Receive, e.Transmit} {
			expected := ntp.ResolveTimestamp(t.Raw, e.Envelope().Timestamp)
			if !t.Time.Equal(expected.Time) {
				return errors.New("NTP timestamp does not match raw value and capture era")
			}
			if !t.Time.IsZero() {
				if err := timestamppb.New(t.Time).CheckValid(); err != nil {
					return err
				}
			}
		}
		if e.Truncated && !e.Envelope().Partial {
			return errors.New("truncated NTP event must be partial")
		}
		return validateAssociation(e.Association, e.AssociationID)
	case events.KnownHostEvent:
		if err := validateSubject(e.Host); err != nil {
			return err
		}
		return validateEvidence(e.Evidence, e.Envelope().Flow.Protocol)
	case events.KnownServiceEvent:
		if err := validateSubject(e.Host); err != nil {
			return err
		}
		if e.Port == 0 || e.Transport != e.Envelope().Flow.Protocol || e.Protocol == "" || len(e.Protocol) > 64 || strings.Trim(e.Protocol, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
			return errors.New("invalid inventory service")
		}
		if e.Evidence == events.EvidenceUDPBidirectional {
			return errors.New("service requires decoded protocol evidence")
		}
		if err := validateEvidence(e.Evidence, e.Transport); err != nil {
			return err
		}
		if e.Transport == 17 {
			expected := map[events.InventoryEvidence]string{events.EvidenceDNSExchange: "dns", events.EvidenceNTPExchange: "ntp", events.EvidenceDHCPExchange: "dhcp"}
			if expected[e.Evidence] != e.Protocol {
				return errors.New("service protocol does not match evidence")
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported network event %T", ev)
}
