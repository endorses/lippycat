package protoadapter

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/dhcp"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/ntp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func networkEvents() []events.Event {
	env := testEnvelope(1)
	env.Flow.Protocol = 17
	env.Flow.DestinationAddress = netip.MustParseAddr("255.255.255.255")
	d := events.NewDHCPEvent(env)
	d.Operation, d.MessageType, d.HardwareType, d.TransactionID = 2, 5, 1, 0xffffffff
	d.HardwareAddress = []byte{0, 1, 2, 3, 4, 255}
	d.ClientIdentifier = []byte{0, 255, 128, 0}
	d.ClientAddress = netip.IPv4Unspecified()
	d.OfferedAddress = netip.MustParseAddr("192.0.2.4")
	d.NextServerAddress = netip.MustParseAddr("192.0.2.5")
	d.RelayAddress = netip.MustParseAddr("192.0.2.6")
	d.ServerIdentifier = netip.MustParseAddr("192.0.2.7")
	d.RequestedAddress = d.OfferedAddress
	d.Hostname, d.Domain = "host", "example.test"
	zero := uint32(0)
	d.LeaseSeconds = &zero
	d.Routers = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	d.DNSServers = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	d.ParameterRequestList = []byte{1, 3, 6, 255}
	d.Association, d.AssociationID, d.Truncated = events.AssociationUnique, "scoped-exchange", true
	n := events.NewNTPEvent(env)
	n.Version, n.Mode, n.LeapIndicator, n.Stratum = 4, 4, 3, 255
	n.Poll, n.Precision = -128, 127
	n.RootDelay, n.RootDispersion = -2147483648, 0xffffffff
	n.ReferenceID = [4]byte{0, 255, 128, 32}
	n.Association, n.AssociationID, n.Truncated = events.AssociationUnique, "request-1", true
	for i, t := range []*events.NTPTimestamp{&n.Reference, &n.Origin, &n.Receive, &n.Transmit} {
		raw := uint64(i) * 0xffffffff00000001
		value := ntp.ResolveTimestamp(raw, env.Timestamp)
		*t = events.NTPTimestamp{Raw: raw, Time: value.Time}
	}
	h := events.NewKnownHostEvent(env)
	h.Host = netip.MustParseAddr("2001:db8::7")
	h.Evidence = events.EvidenceUDPBidirectional
	s := events.NewKnownServiceEvent(env)
	s.Host = netip.MustParseAddr("192.0.2.8")
	s.Port, s.Transport, s.Protocol, s.Evidence = 123, 17, "ntp", events.EvidenceNTPExchange
	return []events.Event{d, n, h, s}
}

func TestNetworkContractRoundTripOwnershipAndUnknownFields(t *testing.T) {
	for _, want := range networkEvents() {
		t.Run(string(want.Kind()), func(t *testing.T) {
			var pointer events.Event
			switch e := want.(type) {
			case events.DHCPEvent:
				pointer = &e
			case events.NTPEvent:
				pointer = &e
			case events.KnownHostEvent:
				pointer = &e
			case events.KnownServiceEvent:
				pointer = &e
			}
			wire, err := ToProto(pointer)
			require.NoError(t, err)
			unknown := protowire.AppendTag(nil, 200, protowire.BytesType)
			unknown = protowire.AppendString(unknown, "future")
			wire.ProtoReflect().SetUnknown(unknown)
			wire.Envelope.ProtoReflect().SetUnknown(unknown)
			if wire.GetDhcp() != nil {
				wire.GetDhcp().ProtoReflect().SetUnknown(unknown)
			}
			data, err := proto.Marshal(wire)
			require.NoError(t, err)
			parsed := new(eventsv1.ProtocolEvent)
			require.NoError(t, proto.Unmarshal(data, parsed))
			decoded, err := DecodeEvent(parsed)
			require.NoError(t, err)
			require.Nil(t, decoded.Omission)
			require.Equal(t, want, decoded.Event)
			require.True(t, proto.Equal(wire, decoded.Wire))
			decoded.Wire.Envelope.Provenance.ProcessorNodeIds[0] = "changed"
			require.Equal(t, "p1", decoded.Event.Envelope().Provenance.ProcessorNodeIDs[0])
			require.Equal(t, "p1", parsed.Envelope.Provenance.ProcessorNodeIds[0])
			if d, ok := want.(events.DHCPEvent); ok {
				wire.GetDhcp().HardwareAddress[0] = 99
				require.Equal(t, byte(0), d.HardwareAddress[0])
				parsed.GetDhcp().ClientIdentifier[0] = 99
				require.Equal(t, byte(0), decoded.Event.(events.DHCPEvent).ClientIdentifier[0])
				*wire.GetDhcp().LeaseSeconds = 99
				require.Zero(t, *d.LeaseSeconds)
			}
		})
	}
}

func TestNetworkRejectsTypedNil(t *testing.T) {
	for _, event := range []events.Event{(*events.DHCPEvent)(nil), (*events.NTPEvent)(nil), (*events.KnownHostEvent)(nil), (*events.KnownServiceEvent)(nil)} {
		_, err := ToProto(event)
		require.Error(t, err)
	}
	valid, err := ToProto(networkEvents()[0])
	require.NoError(t, err)
	for _, mutate := range []func(*eventsv1.ProtocolEvent){
		func(p *eventsv1.ProtocolEvent) { p.Payload = (*eventsv1.ProtocolEvent_Dhcp)(nil) },
		func(p *eventsv1.ProtocolEvent) { p.Payload = &eventsv1.ProtocolEvent_Dhcp{} },
		func(p *eventsv1.ProtocolEvent) { p.Payload = (*eventsv1.ProtocolEvent_Ntp)(nil) },
		func(p *eventsv1.ProtocolEvent) { p.Payload = &eventsv1.ProtocolEvent_Ntp{} },
		func(p *eventsv1.ProtocolEvent) { p.Payload = (*eventsv1.ProtocolEvent_KnownHost)(nil) },
		func(p *eventsv1.ProtocolEvent) { p.Payload = &eventsv1.ProtocolEvent_KnownHost{} },
		func(p *eventsv1.ProtocolEvent) { p.Payload = (*eventsv1.ProtocolEvent_KnownService)(nil) },
		func(p *eventsv1.ProtocolEvent) { p.Payload = &eventsv1.ProtocolEvent_KnownService{} },
	} {
		p := proto.Clone(valid).(*eventsv1.ProtocolEvent)
		mutate(p)
		require.NotPanics(t, func() { _, err := DecodeEvent(p); require.Error(t, err) })
	}
}

func TestNetworkWireValidation(t *testing.T) {
	tests := []struct {
		name   string
		index  int
		mutate func(*eventsv1.ProtocolEvent)
	}{
		{"dhcp operation overflow", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Operation = 257 }},
		{"dhcp operation", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Operation = 3 }},
		{"dhcp message type", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().MessageType = 9 }},
		{"dhcp hardware", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().HardwareAddress = make([]byte, 17) }},
		{"dhcp client id", 0, func(p *eventsv1.ProtocolEvent) {
			p.GetDhcp().ClientIdentifier = make([]byte, dhcp.MaxIdentifierBytes+1)
		}},
		{"dhcp name", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Hostname = strings.Repeat("a", 256) }},
		{"dhcp unsafe name", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Hostname = "a\x1bb" }},
		{"dhcp non utf8", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Domain = "\xff" }},
		{"dhcp IPv6", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().ClientAddress = "::1" }},
		{"dhcp mapped IPv6", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().ServerIdentifier = "::ffff:192.0.2.1" }},
		{"dhcp missing address", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().RelayAddress = "" }},
		{"dhcp invalid list", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Routers = []string{"bad"} }},
		{"dhcp list cap", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().DnsServers = make([]string, dhcp.MaxAddresses+1) }},
		{"dhcp parameter cap", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().ParameterRequestList = make([]byte, 256) }},
		{"dhcp unknown association", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Association = 99 }},
		{"dhcp unspecified association", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().Association = 0 }},
		{"dhcp empty unique id", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().AssociationId = "" }},
		{"dhcp oversized id", 0, func(p *eventsv1.ProtocolEvent) { p.GetDhcp().AssociationId = strings.Repeat("x", 257) }},
		{"dhcp truncated complete", 0, func(p *eventsv1.ProtocolEvent) { p.Envelope.Partial = false }},
		{"dhcp transport", 0, func(p *eventsv1.ProtocolEvent) { p.Envelope.Flow.Protocol = 6 }},
		{"ntp version", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Version = 5 }},
		{"ntp mode", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Mode = 6 }},
		{"ntp leap", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().LeapIndicator = 4 }},
		{"ntp poll", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Poll = 128 }},
		{"ntp precision", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Precision = -129 }},
		{"ntp stratum", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Stratum = 256 }},
		{"ntp reference id", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().ReferenceId = []byte{1, 2, 3} }},
		{"ntp missing timestamp", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Origin = nil }},
		{"ntp missing converted time", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Origin.Time = nil }},
		{"ntp zero with time", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Reference.Time = timestamppb.New(time.Unix(0, 0)) }},
		{"ntp inconsistent era", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Origin.Time.Seconds++ }},
		{"ntp malformed timestamp", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Origin.Time.Nanos = -1 }},
		{"ntp association", 1, func(p *eventsv1.ProtocolEvent) { p.GetNtp().Association = -1 }},
		{"host unspecified", 2, func(p *eventsv1.ProtocolEvent) { p.GetKnownHost().Host = "::" }},
		{"host multicast", 2, func(p *eventsv1.ProtocolEvent) { p.GetKnownHost().Host = "ff02::1" }},
		{"host broadcast", 2, func(p *eventsv1.ProtocolEvent) { p.GetKnownHost().Host = "255.255.255.255" }},
		{"host mapped", 2, func(p *eventsv1.ProtocolEvent) { p.GetKnownHost().Host = "::ffff:192.0.2.1" }},
		{"host evidence", 2, func(p *eventsv1.ProtocolEvent) { p.GetKnownHost().Evidence = 99 }},
		{"host evidence transport", 2, func(p *eventsv1.ProtocolEvent) {
			p.GetKnownHost().Evidence = eventsv1.InventoryEvidence_INVENTORY_EVIDENCE_TCP_HANDSHAKE
		}},
		{"service port", 3, func(p *eventsv1.ProtocolEvent) { p.GetKnownService().Port = 65536 }},
		{"service zero port", 3, func(p *eventsv1.ProtocolEvent) { p.GetKnownService().Port = 0 }},
		{"service label", 3, func(p *eventsv1.ProtocolEvent) { p.GetKnownService().Protocol = "NTP" }},
		{"service evidence mismatch", 3, func(p *eventsv1.ProtocolEvent) { p.GetKnownService().Protocol = "dns" }},
		{"service port-only", 3, func(p *eventsv1.ProtocolEvent) {
			p.GetKnownService().Evidence = eventsv1.InventoryEvidence_INVENTORY_EVIDENCE_UDP_BIDIRECTIONAL
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ToProto(networkEvents()[tt.index])
			require.NoError(t, err)
			tt.mutate(p)
			_, err = DecodeEvent(p)
			require.Error(t, err)
		})
	}
}

func TestNetworkOptionalLeaseAndAssociations(t *testing.T) {
	e := networkEvents()[0].(events.DHCPEvent)
	e.LeaseSeconds = nil
	e.ServerIdentifier = netip.Addr{}
	e.RequestedAddress = netip.Addr{}
	e.Routers = nil
	e.DNSServers = nil
	for _, a := range associations[1:] {
		e.Association = a
		p, err := ToProto(e)
		require.NoError(t, err)
		got, _, err := FromProto(p)
		require.NoError(t, err)
		require.Equal(t, e, got)
		require.Nil(t, p.GetDhcp().LeaseSeconds)
	}
}

func TestKindMappingSeparatesSupportFromRequirements(t *testing.T) {
	require.Len(t, SupportedKinds(false), 9)
	require.Len(t, SupportedKinds(true), 11)
	require.Equal(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9}, SupportedKindIDs(false))
	for _, kind := range SupportedKinds(true) {
		native, ok := NativeKind(kind)
		require.True(t, ok)
		wire, ok := WireKind(native)
		require.True(t, ok)
		require.Equal(t, kind, wire)
		stream, ok := StreamForKind(native)
		require.True(t, ok)
		mapped, ok := KindForStream(stream)
		require.True(t, ok)
		require.Equal(t, native, mapped)
	}
	required, err := RequiredKinds([]string{"dns", "dns", "known_hosts"})
	require.NoError(t, err)
	require.Equal(t, []eventsv1.EventKind{2, 10}, required)
	required, err = RequiredKinds(nil)
	require.NoError(t, err)
	require.Empty(t, required)
	_, err = RequiredKinds([]string{"unknown"})
	require.Error(t, err)
	_, ok := NativeKind(99)
	require.False(t, ok)
	_, ok = WireKind(events.KindFileContent)
	require.False(t, ok)
	kinds := SupportedKinds(true)
	kinds[0] = 99
	require.Equal(t, eventsv1.EventKind_EVENT_KIND_CONN, SupportedKinds(true)[0])
}

func TestNetworkNativeValidation(t *testing.T) {
	d := networkEvents()[0].(events.DHCPEvent)
	for _, mutate := range []func(*events.DHCPEvent){
		func(e *events.DHCPEvent) { e.HardwareAddress = make([]byte, 17) },
		func(e *events.DHCPEvent) { e.ClientIdentifier = make([]byte, dhcp.MaxIdentifierBytes+1) },
		func(e *events.DHCPEvent) { e.Domain = "bad\nname" },
		func(e *events.DHCPEvent) { e.Routers = []netip.Addr{{}} },
		func(e *events.DHCPEvent) { e.Association = "future" },
	} {
		e := d.Clone()
		mutate(&e)
		_, err := ToProto(e)
		require.Error(t, err)
	}
	n := networkEvents()[1].(events.NTPEvent)
	n.Precision = -128
	n.Poll = 127
	p, err := ToProto(n)
	require.NoError(t, err)
	got, _, err := FromProto(p)
	require.NoError(t, err)
	require.Equal(t, n, got)
	n.Mode = 7
	_, err = ToProto(n)
	require.Error(t, err)
	s := networkEvents()[3].(events.KnownServiceEvent)
	s.Protocol = strings.Repeat("a", 65)
	_, err = ToProto(s)
	require.Error(t, err)
}

func TestUnknownOptionalPayloadRemainsCompatibilityOmission(t *testing.T) {
	p, err := ToProto(networkEvents()[0])
	require.NoError(t, err)
	payload, err := proto.Marshal(p.GetDhcp())
	require.NoError(t, err)
	// A future payload follows the identical unknown-field behavior old peers
	// use for newly added fields 17–20. Do not turn it into an empty known event.
	p.Payload = nil
	unknown := protowire.AppendTag(nil, 21, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, payload)
	p.ProtoReflect().SetUnknown(unknown)
	decoded, err := DecodeEvent(p)
	require.NoError(t, err)
	require.Nil(t, decoded.Event)
	require.Equal(t, OmissionUnsupportedKind, decoded.Omission.Reason)
	require.True(t, proto.Equal(p, decoded.Wire))
}
