package records

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
)

func networkRecord(name string, env events.Envelope, middle ...any) (logstream.Record, bool, error) {
	values := []any{env.Timestamp, env.UID, env.Flow.SourceAddress, env.Flow.SourcePort, env.Flow.DestinationAddress, env.Flow.DestinationPort, protocolName(env.Flow.Protocol)}
	values = append(values, middle...)
	values = append(values, env.CommunityID, env.NodeID, string(env.CaptureScope), env.Partial)
	record, err := logstream.NewRecord(name, values...)
	return record, err == nil, err
}
func optionalAddresses(value []netip.Addr) any {
	if value == nil {
		return logstream.Unset
	}
	return value
}

func optionalText(value string) any {
	if value == "" {
		return logstream.Unset
	}
	return value
}
func optionalTime(value time.Time) any {
	if value.IsZero() {
		return logstream.Unset
	}
	return value
}
func optionalHex(value []byte) any {
	if value == nil {
		return logstream.Unset
	}
	return hex.EncodeToString(value)
}

// DHCP preserves observed message direction and optional-field presence.
func DHCP(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.DHCPEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected DHCP event, got %T", event)
	}
	var lease any = logstream.Unset
	if ev.LeaseSeconds != nil {
		lease = *ev.LeaseSeconds
	}
	var parameters any = logstream.Unset
	if ev.ParameterRequestList != nil {
		values := make([]uint64, len(ev.ParameterRequestList))
		for i, v := range ev.ParameterRequestList {
			values[i] = uint64(v)
		}
		parameters = values
	}
	return networkRecord("dhcp", ev.Envelope(), ev.Operation, ev.MessageType, ev.TransactionID, ev.HardwareType,
		optionalHex(ev.HardwareAddress), optionalHex(ev.ClientIdentifier), ev.ClientAddress, ev.OfferedAddress, ev.NextServerAddress, ev.RelayAddress,
		ev.ServerIdentifier, ev.RequestedAddress, optionalText(ev.Hostname), optionalText(ev.Domain), lease, optionalAddresses(ev.Routers), optionalAddresses(ev.DNSServers), parameters,
		string(ev.Association), optionalText(ev.AssociationID), ev.Truncated)
}
func NTP(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.NTPEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected NTP event, got %T", event)
	}
	return networkRecord("ntp", ev.Envelope(), ev.Version, ev.Mode, ev.LeapIndicator, ev.Stratum, ev.Poll, ev.Precision, ev.RootDelay, ev.RootDispersion,
		hex.EncodeToString(ev.ReferenceID[:]), fmt.Sprintf("%016x", ev.Reference.Raw), fmt.Sprintf("%016x", ev.Origin.Raw), fmt.Sprintf("%016x", ev.Receive.Raw), fmt.Sprintf("%016x", ev.Transmit.Raw),
		optionalTime(ev.Reference.Time), optionalTime(ev.Origin.Time), optionalTime(ev.Receive.Time), optionalTime(ev.Transmit.Time), string(ev.Association), optionalText(ev.AssociationID), ev.Truncated)
}
func KnownHosts(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.KnownHostEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected known host event, got %T", event)
	}
	return networkRecord("known_hosts", ev.Envelope(), ev.Host, string(ev.Evidence))
}
func KnownServices(event events.Event) (logstream.Record, bool, error) {
	ev, ok := event.(events.KnownServiceEvent)
	if !ok {
		return logstream.Record{}, false, fmt.Errorf("expected known service event, got %T", event)
	}
	return networkRecord("known_services", ev.Envelope(), ev.Host, ev.Port, protocolName(ev.Transport), ev.Protocol, string(ev.Evidence))
}
