package eventanalysis

import (
	"crypto/sha256"
	"fmt"
	"net/netip"

	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/dhcp"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/ntp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// associationScope is independent of flow direction, since DHCP exchanges span
// multiple broadcast/unicast flows. Quoted components avoid delimiter aliases.
type associationScopeKey struct {
	node, analysisEpoch, captureEpoch, captureSource, interfaceName, inputFile string
	generation                                                                 uint64
	interfaceIndex                                                             uint32
}

func (r *Runtime) associationScope(source Source, env events.Envelope) string {
	p := env.Provenance
	key := associationScopeKey{env.NodeID, r.cfg.AnalysisEpoch, source.CaptureEpoch, p.CaptureSource, p.InterfaceName, p.InputFile, r.generation, p.InterfaceIndex}
	if !r.associationValid || key != r.associationKey {
		r.associationKey = key
		r.associationValue = fmt.Sprintf("%q/%q/%q/%d/%q/%q/%d/%q", env.NodeID, r.cfg.AnalysisEpoch, source.CaptureEpoch, r.generation, p.CaptureSource, p.InterfaceName, p.InterfaceIndex, p.InputFile)
		r.associationDigest = sha256.Sum256([]byte(r.associationValue))
		r.associationValid = true
	}
	return r.associationValue
}

func (r *Runtime) observeNetworkDatagram(source Source, env events.Envelope, packet gopacket.Packet, captureTruncated bool) *conntrack.UDPEvidence {
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok {
		return nil
	}
	// A transport port only selects a parser; it is never protocol evidence.
	if udp.SrcPort == 67 || udp.SrcPort == 68 || udp.DstPort == 67 || udp.DstPort == 68 {
		message, err := dhcp.Decode(udp.Payload)
		if message == nil || message.MessageType == 0 {
			return nil
		}
		if err != nil {
			r.stats.Invalid++
		}
		message.Partial = message.Partial || captureTruncated
		message.Truncated = message.Truncated || captureTruncated
		association := r.dhcp.Observe(r.associationScope(source, env), env.Timestamp, message)
		env.Partial = env.Partial || message.Partial
		ev := events.NewDHCPEvent(env)
		ev.Operation, ev.MessageType, ev.HardwareType = message.Operation, message.MessageType, message.HardwareType
		ev.TransactionID = message.TransactionID
		ev.HardwareAddress, ev.ClientIdentifier, ev.ParameterRequestList = message.HardwareAddress, message.ClientIdentifier, message.ParameterRequestList
		ev.ClientAddress, ev.OfferedAddress, ev.NextServerAddress, ev.RelayAddress = message.ClientAddress, message.OfferedAddress, message.NextServerAddress, message.RelayAddress
		ev.ServerIdentifier, ev.RequestedAddress = message.ServerIdentifier, message.RequestedAddress
		ev.Hostname, ev.Domain, ev.LeaseSeconds = message.Hostname, message.Domain, message.LeaseSeconds
		ev.Routers, ev.DNSServers = message.Routers, message.DNSServers
		ev.Association, ev.AssociationID, ev.Truncated = events.AssociationStatus(association.Status), association.ID, message.Truncated
		r.emit(ev.Clone())
		if !r.cfg.Policy.Inventory.Enabled || message.Partial || message.Truncated || (message.RelayAddress.IsValid() && !message.RelayAddress.IsUnspecified()) || !r.unicastEndpoints(env.Flow) {
			return nil
		}
		role := conntrack.UDPRequest
		if message.Role() == dhcp.RoleResponse {
			role = conntrack.UDPResponse
		}
		if association.Status != dhcp.AssociationRequest && association.Status != dhcp.AssociationUnique {
			return nil
		}
		return &conntrack.UDPEvidence{Protocol: "dhcp", Role: role, Key: sha256.Sum256([]byte(association.ID)), Matched: association.Status == dhcp.AssociationUnique}
	}
	if udp.SrcPort != 123 && udp.DstPort != 123 {
		return r.dnsInventoryEvidence(udp, env, captureTruncated)
	}
	observation, err := ntp.Decode(udp.Payload, env.Timestamp)
	if err != nil {
		return nil
	}
	observation.Partial = observation.Partial || captureTruncated
	observation.Truncated = observation.Truncated || captureTruncated
	association := r.ntp.Observe(r.associationScope(source, env), netip.AddrPortFrom(env.Flow.SourceAddress, env.Flow.SourcePort), netip.AddrPortFrom(env.Flow.DestinationAddress, env.Flow.DestinationPort), env.Timestamp, &observation)
	env.Partial = env.Partial || observation.Partial
	ev := events.NewNTPEvent(env)
	ev.Version, ev.Mode, ev.LeapIndicator, ev.Stratum = observation.Version, observation.Mode, observation.LeapIndicator, observation.Stratum
	ev.Poll, ev.Precision, ev.RootDelay, ev.RootDispersion = observation.Poll, observation.Precision, observation.RootDelay, observation.RootDispersion
	ev.ReferenceID = observation.ReferenceID
	ev.Reference, ev.Origin, ev.Receive, ev.Transmit = ntpTimestamp(observation.Reference), ntpTimestamp(observation.Origin), ntpTimestamp(observation.Receive), ntpTimestamp(observation.Transmit)
	ev.Association, ev.AssociationID, ev.Truncated = events.AssociationStatus(association.Status), association.ID, observation.Truncated
	r.emit(ev)
	if !r.cfg.Policy.Inventory.Enabled || observation.Partial || observation.Truncated || !r.unicastEndpoints(env.Flow) || (association.Status != ntp.AssociationRequest && association.Status != ntp.AssociationUnique) {
		return nil
	}
	role := conntrack.UDPRequest
	if observation.Mode == 4 {
		role = conntrack.UDPResponse
	}
	return &conntrack.UDPEvidence{Protocol: "ntp", Role: role, Key: sha256.Sum256([]byte(association.ID)), Matched: association.Status == ntp.AssociationUnique}
}
func ntpTimestamp(t ntp.Timestamp) events.NTPTimestamp {
	return events.NTPTimestamp{Raw: t.Raw, Time: t.Time}
}
