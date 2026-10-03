package conntrack

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/stretchr/testify/require"
)

func evidenceTracker(t *testing.T) *Tracker {
	t.Helper()
	tr, err := New(Config{MaxFlows: 16, IdleTimeout: time.Minute, HalfOpenTimeout: time.Second})
	require.NoError(t, err)
	return tr
}
func tcpObservation(n int, reverse bool, flags TCPFlags) Observation {
	return Observation{Envelope: testEnv(time.Unix(1000+int64(n), 0), reverse), TCP: &flags, InventoryEligible: true, AnalysisScope: "epoch-a"}
}
func tcpHandshake() []Observation {
	return []Observation{
		tcpObservation(0, false, TCPFlags{SYN: true, Sequence: 100, SequenceValid: true}),
		tcpObservation(1, true, TCPFlags{SYN: true, ACK: true, Sequence: 200, Acknowledgment: 101, SequenceValid: true}),
		tcpObservation(2, false, TCPFlags{ACK: true, Sequence: 101, Acknowledgment: 201, SequenceValid: true}),
	}
}
func observeEvidence(t *testing.T, tr *Tracker, observations ...Observation) {
	t.Helper()
	for _, o := range observations {
		_, err := tr.Observe(o)
		require.NoError(t, err)
	}
}

func TestInventoryTCPNeedsWireHandshakeAndAnalyzedService(t *testing.T) {
	tr := evidenceTracker(t)
	observations := tcpHandshake()
	observations[0].Envelope.CaptureScope = events.CaptureScopeFiltered
	observeEvidence(t, tr, observations...)
	require.NoError(t, tr.SetService(observations[2].Envelope, "port_hint", "epoch-a"))
	// Generic labels cannot establish service identity.
	s := tr.shardFor(trackerKeyForTest(t, observations[0]))
	s.Lock()
	for _, f := range s.flows {
		require.Empty(t, f.inventory.evidence().Service)
	}
	s.Unlock()
	require.NoError(t, tr.SetAnalyzedService(observations[2].Envelope, "epoch-a", "TLS", true))
	got := tr.Close()
	require.Len(t, got, 1)
	require.Equal(t, events.EvidenceTCPHandshake, got[0].Evidence.Host)
	require.Equal(t, events.EvidenceTCPHandshake, got[0].Evidence.Service)
	require.Equal(t, "tls", got[0].Evidence.Protocol)
	require.Equal(t, netip.MustParseAddrPort("198.51.100.2:443"), got[0].Evidence.Responder)
	require.True(t, got[0].Envelope().Partial)
	require.Equal(t, "epoch-a", got[0].AnalysisScope)
	encoded, err := json.Marshal(got[0])
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "Evidence")
	require.NotContains(t, string(encoded), "AnalysisScope")
	require.NotContains(t, string(encoded), "epoch-a")
}

func trackerKeyForTest(t *testing.T, o Observation) trackerKey {
	t.Helper()
	key, err := flowid.Normalize(o.Envelope.Flow)
	require.NoError(t, err)
	return trackerKeyForEnvelope(key, o.Envelope, o.AnalysisScope)
}

func TestInventoryTCPRejectsInsufficientEvidence(t *testing.T) {
	cases := []string{"syn", "synack", "midstream", "wrong_synack", "wrong_final_ack", "wrong_final_seq", "legacy_flags", "ineligible_syn", "ineligible_ack", "out_of_order", "reset", "fin", "scope", "unproven_service"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			tr := evidenceTracker(t)
			o := tcpHandshake()
			switch name {
			case "syn":
				o = o[:1]
			case "synack":
				o = o[1:]
			case "midstream":
				o = o[2:]
			case "wrong_synack":
				o[1].TCP.Acknowledgment++
			case "wrong_final_ack":
				o[2].TCP.Acknowledgment++
			case "wrong_final_seq":
				o[2].TCP.Sequence++
			case "legacy_flags":
				for i := range o {
					o[i].TCP.SequenceValid = false
				}
			case "ineligible_syn":
				o[0].InventoryEligible = false
			case "ineligible_ack":
				o[2].InventoryEligible = false
			case "out_of_order":
				o[2].Envelope.Timestamp = o[0].Envelope.Timestamp
			case "reset":
				o[1].TCP.RST = true
			case "fin":
				o[2].TCP.FIN = true
			case "scope":
				o[1].AnalysisScope = "epoch-b"
			case "unproven_service":
				o = o[:1]
				o[0].Service = "http"
			}
			observeEvidence(t, tr, o...)
			require.NoError(t, tr.SetAnalyzedService(o[len(o)-1].Envelope, "epoch-a", "HTTP", true))
			for _, e := range tr.Close() {
				require.Empty(t, e.Evidence.Host)
				require.Empty(t, e.Evidence.Service)
			}
		})
	}
}

func TestInventoryTCPSequenceWrapRetransmissionAndLateAnalysis(t *testing.T) {
	tr := evidenceTracker(t)
	o := tcpHandshake()
	o[0].TCP.Sequence = ^uint32(0)
	o[1].TCP.Acknowledgment = 0
	o[2].TCP.Sequence = 0
	observeEvidence(t, tr, o[0], o[1], o[0], o[2])
	require.NoError(t, tr.SetAnalyzedService(o[0].Envelope, "epoch-a", "HTTP", true))
	require.NoError(t, tr.SetAnalyzedService(o[2].Envelope, "epoch-a", "HTTP", false))
	got := tr.Close()
	require.Equal(t, events.EvidenceTCPHandshake, got[0].Evidence.Host)
	require.Empty(t, got[0].Evidence.Service)
}

func udpObservation(n int, reverse bool, protocol string, role UDPRole, key byte, matched bool) Observation {
	o := tcpObservation(n, reverse, TCPFlags{})
	o.TCP = nil
	o.Envelope.Flow.Protocol = 17
	if protocol != "" {
		o.UDP = &UDPEvidence{Protocol: protocol, Role: role, Key: [32]byte{key}, Matched: matched}
	}
	return o
}
func TestInventoryUDPRequiresMatchedDecodedSameFlowRequests(t *testing.T) {
	for _, protocol := range []string{"dns", "ntp", "dhcp"} {
		t.Run(protocol, func(t *testing.T) {
			tr := evidenceTracker(t)
			observeEvidence(t, tr, udpObservation(0, false, protocol, UDPRequest, 1, false), udpObservation(1, true, protocol, UDPResponse, 1, true))
			got := tr.Close()
			require.Equal(t, events.EvidenceUDPBidirectional, got[0].Evidence.Host)
			require.NotEmpty(t, got[0].Evidence.Service)
			require.Equal(t, protocol, got[0].Evidence.Protocol)
			require.Equal(t, netip.MustParseAddrPort("198.51.100.2:443"), got[0].Evidence.Responder)
		})
	}
	cases := []string{"one_way", "label_only", "unmatched", "wrong_key", "same_direction", "wrong_scope", "ineligible_request", "ineligible_response", "out_of_order", "expired_request", "unsupported", "response_only", "symmetric"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			tr := evidenceTracker(t)
			request := udpObservation(0, false, "dns", UDPRequest, 1, false)
			reply := udpObservation(1, true, "dns", UDPResponse, 1, true)
			var input []Observation
			switch name {
			case "one_way":
				reply = request
			case "label_only":
				request.UDP = nil
				reply.UDP = nil
				request.Service = "dns"
				reply.Service = "dns"
			case "unmatched":
				reply.UDP.Matched = false
			case "wrong_key":
				reply.UDP.Key[0] = 2
			case "same_direction":
				reply.Envelope.Flow = request.Envelope.Flow
			case "wrong_scope":
				reply.AnalysisScope = "epoch-b"
			case "ineligible_request":
				request.InventoryEligible = false
			case "ineligible_response":
				reply.InventoryEligible = false
			case "out_of_order":
				reply.Envelope.Timestamp = request.Envelope.Timestamp.Add(-time.Second)
			case "expired_request":
				reply.Envelope.Timestamp = request.Envelope.Timestamp.Add(time.Minute)
			case "unsupported":
				request.UDP.Protocol = "cached_label"
				reply.UDP.Protocol = "cached_label"
			case "response_only":
				request.UDP.Role = UDPResponse
			case "symmetric":
				input = append(input, request, reply)
				request = udpObservation(2, true, "dns", UDPRequest, 2, false)
				reply = udpObservation(3, false, "dns", UDPResponse, 2, true)
			}
			input = append(input, request, reply)
			observeEvidence(t, tr, input...)
			for _, got := range tr.Close() {
				require.Empty(t, got.Evidence.Service)
				if name == "one_way" || name == "ineligible_request" || name == "ineligible_response" || name == "out_of_order" || name == "wrong_scope" {
					require.Empty(t, got.Evidence.Host)
				}
			}
		})
	}
}

func TestInventoryUDPSlotsAndSpecialEndpoints(t *testing.T) {
	tr := evidenceTracker(t)
	for i := 0; i < inventoryRequestSlots+1; i++ {
		observeEvidence(t, tr, udpObservation(i, false, "dns", UDPRequest, byte(i), false))
	}
	observeEvidence(t, tr, udpObservation(20, true, "dns", UDPResponse, 0, true))
	got := tr.Close()
	require.Empty(t, got[0].Evidence.Service)
	for _, special := range []string{"0.0.0.0", "255.255.255.255", "224.0.0.1"} {
		tr = evidenceTracker(t)
		request := udpObservation(0, false, "dhcp", UDPRequest, 1, false)
		reply := udpObservation(1, true, "dhcp", UDPResponse, 1, true)
		request.Envelope.Flow.DestinationAddress = netip.MustParseAddr(special)
		reply.Envelope.Flow.SourceAddress = request.Envelope.Flow.DestinationAddress
		observeEvidence(t, tr, request, reply)
		require.Empty(t, tr.Close()[0].Evidence.Service)
	}
}

func TestInventoryEvidenceOnExpiryEvictionAndScopeOrdering(t *testing.T) {
	tr := evidenceTracker(t)
	observeEvidence(t, tr, tcpHandshake()...)
	got := tr.Expire(time.Unix(2000, 0))
	require.Len(t, got, 1)
	require.Equal(t, events.EvidenceTCPHandshake, got[0].Evidence.Host)
	require.Empty(t, tr.Close())
	tr = evidenceTracker(t)
	tr.cfg.MaxFlows = 1
	observeEvidence(t, tr, tcpHandshake()...)
	other := tcpHandshake()[0]
	other.AnalysisScope = "epoch-b"
	other.Envelope.Timestamp = time.Unix(1003, 0)
	got, err := tr.Observe(other)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, events.EvidenceTCPHandshake, got[0].Evidence.Host)
	tr = evidenceTracker(t)
	for _, scope := range []string{"z", "a", "m"} {
		o := tcpHandshake()[0]
		o.AnalysisScope = scope
		observeEvidence(t, tr, o)
	}
	got = tr.Close()
	require.Equal(t, "a", got[0].AnalysisScope)
	require.Equal(t, "m", got[1].AnalysisScope)
	require.Equal(t, "z", got[2].AnalysisScope)
}

func TestDisabledInventoryRetainsNoProofState(t *testing.T) {
	tr := evidenceTracker(t)
	observations := tcpHandshake()
	for i := range observations {
		observations[i].InventoryEligible = false
	}
	observeEvidence(t, tr, observations...)
	last := observations[len(observations)-1]
	// A parser callback may update the display label, but cannot create evidence
	// storage for a flow whose packet path never enabled inventory.
	require.NoError(t, tr.SetAnalyzedService(last.Envelope, last.AnalysisScope, "HTTP", true))
	for i := range tr.shards {
		shard := &tr.shards[i]
		shard.Lock()
		for _, flow := range shard.flows {
			require.Nil(t, flow.inventory)
		}
		shard.Unlock()
	}
	got := tr.Close()
	require.Len(t, got, 1)
	require.Empty(t, got[0].Evidence)
	require.Equal(t, "HTTP", got[0].Service)
}

func TestInventoryUDPLinkLocalServiceEvidence(t *testing.T) {
	for _, addresses := range [][2]string{{"fe80::20", "fe80::53"}, {"169.254.1.20", "169.254.1.53"}} {
		tr := evidenceTracker(t)
		request := udpObservation(0, false, "dns", UDPRequest, 1, false)
		request.Envelope.Flow.SourceAddress = netip.MustParseAddr(addresses[0])
		request.Envelope.Flow.DestinationAddress = netip.MustParseAddr(addresses[1])
		response := request
		response.Envelope.Timestamp = response.Envelope.Timestamp.Add(time.Second)
		response.Envelope.Flow.SourceAddress, response.Envelope.Flow.DestinationAddress = response.Envelope.Flow.DestinationAddress, response.Envelope.Flow.SourceAddress
		response.Envelope.Flow.SourcePort, response.Envelope.Flow.DestinationPort = response.Envelope.Flow.DestinationPort, response.Envelope.Flow.SourcePort
		response.UDP = &UDPEvidence{Protocol: "dns", Role: UDPResponse, Key: request.UDP.Key, Matched: true}
		observeEvidence(t, tr, request, response)
		records := tr.Close()
		require.Len(t, records, 1)
		require.Equal(t, events.EvidenceDNSExchange, records[0].Evidence.Service)
		require.Equal(t, netip.MustParseAddr(addresses[1]), records[0].Evidence.Responder.Addr())
	}
	for _, endpoint := range []string{"[::]:53", "[ff02::1]:53", "0.0.0.0:53", "255.255.255.255:53", "224.0.0.1:53", "192.0.2.53:0"} {
		require.False(t, unicastServiceEndpoint(netip.MustParseAddrPort(endpoint)))
	}
}
