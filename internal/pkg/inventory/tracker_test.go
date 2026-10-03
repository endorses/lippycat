package inventory

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func policy() eventconfig.Inventory {
	cfg := eventconfig.Default().Inventory
	cfg.Enabled = true
	cfg.LocalCIDRs = []string{"192.0.2.0/24", "2001:db8::/32"}
	return cfg
}

func connection(transport uint8) events.ConnEvent {
	env := events.Envelope{
		Timestamp: time.Unix(100, 0), NodeID: "sensor", UID: "connection", CommunityID: "community", ProducerSessionID: "epoch", EventSequence: 1, EventID: "connection-event",
		CaptureScope: events.CaptureScopeFiltered, Partial: true,
		Flow:       events.FlowTuple{SourceAddress: netip.MustParseAddr("192.0.2.10"), DestinationAddress: netip.MustParseAddr("192.0.2.20"), SourcePort: 49152, DestinationPort: 123, Protocol: transport},
		Provenance: events.SourceProvenance{CaptureSource: "input", InputFile: "capture.pcap", InterfaceName: "eth0", ProcessorNodeIDs: []string{"upstream"}},
	}
	return events.NewConnEvent(env)
}

func TestExplicitLocalPolicy(t *testing.T) {
	cfg := policy()
	cfg.LocalCIDRs = append(cfg.LocalCIDRs, "198.51.100.0/31", "203.0.113.255/32", "::ffff:10.0.0.0/120")
	tracker, err := New(cfg)
	require.NoError(t, err)
	for _, address := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::abcd", "2001:db8::abcd%eth0", "198.51.100.0", "198.51.100.1", "203.0.113.255", "10.0.0.1"} {
		require.True(t, tracker.Local(netip.MustParseAddr(address)), address)
	}
	for _, address := range []string{"192.0.2.255", "10.0.0.255", "10.0.1.1", "172.16.0.1", "2001:db9::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"} {
		require.False(t, tracker.Local(netip.MustParseAddr(address)), address)
	}
	require.False(t, tracker.Local(netip.Addr{}))
	require.True(t, tracker.Unicast(netip.MustParseAddr("198.18.0.1")), "remote unicast does not require local membership")
	require.False(t, tracker.Unicast(netip.MustParseAddr("192.0.2.255")), "configured directed broadcast remains excluded")
	cfg.LocalCIDRs = []string{"0.0.0.0/0", "::/0", "192.0.2.0/24", "192.0.2.254/31"}
	tracker, err = New(cfg)
	require.NoError(t, err)
	require.True(t, tracker.Local(netip.MustParseAddr("192.0.2.255")), "explicit /31 overrides broader broadcast")
	for _, address := range []string{"255.255.255.255", "224.0.0.1", "ff02::1", "::", "0.0.0.0"} {
		require.False(t, tracker.Local(netip.MustParseAddr(address)))
	}
}

func TestPolicyValidationAndDisabledAllocation(t *testing.T) {
	mutators := []func(*eventconfig.Inventory){
		func(c *eventconfig.Inventory) { c.LocalCIDRs = nil },
		func(c *eventconfig.Inventory) { c.LocalCIDRs = []string{"bad"} },
		func(c *eventconfig.Inventory) { c.LocalCIDRs = []string{"::ffff:192.0.2.1/80"} },
		func(c *eventconfig.Inventory) { c.MaxEntries = 0 }, func(c *eventconfig.Inventory) { c.MaxEntries = -1 },
		func(c *eventconfig.Inventory) { c.MaxEntriesPerScope = 0 }, func(c *eventconfig.Inventory) { c.MaxEntriesPerScope = -1 },
		func(c *eventconfig.Inventory) { c.MaxBytes = 0 }, func(c *eventconfig.Inventory) { c.MaxBytes = -1 },
		func(c *eventconfig.Inventory) { c.MaxBytesPerScope = 0 }, func(c *eventconfig.Inventory) { c.MaxBytesPerScope = -1 },
		func(c *eventconfig.Inventory) { c.Retention = 0 }, func(c *eventconfig.Inventory) { c.Retention = -1 },
		func(c *eventconfig.Inventory) { c.MaxEntriesPerScope = c.MaxEntries + 1 }, func(c *eventconfig.Inventory) { c.MaxBytesPerScope = c.MaxBytes + 1 },
	}
	for i, mutate := range mutators {
		t.Run(fmt.Sprint(i), func(t *testing.T) { cfg := policy(); mutate(&cfg); _, err := New(cfg); require.Error(t, err) })
	}
	cfg := eventconfig.Default().Inventory
	tracker, err := New(cfg)
	require.NoError(t, err)
	require.Nil(t, tracker.entries)
	require.Nil(t, tracker.scopes)
	require.Nil(t, tracker.prefixes)
	require.Empty(t, tracker.Observe("sensor", time.Unix(100, 0), connection(6), Evidence{Host: events.EvidenceTCPHandshake}))
	tracker.Advance(time.Unix(200, 0))
	tracker.Reset()
	require.Equal(t, Stats{}, tracker.Stats())
	require.Nil(t, tracker.entries)
	require.Nil(t, tracker.scopes)
}

func TestEvidenceGatesAndEnvelopeOwnership(t *testing.T) {
	tracker, err := New(policy())
	require.NoError(t, err)
	conn := connection(6)
	conn.Service = "http"
	conn.OriginPackets, conn.ResponsePackets = 100, 100
	at := time.Unix(105, 0)
	require.Empty(t, tracker.Observe("sensor", at, conn, Evidence{}), "labels and bidirectional counts are not handshake proof")
	require.Empty(t, tracker.Observe("sensor", at, conn, Evidence{Host: events.EvidenceUDPBidirectional}))
	got := tracker.Observe("sensor", at, conn, Evidence{Host: events.EvidenceTCPHandshake, Service: events.EvidenceTCPHandshake, Protocol: "HTTP", Responder: netip.MustParseAddrPort("192.0.2.20:123")})
	require.Len(t, got, 3)
	require.Equal(t, events.KindKnownHost, got[0].Kind())
	require.Equal(t, events.KindKnownHost, got[1].Kind())
	require.Equal(t, events.KindKnownService, got[2].Kind())
	for _, event := range got {
		require.Equal(t, conn.Envelope(), event.Envelope())
		require.Equal(t, time.Unix(100, 0), event.Envelope().Timestamp)
	}
	require.Equal(t, "192.0.2.10", got[0].(events.KnownHostEvent).Host.String())
	service := got[2].(events.KnownServiceEvent)
	require.Equal(t, "192.0.2.20", service.Host.String())
	require.Equal(t, "http", service.Protocol)
	service.EventEnvelope.Provenance.ProcessorNodeIDs[0] = "mutated"
	require.Equal(t, []string{"upstream"}, conn.Envelope().Provenance.ProcessorNodeIDs)
	require.Equal(t, []string{"upstream"}, got[0].Envelope().Provenance.ProcessorNodeIDs)
	require.Equal(t, uint64(2), tracker.Stats().EmittedHosts)
	require.Equal(t, uint64(1), tracker.Stats().EmittedServices)
}

func TestUDPServiceRequiresAssociatedDecodedRoles(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		evidence events.InventoryEvidence
		valid    bool
	}{
		{"ntp", events.EvidenceNTPExchange, true}, {"dns", events.EvidenceDNSExchange, true}, {"dhcp", events.EvidenceDHCPExchange, true},
		{"ntp", events.EvidenceUDPBidirectional, false}, {"ntp", events.EvidenceDNSExchange, false}, {"dns", events.EvidenceTCPHandshake, false},
		{"udp", events.EvidenceNTPExchange, false}, {"unknown", events.EvidenceNTPExchange, false}, {"http", events.EvidenceNTPExchange, false}, {"ntp", "invented", false},
	} {
		t.Run(tc.protocol+string(tc.evidence), func(t *testing.T) {
			tracker, err := New(policy())
			require.NoError(t, err)
			got := tracker.Observe("sensor", time.Unix(100, 0), connection(17), Evidence{Service: tc.evidence, Protocol: tc.protocol, Responder: netip.MustParseAddrPort("192.0.2.20:123")})
			if tc.valid {
				require.Len(t, got, 1)
				require.Equal(t, events.KindKnownService, got[0].Kind())
			} else {
				require.Empty(t, got)
			}
		})
	}
	for _, responder := range []string{"192.0.2.30:123", "192.0.2.20:124", "192.0.2.20:0", "192.0.2.255:123", "224.0.0.1:123", "[::]:123"} {
		tracker, err := New(policy())
		require.NoError(t, err)
		require.Empty(t, tracker.Observe("sensor", time.Unix(100, 0), connection(17), Evidence{Service: events.EvidenceNTPExchange, Protocol: "ntp", Responder: netip.MustParseAddrPort(responder)}))
	}
}

func TestHostsLocalBothEndpointsAndServiceReverseOrientation(t *testing.T) {
	tracker, err := New(policy())
	require.NoError(t, err)
	conn := connection(17)
	env := conn.Envelope()
	env.Flow.SourceAddress, env.Flow.DestinationAddress = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db9::1")
	env.Flow.SourcePort, env.Flow.DestinationPort = 53, 49152
	conn = events.NewConnEvent(env)
	got := tracker.Observe("sensor", time.Unix(100, 0), conn, Evidence{Host: events.EvidenceUDPBidirectional, Service: events.EvidenceDNSExchange, Protocol: "dns", Responder: netip.MustParseAddrPort("[2001:db8::1]:53")})
	require.Len(t, got, 2)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), got[0].(events.KnownHostEvent).Host)
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), got[1].(events.KnownServiceEvent).Host)
	require.Equal(t, env, got[1].Envelope(), "service subject must not reorient the evidence envelope")
}

func TestDedupScopeNormalizationRetentionResetAndLateInput(t *testing.T) {
	cfg := policy()
	cfg.Retention = time.Second
	tracker, err := New(cfg)
	require.NoError(t, err)
	conn := connection(17)
	evidence := Evidence{Host: events.EvidenceUDPBidirectional}
	at := time.Unix(100, 0)
	require.Len(t, tracker.Observe("sensor/epoch/input", at, conn, evidence), 2)
	require.Empty(t, tracker.Observe("sensor/epoch/input", at.Add(500*time.Millisecond), conn, evidence))
	env := conn.Envelope()
	env.Flow.SourceAddress = netip.MustParseAddr("::ffff:192.0.2.10")
	env.Flow.DestinationAddress = netip.MustParseAddr("::ffff:192.0.2.20")
	require.Empty(t, tracker.Observe("sensor/epoch/input", at.Add(500*time.Millisecond), events.NewConnEvent(env), evidence))
	require.Len(t, tracker.Observe("another-sensor/epoch/input", at.Add(500*time.Millisecond), conn, evidence), 2)
	require.Len(t, tracker.Observe("sensor/epoch/input", at.Add(time.Second), conn, evidence), 2, "duplicates do not extend retention")
	tracker.Advance(at.Add(2 * time.Second))
	require.Zero(t, tracker.Stats().Entries)
	require.Zero(t, tracker.Stats().Scopes)
	require.Empty(t, tracker.Observe("sensor/epoch/input", at.Add(1500*time.Millisecond), conn, evidence), "late summaries cannot revive expired state")
	require.Equal(t, uint64(1), tracker.Stats().Late)
	require.Len(t, tracker.Observe("sensor/epoch/input", at.Add(2*time.Second), conn, evidence), 2)
	tracker.Reset()
	require.Zero(t, tracker.Stats().Bytes)
	require.Len(t, tracker.Observe("sensor/new-epoch/input", at, conn, evidence), 2)
}

func TestGlobalAndScopeEntryAndByteCaps(t *testing.T) {
	for _, byBytes := range []bool{false, true} {
		t.Run(fmt.Sprint(byBytes), func(t *testing.T) {
			cfg := policy()
			cfg.MaxEntries, cfg.MaxEntriesPerScope = 3, 2
			cfg.MaxBytes, cfg.MaxBytesPerScope = 10*EntryBytes, 10*EntryBytes
			if byBytes {
				cfg.MaxEntries, cfg.MaxEntriesPerScope = 10, 10
				cfg.MaxBytes, cfg.MaxBytesPerScope = 3*EntryBytes, 2*EntryBytes
			}
			tracker, err := New(cfg)
			require.NoError(t, err)
			conn := connection(17)
			evidence := Evidence{Host: events.EvidenceUDPBidirectional, Service: events.EvidenceNTPExchange, Protocol: "ntp", Responder: netip.MustParseAddrPort("192.0.2.20:123")}
			at := time.Unix(100, 0)
			require.Len(t, tracker.Observe("a", at, conn, evidence), 3)
			require.Equal(t, 2, tracker.Stats().Entries)
			require.Equal(t, uint64(1), tracker.Stats().ScopeEvicted)
			require.Len(t, tracker.Observe("b", at, conn, evidence), 3)
			s := tracker.Stats()
			require.Equal(t, 3, s.Entries)
			require.Equal(t, 3*EntryBytes, s.Bytes)
			require.Equal(t, 2, s.Scopes)
			require.Equal(t, uint64(3), s.Evicted)
			require.Equal(t, uint64(2), s.ScopeEvicted)
			// Global eviction removes the oldest first; only a's service survives.
			require.Equal(t, "a", func() string {
				if tracker.head.key.scope == sha256.Sum256([]byte("a")) {
					return "a"
				}
				return "other"
			}())
			require.True(t, tracker.head.key.service)
			require.Len(t, tracker.Observe("a", at, conn, Evidence{Host: events.EvidenceUDPBidirectional}), 2, "evicted subjects may emit again")
			tracker.Advance(at.Add(cfg.Retention))
			require.Zero(t, tracker.Stats().Entries)
			require.Zero(t, tracker.Stats().Scopes)
			require.Nil(t, tracker.head)
			require.Nil(t, tracker.tail)
		})
	}
	cfg := policy()
	cfg.MaxBytesPerScope = EntryBytes - 1
	tracker, err := New(cfg)
	require.NoError(t, err)
	require.Empty(t, tracker.Observe("a", time.Unix(100, 0), connection(6), Evidence{Host: events.EvidenceTCPHandshake}))
	require.Equal(t, uint64(2), tracker.Stats().CapacitySuppressed)
	require.Zero(t, tracker.Stats().Entries)
	require.Zero(t, tracker.Stats().Scopes)
}

func TestConcurrentObservationsAndReset(t *testing.T) {
	tracker, err := New(policy())
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tracker.Observe(fmt.Sprint(i), time.Unix(100, 0), connection(6), Evidence{Host: events.EvidenceTCPHandshake})
				tracker.Local(netip.MustParseAddr("192.0.2.1"))
				tracker.Stats()
				tracker.Advance(time.Unix(100, 0))
				if i == 0 && j == 10 {
					tracker.Reset()
				}
			}
		}(i)
	}
	wg.Wait()
	s := tracker.Stats()
	require.LessOrEqual(t, s.Entries, 32)
	require.LessOrEqual(t, s.Scopes, 16)
}

func TestServiceDedupIncludesEndpointTransportAndProtocol(t *testing.T) {
	tracker, err := New(policy())
	require.NoError(t, err)
	at := time.Unix(100, 0)
	conn := connection(6)
	evidence := Evidence{Service: events.EvidenceTCPHandshake, Protocol: "dns", Responder: netip.MustParseAddrPort("192.0.2.20:123")}
	require.Len(t, tracker.Observe("sensor", at, conn, evidence), 1)
	require.Empty(t, tracker.Observe("sensor", at, conn, evidence))
	evidence.Protocol = "http"
	require.Len(t, tracker.Observe("sensor", at, conn, evidence), 1, "recognized protocol is part of service identity")
	env := conn.Envelope()
	env.Flow.DestinationPort = 124
	evidence.Responder = netip.MustParseAddrPort("192.0.2.20:124")
	require.Len(t, tracker.Observe("sensor", at, events.NewConnEvent(env), evidence), 1, "responder port is part of service identity")
	evidence.Protocol, evidence.Service, evidence.Responder = "dns", events.EvidenceDNSExchange, netip.MustParseAddrPort("192.0.2.20:123")
	require.Len(t, tracker.Observe("sensor", at, connection(17), evidence), 1, "TCP and UDP services do not merge")
	require.Len(t, tracker.Observe("other-sensor", at, connection(17), evidence), 1, "sensor scopes do not merge")
	require.Equal(t, 5, tracker.Stats().Entries)
}
