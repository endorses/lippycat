package eventquery

import (
	"net/netip"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestNetworkProjectionAndQueries(t *testing.T) {
	env := envelope()
	env.Flow.Protocol = 17
	env.Partial = true
	dhcp := events.NewDHCPEvent(env)
	dhcp.Operation, dhcp.MessageType, dhcp.TransactionID = 2, 5, 42
	dhcp.ClientIdentifier = []byte{0, 255, 128}
	dhcp.DNSServers = []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("198.51.100.53")}
	dhcp.Association = events.AssociationUnique
	ntp := events.NewNTPEvent(env)
	ntp.Version, ntp.Mode, ntp.Poll, ntp.Precision = 4, 4, -1, -18
	ntp.RootDelay = -32768
	ntp.Transmit.Raw = 0xffffffffffffffff
	ntp.Association = events.AssociationAmbiguous
	host := events.NewKnownHostEvent(env)
	host.Host, host.Evidence = env.Flow.SourceAddress, events.EvidenceUDPBidirectional
	service := events.NewKnownServiceEvent(env)
	service.Host, service.Port, service.Transport, service.Protocol, service.Evidence = env.Flow.DestinationAddress, 123, 17, "ntp", events.EvidenceNTPExchange
	for _, tc := range []struct {
		event   events.Event
		queries []string
		missing string
	}{
		{dhcp, []string{"kind:dhcp AND message_type:5", "transaction_id:42", "client_identifier:00ff80", "dns_servers:198.51.100.53", "association:unique", "partial:true"}, "lease_seconds"},
		{ntp, []string{"kind:ntp AND version:4", "poll:<0", "precision:-18", "root_delay_raw:-32768", "transmit_raw:ffffffffffffffff", "association:ambiguous"}, "transmit_time"},
		{host, []string{"kind:known_host", "host:192.0.2.1", "evidence:udp_bidirectional", "src:192.0.2.1"}, "port"},
		{service, []string{"kind:known_service", "host:198.51.100.2", "port:123", "transport:udp", "service:ntp", "evidence:ntp_exchange", "dport:443"}, "hostname"},
	} {
		t.Run(string(tc.event.Kind()), func(t *testing.T) {
			p := Project(tc.event)
			require.Equal(t, tc.event.Kind(), p.Kind)
			require.NotEmpty(t, p.Summary)
			require.NotContains(t, p.Fields, tc.missing)
			require.Equal(t, []any{"node-1"}, p.Fields["node_id"].Values)
			for _, q := range tc.queries {
				pred, err := Compile(q)
				require.NoError(t, err, q)
				require.True(t, pred(tc.event), q)
			}
			pred, err := Compile("kind:http")
			require.NoError(t, err)
			require.False(t, pred(tc.event))
		})
	}
	require.Equal(t, []any{int8(-1)}, Project(ntp).Fields["poll"].Values)
	require.Equal(t, []byte{0, 255, 128}, dhcp.ClientIdentifier)
}

func TestNetworkQuerySchemaTypeCollisions(t *testing.T) {
	tls := events.NewTLSEvent(envelope())
	tls.Version = "TLSv13"
	ntp := events.NewNTPEvent(envelope())
	ntp.Version = 4
	host := events.NewKnownHostEvent(envelope())
	host.Host = netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		query string
		event events.Event
	}{
		{"version:TLSv13", tls},
		{"version:>=4", ntp},
		{`host:"Example Org"`, httpEvent()},
		{"host:192.0.2.1", host},
	} {
		pred, err := Compile(tc.query)
		require.NoError(t, err, tc.query)
		require.True(t, pred(tc.event), tc.query)
	}
}
