package records

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	"github.com/stretchr/testify/require"
)

func networkGoldenEvents() []events.Event {
	env := events.Envelope{Timestamp: time.Unix(1, 500000000).UTC(), UID: "Cnetwork", CommunityID: "1:network", NodeID: "sensor-a", CaptureScope: events.CaptureScopeFiltered, Partial: true, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.20"), SourcePort: 40000, DestinationAddress: netip.MustParseAddr("192.0.2.123"), DestinationPort: 123}}
	d := events.NewDHCPEvent(env)
	d.EventEnvelope.Flow.SourceAddress = netip.IPv4Unspecified()
	d.EventEnvelope.Flow.DestinationAddress = netip.MustParseAddr("255.255.255.255")
	d.EventEnvelope.Flow.SourcePort, d.EventEnvelope.Flow.DestinationPort = 68, 67
	d.Operation, d.MessageType, d.HardwareType, d.TransactionID = 1, 3, 1, 0xffffffff
	d.HardwareAddress = []byte{0, 1, 2, 3, 4, 255}
	d.ClientIdentifier = []byte{0, 255, 128}
	d.ClientAddress = netip.IPv4Unspecified()
	d.OfferedAddress = netip.MustParseAddr("192.0.2.20")
	d.NextServerAddress = netip.MustParseAddr("192.0.2.2")
	d.RelayAddress = netip.IPv4Unspecified()
	d.Hostname, d.Domain = "host", "example.test"
	d.Routers = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	d.DNSServers = []netip.Addr{}
	d.ParameterRequestList = []byte{1, 3, 6, 255}
	d.Association = events.AssociationRequest
	d.AssociationID = "exchange-id"
	d.Truncated = true
	absent := d.Clone()
	absent.LeaseSeconds = nil
	absent.ClientIdentifier = nil
	absent.Hostname = ""
	absent.Domain = ""
	absent.Routers = nil
	absent.DNSServers = nil
	absent.ParameterRequestList = nil
	absent.Association = events.AssociationMissing
	absent.AssociationID = ""
	zero := uint32(0)
	d.LeaseSeconds = &zero
	n := events.NewNTPEvent(env)
	n.Version, n.Mode, n.LeapIndicator, n.Stratum = 4, 4, 3, 2
	n.Poll, n.Precision = -6, -20
	n.RootDelay = -65536
	n.RootDispersion = 0xffffffff
	n.ReferenceID = [4]byte{0, 255, 128, 1}
	n.Transmit = events.NTPTimestamp{Raw: 0x83aa7e8180000001, Time: time.Unix(1, 500000000).UTC()}
	n.Association = events.AssociationNotApplicable
	h := events.NewKnownHostEvent(env)
	h.Host = netip.MustParseAddr("2001:db8::20")
	h.EventEnvelope.Flow.SourceAddress = h.Host
	h.Evidence = events.EvidenceUDPBidirectional
	s := events.NewKnownServiceEvent(env)
	s.Host = env.Flow.DestinationAddress
	s.Port, s.Transport, s.Protocol, s.Evidence = 123, 17, "ntp", events.EvidenceNTPExchange
	return []events.Event{d, absent, n, h, s}
}

func TestNetworkWriterGoldens(t *testing.T) {
	for _, format := range []logstream.Format{logstream.FormatTSV, logstream.FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			dir := t.TempDir()
			sink, err := logstream.New(logstream.Config{Directory: dir, Format: format, QueueSize: 16, Now: func() time.Time { return time.Unix(0, 0).UTC() }})
			require.NoError(t, err)
			require.NoError(t, sink.Register(events.KindDHCP, "dhcp", DHCP))
			require.NoError(t, sink.Register(events.KindNTP, "ntp", NTP))
			require.NoError(t, sink.Register(events.KindKnownHost, "known_hosts", KnownHosts))
			require.NoError(t, sink.Register(events.KindKnownService, "known_services", KnownServices))
			require.NoError(t, sink.Start(context.Background()))
			for _, e := range networkGoldenEvents() {
				require.NoError(t, sink.HandleEvent(context.Background(), e))
			}
			require.NoError(t, sink.Close(context.Background()))
			for _, stream := range []string{"dhcp", "ntp", "known_hosts", "known_services"} {
				got, err := os.ReadFile(filepath.Join(dir, stream+".log"))
				require.NoError(t, err)
				golden := filepath.Join("testdata", stream+"."+string(format)+".golden")
				if os.Getenv("UPDATE_NETWORK_GOLDENS") == "1" {
					require.NoError(t, os.MkdirAll("testdata", 0755))
					require.NoError(t, os.WriteFile(golden, got, 0644))
				}
				want, err := os.ReadFile(golden)
				require.NoError(t, err)
				require.Equal(t, string(want), string(got), stream)
			}
		})
	}
}
