package flowid

import (
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func flow(proto uint8, src string, sport uint16, dst string, dport uint16) events.FlowTuple {
	return events.FlowTuple{Protocol: proto, SourceAddress: netip.MustParseAddr(src), DestinationAddress: netip.MustParseAddr(dst), SourcePort: sport, DestinationPort: dport}
}

func reverse(f events.FlowTuple) events.FlowTuple {
	f.SourceAddress, f.DestinationAddress = f.DestinationAddress, f.SourceAddress
	f.SourcePort, f.DestinationPort = f.DestinationPort, f.SourcePort
	return f
}

func TestNormalizeOppositeDirections(t *testing.T) {
	for _, f := range []events.FlowTuple{
		flow(ProtocolTCP, "192.0.2.10", 49152, "198.51.100.20", 443),
		flow(ProtocolUDP, "192.0.2.10", 49152, "198.51.100.20", 53),
		flow(ProtocolTCP, "2001:db8::2", 443, "2001:db8::1", 49152),
	} {
		forward, err := Normalize(f)
		require.NoError(t, err)
		backward, err := Normalize(reverse(f))
		require.NoError(t, err)
		require.Equal(t, forward, backward)
	}
}

func TestNormalizeICMPRequestReply(t *testing.T) {
	request := flow(ProtocolICMP, "1.2.3.4", 8, "5.6.7.8", 0)
	reply := flow(ProtocolICMP, "5.6.7.8", 0, "1.2.3.4", 0)
	a, err := Normalize(request)
	require.NoError(t, err)
	b, err := Normalize(reply)
	require.NoError(t, err)
	require.Equal(t, a, b)

	v6Request := flow(ProtocolICMPv6, "fe80:1:203:405:607:809:a0b:c0d", 128, "fe80:1011:1213:1415:1617:1819:1a1b:1c1d", 0)
	v6Reply := flow(ProtocolICMPv6, "fe80:1011:1213:1415:1617:1819:1a1b:1c1d", 129, "fe80:1:203:405:607:809:a0b:c0d", 0)
	a, err = Normalize(v6Request)
	require.NoError(t, err)
	b, err = Normalize(v6Reply)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestCommunityIDPublicVectors(t *testing.T) {
	tests := []struct {
		name string
		flow events.FlowTuple
		want string
	}{
		{"tcp", flow(ProtocolTCP, "1.2.3.4", 1122, "5.6.7.8", 3344), "1:wCb3OG7yAFWelaUydu0D+125CLM="},
		{"udp", flow(ProtocolUDP, "1.2.3.4", 1122, "5.6.7.8", 3344), "1:0Mu9InQx6z4ZiCZM/7HXi2WMhOg="},
		{"icmp request", flow(ProtocolICMP, "1.2.3.4", 8, "5.6.7.8", 0), "1:crodRHL2FEsHjbv3UkRrfbs4bZ0="},
		{"icmp reply", flow(ProtocolICMP, "5.6.7.8", 0, "1.2.3.4", 0), "1:crodRHL2FEsHjbv3UkRrfbs4bZ0="},
		{"icmp6", flow(ProtocolICMPv6, "fe80:1:203:405:607:809:a0b:c0d", 128, "fe80:1011:1213:1415:1617:1819:1a1b:1c1d", 0), "1:0bf7hyMJUwt3fMED7z8LIfRpBeo="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CommunityID(tt.flow, 0)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCacheStableBoundedAndObservable(t *testing.T) {
	cache, err := NewCache(Config{MaxEntries: 2, IdleTimeout: time.Minute})
	require.NoError(t, err)
	now := time.Unix(100, 0)
	f1 := flow(ProtocolTCP, "192.0.2.1", 1000, "192.0.2.2", 80)
	first, err := cache.Lookup(f1, now)
	require.NoError(t, err)
	again, err := cache.Lookup(reverse(f1), now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, first, again)
	require.Len(t, first.UID, 18)
	require.Equal(t, byte('C'), first.UID[0])

	_, err = cache.Lookup(flow(ProtocolUDP, "192.0.2.3", 1001, "192.0.2.4", 53), now)
	require.NoError(t, err)
	_, err = cache.Lookup(flow(ProtocolTCP, "192.0.2.5", 1002, "192.0.2.6", 443), now)
	require.NoError(t, err)
	stats := cache.Stats()
	require.Equal(t, 2, stats.Size)
	require.Equal(t, uint64(4), stats.Lookups)
	require.Equal(t, uint64(1), stats.Hits)
	require.Equal(t, uint64(3), stats.Misses)
	require.Equal(t, uint64(1), stats.Evictions)
}

func TestCacheIdleExpirationAndEnvelopeEnrichment(t *testing.T) {
	cache, err := NewCache(Config{MaxEntries: 4, IdleTimeout: time.Minute})
	require.NoError(t, err)
	f := flow(ProtocolUDP, "192.0.2.1", 53000, "198.51.100.1", 53)
	env, err := cache.Enrich(events.Envelope{Timestamp: time.Unix(100, 0), Flow: f, NodeID: "hunter-a"})
	require.NoError(t, err)
	require.NotEmpty(t, env.UID)
	require.NotEmpty(t, env.CommunityID)
	require.Equal(t, "hunter-a", env.NodeID)
	oldUID := env.UID

	env.Timestamp = env.Timestamp.Add(2 * time.Minute)
	env, err = cache.Enrich(env)
	require.NoError(t, err)
	require.NotEqual(t, oldUID, env.UID)
	require.Equal(t, uint64(1), cache.Stats().Expired)
}

func TestInvalidConfigurationAndTuple(t *testing.T) {
	_, err := NewCache(Config{})
	require.Error(t, err)
	_, err = Normalize(events.FlowTuple{})
	require.ErrorIs(t, err, ErrInvalidTuple)
	_, err = Normalize(flow(ProtocolTCP, "192.0.2.1", 1, "2001:db8::1", 2))
	require.ErrorIs(t, err, ErrInvalidTuple)
	_, err = Normalize(flow(ProtocolICMP, "192.0.2.1", 256, "192.0.2.2", 0))
	require.ErrorIs(t, err, ErrInvalidTuple)
}

func BenchmarkCacheLookupHighFlowCount(b *testing.B) {
	cache, _ := NewCache(Config{MaxEntries: 100_000, IdleTimeout: 5 * time.Minute})
	flows := make([]events.FlowTuple, 100_000)
	for i := range flows {
		flows[i] = flow(ProtocolTCP, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String(), uint16(i), "192.0.2.1", 443)
		_, _ = cache.Lookup(flows[i], time.Unix(100, 0))
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _ = cache.Lookup(flows[i%len(flows)], time.Unix(101, 0))
			i++
		}
	})
}
