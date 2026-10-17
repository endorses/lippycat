package packetdedup

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}
func setup(t *testing.T, entries int, maxBytes int64) (*Detector, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Unix(1700000000, 0)}
	d, err := New(Config{MaxEntries: entries, MaxBytes: maxBytes, Window: time.Second, Clock: clock.Now})
	require.NoError(t, err)
	return d, clock
}
func rtp(sequence uint16) []byte {
	p := []byte{0x80, 96, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4, 9, 8, 7}
	binary.BigEndian.PutUint16(p[2:4], sequence)
	return p
}
func udpPacket(t *testing.T, v6 bool, id uint16, payload []byte) []byte {
	t.Helper()
	udp := &layers.UDP{SrcPort: 4000, DstPort: 5000}
	var network gopacket.SerializableLayer
	if v6 {
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		network = ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, Id: id, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		network = ip
	}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, network, udp, gopacket.Payload(payload)))
	return buffer.Bytes()
}
func observation(clock *testClock, source string, packet []byte) Observation {
	return Observation{Consumer: "analysis", Domain: "network", Flow: "call/direction", Source: source, CapturedAt: clock.Now(), Packet: packet, LinkType: layers.LinkTypeRaw}
}
func TestClaimAcceptanceRejectionAndIndependentConsumers(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	original := observation(clock, "a", udpPacket(t, false, 12, rtp(3)))
	decision, claim := d.Begin(original)
	require.Equal(t, Accept, decision)
	alternate := original
	alternate.Source = "b"
	decision, wait := d.Begin(alternate)
	require.Equal(t, InFlight, decision)
	require.False(t, wait.Commit(), "waiting consumer cannot accept someone else's reservation")
	require.False(t, wait.Abort())
	select {
	case <-wait.Done():
		t.Fatal("unaccepted first copy cannot suppress an eligible alternate")
	default:
	}
	require.True(t, claim.Abort())
	<-wait.Done()
	require.False(t, claim.Commit())
	decision, accepted := d.Begin(alternate)
	require.Equal(t, Accept, decision)
	require.True(t, accepted.Commit())
	require.False(t, accepted.Commit())
	require.False(t, accepted.Abort())
	decision, _ = d.Begin(original)
	require.Equal(t, Duplicate, decision)
	require.ElementsMatch(t, []string{"a", "b"}, accepted.Contributors())
	// No consumer may lose its independently authorized/accepted copy.
	original.Consumer = "another-task"
	decision, separate := d.Begin(original)
	require.Equal(t, Accept, decision)
	require.True(t, separate.Commit())
	stats := d.Stats()
	require.EqualValues(t, 1, stats.Aborts)
	require.EqualValues(t, 2, stats.Commits)
	require.EqualValues(t, 1, stats.Duplicates)
}
func TestSameSourceRepeatsMakeFurtherPairingAmbiguous(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	a := observation(clock, "a", udpPacket(t, false, 3, rtp(1)))
	decision, claim := d.Begin(a)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
	b := a
	b.Source = "b"
	decision, _ = d.Begin(b)
	require.Equal(t, Duplicate, decision)
	decision, _ = d.Begin(b)
	require.Equal(t, RetainRepeat, decision, "same-source repeats remain eligible even after its earlier copy was suppressed")
	c := a
	c.Source = "c"
	decision, _ = d.Begin(c)
	require.Equal(t, RetainAmbiguous, decision, "repeat history cannot be paired with a new source's observation")
	decision, _ = d.Begin(a)
	require.Equal(t, RetainRepeat, decision)
	require.EqualValues(t, 1, d.Stats().Duplicates)
}
func TestConcurrentEquivalentSourcesHaveOneAcceptedOwner(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	packet := udpPacket(t, true, 0, rtp(1))
	ready := make(chan struct{})
	var wg sync.WaitGroup
	const sources = 20
	results := make(chan Decision, sources)
	for i := 0; i < sources; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-ready
			obs := observation(clock, string(rune('a'+i)), packet)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for {
				decision, claim := d.Begin(obs)
				if decision == InFlight {
					select {
					case <-claim.Done():
						continue
					case <-ctx.Done():
						results <- RetainAmbiguous
						return
					}
				}
				if decision == Accept && !claim.Commit() {
					results <- RetainAmbiguous
					return
				}
				results <- decision
				return
			}
		}(i)
	}
	close(ready)
	wg.Wait()
	close(results)
	accepted, duplicates := 0, 0
	for result := range results {
		switch result {
		case Accept:
			accepted++
		case Duplicate:
			duplicates++
		default:
			t.Errorf("unexpected decision %v", result)
		}
	}
	require.Equal(t, 1, accepted)
	require.Equal(t, sources-1, duplicates)
	require.Equal(t, sources, d.Stats().Contributors)
}
func TestWindowPressureAndExpiredClaimsRetainCoverage(t *testing.T) {
	d, clock := setup(t, 1, 16000)
	a := observation(clock, "a", udpPacket(t, false, 1, rtp(1)))
	decision, claim := d.Begin(a)
	require.Equal(t, Accept, decision)
	b := a
	b.Source = "b"
	_, waiting := d.Begin(b)
	different := a
	different.Packet = udpPacket(t, false, 2, rtp(2))
	decision, _ = d.Begin(different)
	require.Equal(t, RetainCapacity, decision)
	clock.Advance(time.Second)
	require.Equal(t, 0, d.Stats().Entries)
	<-waiting.Done()
	require.False(t, claim.Commit(), "expired ownership cannot create a suppression record")
	decision, _ = d.Begin(a)
	require.Equal(t, RetainOutsideWindow, decision)
	a.CapturedAt = clock.Now()
	decision, claim = d.Begin(a)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
	require.EqualValues(t, 1, d.Stats().ExpiredPending)
	// Byte pressure also retains a new source rather than suppressing it without
	// room for bounded same-source-repeat evidence.
	cost := d.Stats().Bytes
	bounded, err := New(Config{MaxEntries: 10, MaxBytes: cost, Window: time.Second, Clock: clock.Now})
	require.NoError(t, err)
	_, claim = bounded.Begin(a)
	require.NotNil(t, claim)
	require.True(t, claim.Commit())
	b.CapturedAt = clock.Now()
	decision, _ = bounded.Begin(b)
	require.Equal(t, RetainCapacity, decision)
	require.Equal(t, cost, bounded.Stats().Bytes)
	require.EqualValues(t, 0, bounded.Stats().Duplicates)
}
func TestDirectionDomainAndContentRemainSignificant(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	a := observation(clock, "a", udpPacket(t, false, 10, rtp(1)))
	_, claim := d.Begin(a)
	require.True(t, claim.Commit())
	for _, alter := range []func(*Observation){
		func(o *Observation) { o.Flow = "opposite-direction" },
		func(o *Observation) { o.Domain = "other-network" },
		func(o *Observation) { o.Packet = append([]byte(nil), o.Packet...); o.Packet[len(o.Packet)-1] ^= 1 },
		func(o *Observation) { o.Packet = udpPacket(t, false, 11, rtp(1)) },
	} {
		b := a
		b.Source = "b"
		alter(&b)
		decision, claim := d.Begin(b)
		require.Equal(t, Accept, decision)
		require.True(t, claim.Commit())
	}
}

func TestClockRollbackDoesNotHideExpiredReservations(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	a := observation(clock, "a", udpPacket(t, false, 1, rtp(1)))
	_, claim := d.Begin(a)
	clock.Advance(-time.Second / 2)
	b := observation(clock, "b", udpPacket(t, false, 2, rtp(2)))
	_, earlier := d.Begin(b)
	clock.Advance(time.Second)
	stats := d.Stats()
	require.Equal(t, 1, stats.Entries)
	require.False(t, earlier.Commit())
	require.True(t, claim.Commit())
	clock.Advance(time.Second / 2)
	require.Zero(t, d.Stats().Entries)
}
