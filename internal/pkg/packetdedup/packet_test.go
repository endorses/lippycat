package packetdedup

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func ethernet(packet []byte, v6 bool, vlan bool, mac byte) []byte {
	header := make([]byte, 14)
	header[0] = mac
	header[6] = mac + 1
	protocol := uint16(0x0800)
	if v6 {
		protocol = 0x86dd
	}
	if vlan {
		binary.BigEndian.PutUint16(header[12:14], 0x8100)
		header = append(header, 0, 42, byte(protocol>>8), byte(protocol))
	} else {
		binary.BigEndian.PutUint16(header[12:14], protocol)
	}
	return append(header, packet...)
}
func TestLinkRoutingChangesDoNotChangeIdentity(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "ipv4"
		if v6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			d, clock := setup(t, 16, 16000)
			raw := udpPacket(t, v6, 3, rtp(9))
			a := observation(clock, "a", ethernet(raw, v6, false, 7))
			a.LinkType = layers.LinkTypeEthernet
			decision, claim := d.Begin(a)
			require.Equal(t, Accept, decision)
			require.True(t, claim.Commit())
			changed := append([]byte(nil), raw...)
			if v6 {
				changed[7] = 31
			} else {
				changed[8] = 31
				changed[10] ^= 1
				changed[11] ^= 7
			}
			b := observation(clock, "b", append(ethernet(changed, v6, true, 99), 0, 0, 0))
			b.LinkType = layers.LinkTypeEthernet
			decision, _ = d.Begin(b)
			require.Equal(t, Duplicate, decision)
		})
	}
}
func TestUnsupportedAndAmbiguousPacketsAlwaysRetained(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	valid := udpPacket(t, false, 1, rtp(1))
	tests := map[string]struct {
		packet   []byte
		decision Decision
	}{
		"empty":                {nil, RetainUnsupported},
		"truncated":            {valid[:len(valid)-1], RetainUnsupported},
		"generic ipv6 udp":     {udpPacket(t, true, 0, []byte("retry-content")), RetainAmbiguous},
		"ipv4 udp no identity": {udpPacket(t, false, 0, []byte("retry-content")), RetainAmbiguous},
	}
	tcp := append([]byte(nil), valid...)
	tcp[9] = 6
	tests["tcp retransmission ambiguous"] = struct {
		packet   []byte
		decision Decision
	}{tcp, RetainAmbiguous}
	fragment := append([]byte(nil), valid...)
	fragment[6] = 0x20
	tests["fragment"] = struct {
		packet   []byte
		decision Decision
	}{fragment, RetainUnsupported}
	options := append([]byte(nil), valid...)
	options[0] = 0x46
	tests["ip options"] = struct {
		packet   []byte
		decision Decision
	}{options, RetainUnsupported}
	ext := udpPacket(t, true, 0, rtp(1))
	ext[6] = 0
	tests["ipv6 extension"] = struct {
		packet   []byte
		decision Decision
	}{ext, RetainUnsupported}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			for _, source := range []string{"a", "b"} {
				decision, claim := d.Begin(observation(clock, source, test.packet))
				require.Equal(t, test.decision, decision)
				require.Nil(t, claim)
			}
		})
	}
	require.Zero(t, d.Stats().Entries)
}
func TestGenericIPv4PacketIdentityPreservesRetransmissions(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	a := observation(clock, "a", udpPacket(t, false, 1, []byte("SIP retransmission")))
	decision, claim := d.Begin(a)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
	b := a
	b.Source = "b"
	decision, _ = d.Begin(b)
	require.Equal(t, Duplicate, decision)
	// A fresh IPv4 ID denotes a new transmission, despite equal UDP content.
	b.Packet = udpPacket(t, false, 2, []byte("SIP retransmission"))
	decision, claim = d.Begin(b)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
	a.Packet = b.Packet
	decision, _ = d.Begin(a)
	require.Equal(t, Duplicate, decision)
}
func TestRTPAndRTCPScopeWithoutIPv4Identity(t *testing.T) {
	senderReport := make([]byte, 28)
	senderReport[0] = 0x80
	senderReport[1] = 200
	senderReport[3] = 6
	binary.BigEndian.PutUint32(senderReport[4:8], 123)
	binary.BigEndian.PutUint64(senderReport[8:16], 456)
	for _, payload := range [][]byte{rtp(1), senderReport} {
		d, clock := setup(t, 16, 16000)
		a := observation(clock, "a", udpPacket(t, true, 0, payload))
		decision, claim := d.Begin(a)
		require.Equal(t, Accept, decision)
		require.True(t, claim.Commit())
		b := a
		b.Source = "b"
		decision, _ = d.Begin(b)
		require.Equal(t, Duplicate, decision)
	}
	require.False(t, mediaIdentity([]byte{0x80, 200, 0, 0, 0, 0, 0, 0}))
	malformed := append([]byte(nil), senderReport...)
	malformed[3] = 0
	require.False(t, mediaIdentity(malformed))
}
func TestSourceIdentityCaptureTimeAndConfigRequired(t *testing.T) {
	for _, cfg := range []Config{{}, {MaxEntries: 1, MaxBytes: 10}, {Window: time.Second, MaxBytes: 100}, {Window: time.Second, MaxEntries: 1}} {
		_, err := New(cfg)
		require.Error(t, err)
	}
	d, clock := setup(t, 16, 16000)
	a := observation(clock, "a", udpPacket(t, false, 1, rtp(1)))
	for _, alter := range []func(*Observation){
		func(o *Observation) { o.Source = "" }, func(o *Observation) { o.Consumer = "" }, func(o *Observation) { o.Domain = "" }, func(o *Observation) { o.Flow = "" }, func(o *Observation) { o.CapturedAt = time.Time{} }, func(o *Observation) { o.CapturedAt = clock.Now().Add(2 * time.Second) },
	} {
		invalid := a
		alter(&invalid)
		decision, claim := d.Begin(invalid)
		require.Equal(t, RetainAmbiguous, decision)
		require.Nil(t, claim)
	}
	a.LinkType = layers.LinkTypeLinuxSLL
	decision, claim := d.Begin(a)
	require.Equal(t, RetainUnsupported, decision)
	require.Nil(t, claim)
}

func FuzzCanonicalPacketRetainsMalformed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, packet []byte) {
		for _, link := range []layers.LinkType{layers.LinkTypeRaw, layers.LinkTypeEthernet} {
			normalized, decision := canonicalPacket(packet, link)
			if decision == Accept {
				require.NotEmpty(t, normalized)
				require.LessOrEqual(t, len(normalized), len(packet))
				again, decision := canonicalPacket(normalized, layers.LinkTypeRaw)
				require.Equal(t, Accept, decision)
				require.Equal(t, normalized, again)
			} else {
				require.Nil(t, normalized)
			}
		}
	})
}

func TestICMPEchoIdentityAndOwnedContent(t *testing.T) {
	d, clock := setup(t, 16, 16000)
	// A valid IPv4 echo request with an immutable packet ID. IPv4 checksum is
	// intentionally not part of canonical identity; the ICMP checksum remains.
	packet := []byte{0x45, 0, 0, 28, 0, 23, 0, 0, 64, 1, 0xf6, 0xc6, 192, 0, 2, 1, 192, 0, 2, 2, 8, 0, 0xf7, 0xfb, 0, 1, 0, 3}
	a := observation(clock, "a", packet)
	decision, claim := d.Begin(a)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
	original := append([]byte(nil), packet...)
	packet[len(packet)-1] = 9 // A caller reusing its input buffer cannot alter cache identity.
	b := observation(clock, "b", original)
	decision, _ = d.Begin(b)
	require.Equal(t, Duplicate, decision)
	b.Source = "c"
	b.Packet = packet
	decision, claim = d.Begin(b)
	require.Equal(t, Accept, decision)
	require.True(t, claim.Commit())
}
