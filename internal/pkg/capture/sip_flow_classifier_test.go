package capture

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testUDPPacketInfo(payload string) PacketInfo {
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return PacketInfo{Packet: gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)}
}

func TestPacketBufferPriorityLaneAccounting(t *testing.T) {
	newUnmergedBuffer := func(regularCap, sipCap int) *PacketBuffer {
		return &PacketBuffer{
			ch:       make(chan PacketInfo, regularCap),
			sipCh:    make(chan PacketInfo, sipCap),
			ctx:      context.Background(),
			sipFlows: newTCPSIPFlowClassifier(),
		}
	}
	regular := testUDPPacketInfo("ordinary payload")
	sip := testUDPPacketInfo("INVITE sip:x@example.invalid SIP/2.0\r\n")

	t.Run("regular saturation does not drop SIP within lane capacity", func(t *testing.T) {
		pb := newUnmergedBuffer(1, 4)
		require.True(t, pb.Send(regular))
		assert.False(t, pb.Send(regular))
		for i := 0; i < cap(pb.sipCh); i++ {
			assert.True(t, pb.Send(sip))
		}
		assert.Equal(t, int64(1), pb.GetDropped())
		assert.Zero(t, pb.GetSIPDropped())
		assert.Equal(t, int64(4), pb.GetSIPClassified())
	})

	t.Run("priority exhaustion is attributed only after fallback fills", func(t *testing.T) {
		pb := newUnmergedBuffer(1, 1)
		require.True(t, pb.Send(sip))
		require.True(t, pb.Send(sip), "full priority lane falls back to regular lane")
		assert.False(t, pb.Send(sip))
		assert.Zero(t, pb.GetDropped())
		assert.Equal(t, int64(1), pb.GetSIPDropped())
		assert.Equal(t, int64(3), pb.GetSIPClassified())
	})
}

func testIPv4(src, dst string) *layers.IPv4 {
	return &layers.IPv4{SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
}

func testTCP(src, dst uint16, payload string) *layers.TCP {
	return &layers.TCP{
		SrcPort:   layers.TCPPort(src),
		DstPort:   layers.TCPPort(dst),
		BaseLayer: layers.BaseLayer{Payload: []byte(payload)},
	}
}

func reverseIPv4(ip *layers.IPv4) *layers.IPv4 {
	return testIPv4(ip.DstIP.String(), ip.SrcIP.String())
}

func reverseTCP(tcp *layers.TCP, payload string) *layers.TCP {
	return testTCP(uint16(tcp.DstPort), uint16(tcp.SrcPort), payload)
}

func TestTCPSIPFlowClassifierSplitPromotionAndBidirectionalContinuation(t *testing.T) {
	c := newTCPSIPFlowClassifier()
	now := time.Unix(100, 0)
	ip := testIPv4("192.0.2.10", "198.51.100.20")
	tcp := testTCP(41000, 5060, "INV")

	assert.False(t, c.classify(ip, tcp, now))
	tcp.BaseLayer.Payload = []byte("ITE sip:user@example.invalid SIP/2.0\r\n")
	assert.True(t, c.classify(ip, tcp, now.Add(time.Millisecond)))

	// Once promoted, header/body continuations and the reverse response direction
	// remain protected even when an individual segment has no recognizable start.
	tcp.BaseLayer.Payload = []byte("Content-Length: 4\r\n\r\nbody")
	assert.True(t, c.classify(ip, tcp, now.Add(2*time.Millisecond)))
	assert.True(t, c.classify(reverseIPv4(ip), reverseTCP(tcp, "SIP/2.0 200 OK\r\n"), now.Add(3*time.Millisecond)))
	assert.True(t, c.classify(reverseIPv4(ip), reverseTCP(tcp, "response-body"), now.Add(4*time.Millisecond)))
}

func TestTCPSIPFlowClassifierLongSplitStartLine(t *testing.T) {
	c := newTCPSIPFlowClassifier()
	now := time.Unix(150, 0)
	ip := testIPv4("192.0.2.10", "198.51.100.20")
	assert.False(t, c.classify(ip, testTCP(41001, 5060, "INVITE sip:"+strings.Repeat("a", 700)), now))
	assert.True(t, c.classify(ip, testTCP(41001, 5060, "@example.invalid SIP/2.0\r\n"), now.Add(time.Millisecond)))
}

func TestTCPSIPFlowClassifierCloseExpiryAndTupleReuse(t *testing.T) {
	tests := []struct {
		name string
		flag func(*layers.TCP)
	}{
		{name: "FIN", flag: func(tcp *layers.TCP) { tcp.FIN = true }},
		{name: "RST", flag: func(tcp *layers.TCP) { tcp.RST = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTCPSIPFlowClassifier()
			now := time.Unix(200, 0)
			ip := testIPv4("192.0.2.1", "192.0.2.2")
			tcp := testTCP(42000, 5060, "INVITE sip:u@example.invalid SIP/2.0\r\n")
			require.True(t, c.classify(ip, tcp, now))

			closing := testTCP(42000, 5060, "last-body-bytes")
			tt.flag(closing)
			assert.True(t, c.classify(ip, closing, now.Add(time.Second)), "closing payload is classified before eviction")
			assert.False(t, c.classify(ip, testTCP(42000, 5060, "unrelated reused tuple"), now.Add(2*time.Second)))
		})
	}

	t.Run("idle expiry", func(t *testing.T) {
		c := newTCPSIPFlowClassifier()
		c.idleTimeout = time.Second
		now := time.Unix(300, 0)
		ip := testIPv4("203.0.113.1", "203.0.113.2")
		require.True(t, c.classify(ip, testTCP(43000, 5060, "OPTIONS sip:u@example.invalid SIP/2.0\r\n"), now))
		assert.False(t, c.classify(ip, testTCP(43000, 5060, "expired continuation"), now.Add(time.Second+time.Nanosecond)))
	})

	for _, handshake := range []struct {
		name string
		ack  bool
	}{
		{name: "fresh SYN"},
		{name: "fresh SYN-ACK after missed SYN", ack: true},
	} {
		t.Run(handshake.name, func(t *testing.T) {
			c := newTCPSIPFlowClassifier()
			now := time.Unix(400, 0)
			ip := testIPv4("203.0.113.3", "203.0.113.4")
			require.True(t, c.classify(ip, testTCP(44000, 5060, "BYE sip:u@example.invalid SIP/2.0\r\n"), now))
			syn := testTCP(44000, 5060, "")
			syn.SYN = true
			syn.ACK = handshake.ack
			assert.False(t, c.classify(ip, syn, now.Add(time.Second)))
			assert.False(t, c.classify(ip, testTCP(44000, 5060, "new connection data"), now.Add(2*time.Second)))
		})
	}
}

func TestTCPSIPFlowClassifierCanonicalKeysIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		name    string
		forward gopacket.NetworkLayer
		reverse gopacket.NetworkLayer
	}{
		{"IPv4", testIPv4("192.0.2.30", "198.51.100.40"), testIPv4("198.51.100.40", "192.0.2.30")},
		{"IPv6", &layers.IPv6{SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}, &layers.IPv6{SrcIP: net.ParseIP("2001:db8::2"), DstIP: net.ParseIP("2001:db8::1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTCPSIPFlowClassifier()
			now := time.Unix(500, 0)
			require.True(t, c.classify(tt.forward, testTCP(45000, 5060, "REGISTER sip:x@example.invalid SIP/2.0\r\n"), now))
			assert.True(t, c.classify(tt.reverse, testTCP(5060, 45000, "continuation"), now.Add(time.Millisecond)))
			assert.Len(t, c.flows, 1)
		})
	}
}

func TestTCPSIPFlowClassifierBoundedStateAndPrefixes(t *testing.T) {
	c := newTCPSIPFlowClassifier()
	c.maxEntries = 32
	now := time.Unix(600, 0)
	for i := 0; i < 1000; i++ {
		ip := testIPv4("192.0.2.1", net.IPv4(198, 51, byte(i>>8), byte(i)).String())
		assert.False(t, c.classify(ip, testTCP(uint16(10000+i%50000), 443, "I"), now.Add(time.Duration(i))))
	}
	require.LessOrEqual(t, len(c.flows), c.maxEntries)
	retainedPrefixBytes := 0
	for _, state := range c.flows {
		assert.LessOrEqual(t, len(state.prefix[0]), tcpSIPPrefixMaxBytes)
		assert.LessOrEqual(t, len(state.prefix[1]), tcpSIPPrefixMaxBytes)
		retainedPrefixBytes += len(state.prefix[0]) + len(state.prefix[1])
	}
	assert.LessOrEqual(t, retainedPrefixBytes, c.maxEntries*2*tcpSIPPrefixMaxBytes)

	prefix := appendSIPPrefix(nil, make([]byte, tcpSIPPrefixMaxBytes*4))
	assert.Len(t, prefix, tcpSIPPrefixMaxBytes)
	stats, active := c.snapshot()
	assert.Equal(t, c.maxEntries, active)
	assert.Greater(t, stats.CapacityEvictions, uint64(0))
}

func TestTCPSIPFlowClassifierConcurrent(t *testing.T) {
	c := newTCPSIPFlowClassifier()
	c.maxEntries = 128
	now := time.Unix(700, 0)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := testIPv4("192.0.2.1", net.IPv4(203, 0, byte(worker), byte(i)).String())
				payload := "not SIP"
				if i%10 == 0 {
					payload = "INVITE sip:x@example.invalid SIP/2.0\r\n"
				}
				c.classify(ip, testTCP(uint16(20000+i), 5060, payload), now.Add(time.Duration(i)))
			}
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, len(c.flows), c.maxEntries)
}

func BenchmarkTCPSIPFlowClassifier(b *testing.B) {
	b.Run("promoted-hit", func(b *testing.B) {
		c := newTCPSIPFlowClassifier()
		ip := testIPv4("192.0.2.1", "192.0.2.2")
		tcp := testTCP(46000, 5060, "INVITE sip:x@example.invalid SIP/2.0\r\n")
		now := time.Unix(800, 0)
		require.True(b, c.classify(ip, tcp, now))
		tcp.BaseLayer.Payload = []byte("body")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.classify(ip, tcp, now)
		}
	})

	b.Run("new-flow-miss", func(b *testing.B) {
		c := newTCPSIPFlowClassifier()
		c.maxEntries = 1024
		ip := &layers.IPv4{SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{198, 51, 0, 0}}
		tcp := testTCP(47000, 443, "not SIP")
		now := time.Unix(900, 0)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ip.DstIP[2] = byte(uint32(i) >> 8)
			ip.DstIP[3] = byte(i)
			tcp.SrcPort = layers.TCPPort(1024 + (i/65536)%64000)
			c.classify(ip, tcp, now)
		}
	})

	b.Run("full-cache-eviction", func(b *testing.B) {
		c := newTCPSIPFlowClassifier()
		c.maxEntries = 1024
		ip := &layers.IPv4{SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{198, 51, 0, 0}}
		tcp := testTCP(47000, 443, "not SIP")
		now := time.Unix(1000, 0)
		for i := 0; i < c.maxEntries; i++ {
			ip.DstIP[2] = byte(i >> 8)
			ip.DstIP[3] = byte(i)
			c.classify(ip, tcp, now)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			flow := i + c.maxEntries
			ip.DstIP[2] = byte(flow >> 8)
			ip.DstIP[3] = byte(flow)
			tcp.SrcPort = layers.TCPPort(1024 + (flow/65536)%64000)
			c.classify(ip, tcp, now)
		}
	})
}
