package capture

import (
	"bytes"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	tcpSIPFlowIdleTimeout = 2 * time.Minute
	tcpSIPFlowMaxEntries  = 65536
	tcpSIPPrefixMaxBytes  = 1024
	tcpSIPFlowEvictSample = 16
)

var sipStartPrefixes = [][]byte{
	[]byte("ACK "), []byte("BYE "), []byte("CANCEL "), []byte("INFO "),
	[]byte("INVITE "), []byte("MESSAGE "), []byte("NOTIFY "), []byte("OPTIONS "),
	[]byte("PRACK "), []byte("PUBLISH "), []byte("REFER "), []byte("REGISTER "),
	[]byte("SUBSCRIBE "), []byte("UPDATE "), []byte("SIP/2.0 "),
}

type tcpSIPEndpoint struct {
	address [16]byte
	port    uint16
	ipv6    bool
}

type tcpSIPFlowKey struct {
	first  tcpSIPEndpoint
	second tcpSIPEndpoint
}

type tcpSIPFlowState struct {
	lastSeen time.Time
	prefix   [2][]byte
	promoted bool
}

// tcpSIPFlowClassifier protects TCP segments after a credible SIP start has
// been observed on either connection direction. State and retained prefixes are
// strictly bounded. Capture joined in the middle of a connection remains on the
// regular lane until a recognizable SIP start is seen; if the SIP lane fills,
// PacketBuffer falls back to the regular lane and attributes a drop only when
// both lanes are full.
type tcpSIPFlowClassifier struct {
	mu          sync.Mutex
	flows       map[tcpSIPFlowKey]*tcpSIPFlowState
	idleTimeout time.Duration
	maxEntries  int
	stats       SIPFlowClassifierStats
}

// SIPFlowClassifierStats contains cumulative, monotonic classification events.
// ClassifiedSegments counts segments protected because their flow was already
// promoted; Promotions counts newly recognized flows.
type SIPFlowClassifierStats struct {
	Promotions         uint64
	ClassifiedSegments uint64
	IdleExpirations    uint64
	CapacityEvictions  uint64
	ConnectionCloses   uint64
}

func newTCPSIPFlowClassifier() *tcpSIPFlowClassifier {
	return &tcpSIPFlowClassifier{
		flows:       make(map[tcpSIPFlowKey]*tcpSIPFlowState),
		idleTimeout: tcpSIPFlowIdleTimeout,
		maxEntries:  tcpSIPFlowMaxEntries,
	}
}

func (c *tcpSIPFlowClassifier) classify(network gopacket.NetworkLayer, tcp *layers.TCP, now time.Time) bool {
	key, direction, ok := makeTCPSIPFlowKey(network, tcp)
	if !ok {
		return mightBeSIP(tcp.LayerPayload())
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	state := c.flows[key]
	if state != nil && now.Sub(state.lastSeen) > c.idleTimeout {
		delete(c.flows, key)
		c.stats.IdleExpirations++
		state = nil
	}
	// A fresh handshake explicitly starts a new incarnation of a reused tuple.
	if tcp.SYN && !tcp.ACK {
		delete(c.flows, key)
		state = nil
	}

	payload := tcp.LayerPayload()
	if state == nil && len(payload) > 0 {
		c.makeRoom(now)
		state = &tcpSIPFlowState{lastSeen: now}
		c.flows[key] = state
	}

	isSIP := false
	if state != nil {
		state.lastSeen = now
		if state.promoted {
			isSIP = true
			c.stats.ClassifiedSegments++
		} else if len(payload) > 0 {
			prefix := appendSIPPrefix(state.prefix[direction], payload)
			state.prefix[direction] = prefix
			if mightBeSIP(prefix) {
				state.promoted = true
				c.stats.Promotions++
				state.prefix = [2][]byte{}
				isSIP = true
			} else if !couldStartSIP(prefix) {
				state.prefix[direction] = nil
			}
		}
	}

	if tcp.FIN || tcp.RST {
		if state != nil {
			c.stats.ConnectionCloses++
		}
		delete(c.flows, key)
	}
	return isSIP
}

func (c *tcpSIPFlowClassifier) makeRoom(now time.Time) {
	if len(c.flows) < c.maxEntries {
		return
	}
	var oldestKey tcpSIPFlowKey
	oldest := now
	found := false
	inspected := 0
	for key, state := range c.flows {
		if now.Sub(state.lastSeen) > c.idleTimeout {
			delete(c.flows, key)
			c.stats.IdleExpirations++
			if len(c.flows) < c.maxEntries {
				return
			}
		}
		if !found || state.lastSeen.Before(oldest) {
			oldestKey, oldest, found = key, state.lastSeen, true
		}
		inspected++
		if inspected == tcpSIPFlowEvictSample {
			break
		}
	}
	if found {
		delete(c.flows, oldestKey)
		c.stats.CapacityEvictions++
	}
}

func (c *tcpSIPFlowClassifier) snapshot() (SIPFlowClassifierStats, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats, len(c.flows)
}

func (c *tcpSIPFlowClassifier) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.flows)
}

func appendSIPPrefix(prefix, payload []byte) []byte {
	remaining := tcpSIPPrefixMaxBytes - len(prefix)
	if remaining <= 0 {
		return prefix
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
	}
	return append(prefix, payload...)
}

func couldStartSIP(prefix []byte) bool {
	for _, candidate := range sipStartPrefixes {
		if bytes.HasPrefix(candidate, prefix) || bytes.HasPrefix(prefix, candidate) {
			return true
		}
	}
	return false
}

func makeTCPSIPFlowKey(network gopacket.NetworkLayer, tcp *layers.TCP) (tcpSIPFlowKey, int, bool) {
	var source, destination tcpSIPEndpoint
	switch ip := network.(type) {
	case *layers.IPv4:
		copy(source.address[12:], ip.SrcIP.To4())
		copy(destination.address[12:], ip.DstIP.To4())
	case *layers.IPv6:
		copy(source.address[:], ip.SrcIP.To16())
		copy(destination.address[:], ip.DstIP.To16())
		source.ipv6, destination.ipv6 = true, true
	default:
		return tcpSIPFlowKey{}, 0, false
	}
	source.port, destination.port = uint16(tcp.SrcPort), uint16(tcp.DstPort)
	if endpointLess(destination, source) {
		return tcpSIPFlowKey{first: destination, second: source}, 1, true
	}
	return tcpSIPFlowKey{first: source, second: destination}, 0, true
}

func endpointLess(a, b tcpSIPEndpoint) bool {
	if a.ipv6 != b.ipv6 {
		return !a.ipv6
	}
	if comparison := bytes.Compare(a.address[:], b.address[:]); comparison != 0 {
		return comparison < 0
	}
	return a.port < b.port
}
