//go:build tui || all

package store

import (
	"net/netip"
	"strconv"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// packetFlowKey canonicalizes direction but keeps node and transport distinct.
// anyNode keys count packets across all nodes, including packets without a node.
type packetFlowKey struct {
	source, destination netip.AddrPort
	node                string
	transport           uint8
	anyNode             bool
}

type packetFlowSelection struct {
	key                     packetFlowKey
	valid, dirty, available bool
}

func canonicalPacketFlow(node string, transport uint8, source, destination netip.Addr, sourcePort, destinationPort uint16) (packetFlowKey, bool) {
	// Missing endpoints must not accidentally join unrelated incomplete observations.
	// Transport zero preserves legacy packets/events without transport metadata.
	if (transport != 0 && transport != 6 && transport != 17) || !source.IsValid() || !destination.IsValid() || sourcePort == 0 || destinationPort == 0 {
		return packetFlowKey{}, false
	}
	a, b := netip.AddrPortFrom(source.Unmap(), sourcePort), netip.AddrPortFrom(destination.Unmap(), destinationPort)
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	return packetFlowKey{source: a, destination: b, node: node, transport: transport}, true
}

func packetFlow(packet components.PacketDisplay) (packetFlowKey, bool) {
	transport := packet.Transport
	if transport == 0 {
		switch packet.Protocol {
		case "TCP", "tcp":
			transport = 6
		case "UDP", "udp":
			transport = 17
		}
	}
	if transport != 0 && transport != 6 && transport != 17 {
		return packetFlowKey{}, false
	}
	source, err := netip.ParseAddr(packet.SrcIP)
	if err != nil {
		return packetFlowKey{}, false
	}
	destination, err := netip.ParseAddr(packet.DstIP)
	if err != nil {
		return packetFlowKey{}, false
	}
	sourcePort, err := strconv.ParseUint(packet.SrcPort, 10, 16)
	if err != nil {
		return packetFlowKey{}, false
	}
	destinationPort, err := strconv.ParseUint(packet.DstPort, 10, 16)
	if err != nil {
		return packetFlowKey{}, false
	}
	return canonicalPacketFlow(packet.NodeID, transport, source, destination, uint16(sourcePort), uint16(destinationPort))
}

func samePacketFlow(a, b packetFlowKey) bool {
	return a.source == b.source && a.destination == b.destination && (a.transport == 0 || b.transport == 0 || a.transport == b.transport) && (a.node == "" || b.node == "" || a.node == b.node)
}

// updatePacketFlowLocked updates exact-node and all-node counts. Empty buckets
// are removed so both index and selection cache remain bounded by retention.
func (ps *PacketStore) updatePacketFlowLocked(packet components.PacketDisplay, delta int) {
	if !ps.flowIndexEnabled {
		return
	}
	key, ok := packetFlow(packet)
	if !ok {
		return
	}
	if ps.flowCounts == nil {
		ps.flowCounts = make(map[packetFlowKey]int)
	}
	if ps.flowSelection.valid && samePacketFlow(ps.flowSelection.key, key) {
		ps.flowSelection.dirty = true
	}
	ps.updateFlowCountLocked(key, delta)
	key.node, key.anyNode = "", true
	ps.updateFlowCountLocked(key, delta)
}

func (ps *PacketStore) updateFlowCountLocked(key packetFlowKey, delta int) {
	count := ps.flowCounts[key] + delta
	if count <= 0 {
		delete(ps.flowCounts, key)
	} else {
		ps.flowCounts[key] = count
	}
}

func (ps *PacketStore) rebuildPacketFlowsLocked() {
	if !ps.flowIndexEnabled {
		return
	}
	ps.flowCounts = nil
	ps.flowSelection.dirty = true
	count := min(ps.PacketsCount, len(ps.Packets))
	start := 0
	if count == len(ps.Packets) {
		start = ps.PacketsHead
	}
	for i := 0; i < count; i++ {
		ps.updatePacketFlowLocked(ps.Packets[(start+i)%len(ps.Packets)], 1)
	}
}

// HasRelatedPacket queries retained raw packets, independently of the display
// filter. A missing node on either side retains the historical wildcard match.
// The index is activated on the first valid query by indexing retained packets
// once under the lock, without copying the ring. Packet-only sessions pay only
// an enabled-state check on ingestion. Activation survives buffer resets.
// The single-selection cache is invalidated only by a different selected flow,
// a matching packet entering/leaving retention, or a buffer replacement/reset.
func (ps *PacketStore) HasRelatedPacket(env events.Envelope) bool {
	key, valid := canonicalPacketFlow(env.NodeID, env.Flow.Protocol, env.Flow.SourceAddress, env.Flow.DestinationAddress, env.Flow.SourcePort, env.Flow.DestinationPort)
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if !valid {
		ps.flowSelection = packetFlowSelection{}
		return false
	}
	if !ps.flowIndexEnabled {
		ps.flowIndexEnabled = true
		ps.rebuildPacketFlowsLocked()
	}
	if ps.flowSelection.valid && ps.flowSelection.key == key && !ps.flowSelection.dirty {
		return ps.flowSelection.available
	}
	ps.flowLookupCount++
	available := ps.hasFlowCountLocked(key)
	if key.transport == 0 {
		for _, transport := range [...]uint8{6, 17} {
			other := key
			other.transport = transport
			available = available || ps.hasFlowCountLocked(other)
		}
	} else {
		unknown := key
		unknown.transport = 0
		available = available || ps.hasFlowCountLocked(unknown)
	}
	ps.flowSelection = packetFlowSelection{key: key, valid: true, available: available}
	return available
}

func (ps *PacketStore) hasFlowCountLocked(key packetFlowKey) bool {
	if key.node == "" {
		key.anyNode = true
		return ps.flowCounts[key] > 0
	}
	if ps.flowCounts[key] > 0 {
		return true
	}
	key.node = ""
	return ps.flowCounts[key] > 0
}
