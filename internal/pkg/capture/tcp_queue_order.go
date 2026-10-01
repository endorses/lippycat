package capture

import (
	"sync/atomic"

	"github.com/google/gopacket/layers"
)

// queuedTCPFlow holds no packets or payload. The map contains only tuples with
// regular-lane packets not yet emitted; its size is bounded by that lane and
// currently active senders. Keeping the tuple regular until its count reaches
// zero prevents promoted SIP data from overtaking its handshake or earlier
// demoted fragments. Unrelated flows retain preferential SIP service.
type queuedTCPFlow struct {
	key     tcpSIPFlowKey
	pending int
}

func packetTCPFlow(pkt PacketInfo) (tcpSIPFlowKey, bool) {
	if pkt.Packet == nil {
		return tcpSIPFlowKey{}, false
	}
	tcp, ok := pkt.Packet.TransportLayer().(*layers.TCP)
	if !ok {
		return tcpSIPFlowKey{}, false
	}
	key, _, ok := makeTCPSIPFlowKey(pkt.Packet.NetworkLayer(), tcp)
	return key, ok
}

func (pb *PacketBuffer) hasRegularTCPPredecessor(pkt PacketInfo) bool {
	key, ok := packetTCPFlow(pkt)
	if !ok {
		return false
	}
	pb.tcpOrderMu.Lock()
	defer pb.tcpOrderMu.Unlock()
	return pb.tcpRegular[key] != nil
}

func (pb *PacketBuffer) trackRegularTCP(pkt PacketInfo) PacketInfo {
	key, ok := packetTCPFlow(pkt)
	if !ok {
		return pkt
	}
	pb.tcpOrderMu.Lock()
	defer pb.tcpOrderMu.Unlock()
	if pb.tcpRegular == nil {
		pb.tcpRegular = make(map[tcpSIPFlowKey]*queuedTCPFlow)
	}
	flow := pb.tcpRegular[key]
	if flow == nil {
		flow = &queuedTCPFlow{key: key}
		pb.tcpRegular[key] = flow
	}
	flow.pending++
	pkt.queuedTCP = flow
	return pkt
}

func (pb *PacketBuffer) releaseRegularTCP(pkt PacketInfo) {
	flow := pkt.queuedTCP
	if flow == nil {
		return
	}
	pb.tcpOrderMu.Lock()
	defer pb.tcpOrderMu.Unlock()
	flow.pending--
	if flow.pending == 0 && pb.tcpRegular[flow.key] == flow {
		delete(pb.tcpRegular, flow.key)
	}
}

func (pb *PacketBuffer) enqueueRegular(pkt PacketInfo, blocking bool) bool {
	pkt = pb.trackRegularTCP(pkt)
	sent := false
	defer func() {
		if !sent {
			pb.releaseRegularTCP(pkt)
		}
	}()
	if blocking {
		select {
		case pb.ch <- pkt:
			sent = true
		case <-pb.ctx.Done():
		}
	} else {
		select {
		case pb.ch <- pkt:
			sent = true
		case <-pb.ctx.Done():
		default:
		}
	}
	return sent
}

// emitPacket releases tuple ordering state only after the predecessor is in the
// FIFO output lane. No additional packet queue or background worker is needed.
func (pb *PacketBuffer) emitPacket(pkt PacketInfo) bool {
	ordering := pkt
	pkt.queuedTCP = nil
	select {
	case pb.mergedCh <- pkt:
		pb.releaseRegularTCP(ordering)
		return true
	case <-pb.ctx.Done():
		return false
	}
}

// SIPOrdered reports SIP packets kept in the regular lane to preserve tuple
// ordering. This is distinct from capacity-driven SIP demotion and drops.
func (pb *PacketBuffer) SIPOrdered() int64 { return atomic.LoadInt64(&pb.sipOrdered) }
