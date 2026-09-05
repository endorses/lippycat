//go:build tui || all

package store_test

import (
	"math/rand"
	"net/netip"
	"strconv"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

func TestPacketFlowMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(6017))
	nodes := []string{"", "a", "b"}
	transports := []uint8{0, 6, 17}
	packet := func() components.PacketDisplay {
		p := components.PacketDisplay{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: strconv.Itoa(100 + r.Intn(3)), DstPort: "443", NodeID: nodes[r.Intn(3)], Transport: transports[r.Intn(3)]}
		if r.Intn(2) == 0 {
			p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
			p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
		}
		return p
	}
	s := store.NewPacketStore(7)
	var retained []components.PacketDisplay
	capacity := 7
	for step := 0; step < 10000; step++ {
		switch r.Intn(12) {
		case 0:
			s.Clear()
			retained = nil
		case 1:
			capacity = 1 + r.Intn(10)
			s.ResizeBuffer(capacity)
			if len(retained) > capacity {
				retained = retained[len(retained)-capacity:]
			}
		case 2:
			capacity = 1 + r.Intn(10)
			s.ClearAndResize(capacity)
			retained = nil
		case 3:
			s.ResetCounts()
		default:
			ps := make([]components.PacketDisplay, 1+r.Intn(15))
			for i := range ps {
				ps[i] = packet()
			}
			if len(ps) == 1 {
				s.AddPacket(ps[0])
			} else {
				s.AddPacketBatch(ps)
			}
			retained = append(retained, ps...)
			if len(retained) > capacity {
				retained = retained[len(retained)-capacity:]
			}
		}
		for q := 0; q < 20; q++ {
			p := packet()
			sp, err := strconv.Atoi(p.SrcPort)
			if err != nil {
				t.Fatal(err)
			}
			dp, err := strconv.Atoi(p.DstPort)
			if err != nil {
				t.Fatal(err)
			}
			env := events.Envelope{NodeID: p.NodeID, Flow: events.FlowTuple{Protocol: p.Transport, SourceAddress: netip.MustParseAddr(p.SrcIP), DestinationAddress: netip.MustParseAddr(p.DstIP), SourcePort: uint16(sp), DestinationPort: uint16(dp)}}
			want := false
			for _, rp := range retained {
				if p.NodeID != "" && rp.NodeID != "" && p.NodeID != rp.NodeID {
					continue
				}
				if p.Transport != 0 && rp.Transport != 0 && p.Transport != rp.Transport {
					continue
				}
				forward := p.SrcIP == rp.SrcIP && p.DstIP == rp.DstIP && p.SrcPort == rp.SrcPort && p.DstPort == rp.DstPort
				reverse := p.SrcIP == rp.DstIP && p.DstIP == rp.SrcIP && p.SrcPort == rp.DstPort && p.DstPort == rp.SrcPort
				want = want || forward || reverse
			}
			for repeat := 0; repeat < 2; repeat++ {
				if got := s.HasRelatedPacket(env); got != want {
					t.Fatalf("step %d query %d got %v want %v", step, q, got, want)
				}
			}
		}
	}
}
