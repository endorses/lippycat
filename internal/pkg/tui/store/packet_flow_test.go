//go:build tui || all

package store

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func flowPacket(node string, transport uint8, port string) components.PacketDisplay {
	return components.PacketDisplay{NodeID: node, Transport: transport, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: port, DstPort: "53"}
}
func flowEnvelope(node string, transport uint8, port uint16) events.Envelope {
	return events.Envelope{NodeID: node, Flow: events.FlowTuple{Protocol: transport, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: port, DestinationPort: 53}}
}

func TestPacketFlowIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet components.PacketDisplay
		env    events.Envelope
		want   bool
	}{
		{"forward", flowPacket("a", 17, "1234"), flowEnvelope("a", 17, 1234), true},
		{"node separation", flowPacket("a", 17, "1234"), flowEnvelope("b", 17, 1234), false},
		{"missing packet node", flowPacket("", 17, "1234"), flowEnvelope("b", 17, 1234), true},
		{"missing event node", flowPacket("a", 17, "1234"), flowEnvelope("", 17, 1234), true},
		{"transport separation", flowPacket("a", 6, "1234"), flowEnvelope("a", 17, 1234), false},
		{"legacy packet transport", flowPacket("a", 0, "1234"), flowEnvelope("a", 17, 1234), true},
		{"legacy event transport", flowPacket("a", 17, "1234"), flowEnvelope("a", 0, 1234), true},
		{"port reuse", flowPacket("a", 17, "1235"), flowEnvelope("a", 17, 1234), false},
		{"empty flow", flowPacket("a", 17, "1234"), events.Envelope{}, false},
		{"empty port", flowPacket("a", 17, ""), flowEnvelope("a", 17, 1234), false},
		{"zero port", flowPacket("a", 17, "0"), flowEnvelope("a", 17, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := NewPacketStore(4)
			ps.AddPacket(tc.packet)
			require.Equal(t, tc.want, ps.HasRelatedPacket(tc.env))
			reversed := tc.env
			reversed.Flow.SourceAddress, reversed.Flow.DestinationAddress = reversed.Flow.DestinationAddress, reversed.Flow.SourceAddress
			reversed.Flow.SourcePort, reversed.Flow.DestinationPort = reversed.Flow.DestinationPort, reversed.Flow.SourcePort
			require.Equal(t, tc.want, ps.HasRelatedPacket(reversed))
		})
	}
}

func TestPacketFlowRetentionAndSelectionCache(t *testing.T) {
	ps := NewPacketStore(3)
	selected := flowEnvelope("a", 17, 1234)
	require.False(t, ps.HasRelatedPacket(selected))
	lookups := ps.flowLookupCount
	ps.AddPacket(flowPacket("b", 17, "1234"))
	require.False(t, ps.HasRelatedPacket(selected))
	require.Equal(t, lookups, ps.flowLookupCount, "unrelated node must not invalidate selection")
	ps.AddPacketBatch([]components.PacketDisplay{flowPacket("a", 17, "1234"), flowPacket("a", 17, "1234")})
	require.True(t, ps.HasRelatedPacket(selected))
	lookups = ps.flowLookupCount
	for i := 0; i < 10; i++ {
		require.True(t, ps.HasRelatedPacket(selected))
	}
	require.Equal(t, lookups, ps.flowLookupCount)
	ps.ClearFilteredPackets()
	require.True(t, ps.HasRelatedPacket(selected), "display filters do not affect raw retention")
	ps.AddPacket(flowPacket("b", 6, "9999"))
	require.True(t, ps.HasRelatedPacket(selected))
	require.Equal(t, lookups, ps.flowLookupCount, "unrelated eviction must not invalidate selection")
	ps.AddPacket(flowPacket("b", 6, "9999"))
	require.True(t, ps.HasRelatedPacket(selected), "one retained reference remains")
	ps.AddPacket(flowPacket("b", 6, "9999"))
	require.False(t, ps.HasRelatedPacket(selected))
	require.LessOrEqual(t, len(ps.flowCounts), 2*ps.Count())
}

func TestPacketFlowBufferMutations(t *testing.T) {
	ps := NewPacketStore(3)
	selected := flowEnvelope("a", 17, 1234)
	ps.AddPacketBatch([]components.PacketDisplay{flowPacket("a", 17, "1234"), flowPacket("a", 17, "1235")})
	require.True(t, ps.HasRelatedPacket(selected))
	ps.ResizeBuffer(6)
	require.True(t, ps.HasRelatedPacket(selected))
	ps.ResizeBuffer(1)
	require.False(t, ps.HasRelatedPacket(selected))
	ps.SetPackets([]components.PacketDisplay{flowPacket("a", 17, "1234")}, 0, 1)
	require.True(t, ps.HasRelatedPacket(selected))
	ps.ResetCounts()
	require.True(t, ps.HasRelatedPacket(selected), "statistics resets do not reset retention")
	ps.Clear()
	require.False(t, ps.HasRelatedPacket(selected))
	require.Empty(t, ps.flowCounts)
	require.Equal(t, components.PacketDisplay{}, ps.Packets[0])
	ps.AddPacket(flowPacket("a", 17, "1234"))
	require.True(t, ps.HasRelatedPacket(selected))
	ps.ClearAndResize(4)
	require.False(t, ps.HasRelatedPacket(selected))
	ps.AddPacket(flowPacket("a", 17, "1234"))
	require.True(t, ps.HasRelatedPacket(selected))
}

func BenchmarkPacketFlowIngestion(b *testing.B) {
	batch := make([]components.PacketDisplay, 64)
	for i := range batch {
		batch[i] = flowPacket("hunter-a", 17, fmt.Sprint(10000+i))
	}
	for _, size := range []int{1000, 10000, 100000} {
		for _, indexed := range []bool{false, true} {
			b.Run(fmt.Sprintf("capacity_%d/indexed_%t", size, indexed), func(b *testing.B) {
				ps := NewPacketStore(size)
				if indexed {
					ps.HasRelatedPacket(flowEnvelope("hunter-a", 17, 10000))
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if indexed {
						ps.AddPacketBatch(batch)
					} else {
						addPacketBatchWithoutFlowIndex(ps, batch)
					}
				}
			})
		}
	}
}

// Retains the pre-index ingestion path as a same-binary benchmark control.
func addPacketBatchWithoutFlowIndex(ps *PacketStore, packets []components.PacketDisplay) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	filterActive := !ps.FilterChain.IsEmpty()
	for i := range packets {
		packet := &packets[i]
		ps.Packets[ps.PacketsHead] = *packet
		ps.PacketsHead = (ps.PacketsHead + 1) % ps.MaxPackets
		if ps.PacketsCount < ps.MaxPackets {
			ps.PacketsCount++
		}
		ps.TotalPackets++
		if !filterActive || ps.FilterChain.Match(*packet) {
			ps.FilteredPackets = append(ps.FilteredPackets, *packet)
			ps.MatchedPackets++
		}
	}
	if len(ps.FilteredPackets) > ps.MaxPackets {
		ps.FilteredPackets = ps.FilteredPackets[len(ps.FilteredPackets)-ps.MaxPackets:]
	}
}

func TestPacketFlowCachedQueryAllocations(t *testing.T) {
	ps := NewPacketStore(10)
	ps.AddPacket(flowPacket("a", 17, "1234"))
	env := flowEnvelope("a", 17, 1234)
	require.True(t, ps.HasRelatedPacket(env))
	require.Zero(t, testing.AllocsPerRun(100, func() { ps.HasRelatedPacket(env) }))
}

func TestPacketFlowConcurrentRetentionAndQueries(t *testing.T) {
	ps := NewPacketStore(16)
	packet := flowPacket("a", 17, "1234")
	env := flowEnvelope("a", 17, 1234)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			ps.AddPacket(packet)
			ps.AddPacketBatch([]components.PacketDisplay{packet, packet})
			if i%10 == 0 {
				ps.Clear()
				ps.ResizeBuffer(8 + i%16)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			ps.HasRelatedPacket(env)
		}
	}()
	workers.Wait()
	ps.Clear()
	require.False(t, ps.HasRelatedPacket(env))
	ps.AddPacket(packet)
	require.True(t, ps.HasRelatedPacket(env))
}

func BenchmarkPacketFlowIngestionChurn(b *testing.B) {
	const capacity = 10000
	packets := make([]components.PacketDisplay, 2*capacity)
	for i := range packets {
		packets[i] = flowPacket("hunter-a", 17, fmt.Sprint(10000+i))
	}
	for _, indexed := range []bool{false, true} {
		b.Run(fmt.Sprintf("indexed_%t", indexed), func(b *testing.B) {
			ps := NewPacketStore(capacity)
			if indexed {
				ps.HasRelatedPacket(flowEnvelope("hunter-a", 17, 10000))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := (i * 64) % (len(packets) - 64)
				if indexed {
					ps.AddPacketBatch(packets[start : start+64])
				} else {
					addPacketBatchWithoutFlowIndex(ps, packets[start:start+64])
				}
			}
		})
	}
}

func TestPacketFlowAddressNormalization(t *testing.T) {
	for _, addresses := range [][4]string{
		{"2001:db8::1", "2001:db8::2", "2001:0db8:0:0:0:0:0:1", "2001:db8::2"},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.2", "192.0.2.1", "192.0.2.2"},
		{"192.0.2.1", "192.0.2.2", "::ffff:192.0.2.1", "::ffff:192.0.2.2"},
	} {
		ps := NewPacketStore(2)
		packet := flowPacket("a", 17, "1234")
		packet.SrcIP, packet.DstIP = addresses[0], addresses[1]
		ps.AddPacket(packet)
		env := flowEnvelope("a", 17, 1234)
		env.Flow.SourceAddress, env.Flow.DestinationAddress = netip.MustParseAddr(addresses[2]), netip.MustParseAddr(addresses[3])
		require.True(t, ps.HasRelatedPacket(env))
		env.Flow.SourceAddress, env.Flow.DestinationAddress = env.Flow.DestinationAddress, env.Flow.SourceAddress
		env.Flow.SourcePort, env.Flow.DestinationPort = env.Flow.DestinationPort, env.Flow.SourcePort
		require.True(t, ps.HasRelatedPacket(env))
	}
}

func TestPacketFlowProtocolFallback(t *testing.T) {
	ps := NewPacketStore(2)
	packet := flowPacket("a", 0, "1234")
	packet.Protocol = "TCP"
	ps.AddPacket(packet)
	require.True(t, ps.HasRelatedPacket(flowEnvelope("a", 6, 1234)))
	require.False(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1234)))
	ps.Clear()
	packet.Transport, packet.Protocol = 6, "DNS"
	ps.AddPacket(packet)
	require.True(t, ps.HasRelatedPacket(flowEnvelope("a", 6, 1234)))
	require.False(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1234)))
}

func TestPacketFlowLazyActivation(t *testing.T) {
	ps := NewPacketStore(2)
	ps.AddPacketBatch([]components.PacketDisplay{flowPacket("a", 17, "1234"), flowPacket("a", 17, "1235"), flowPacket("a", 17, "1236")})
	require.False(t, ps.flowIndexEnabled)
	require.Empty(t, ps.flowCounts)
	ps.ResizeBuffer(4)
	require.False(t, ps.HasRelatedPacket(events.Envelope{}))
	require.False(t, ps.flowIndexEnabled, "incomplete queries do not activate indexing")
	require.False(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1234)))
	require.True(t, ps.flowIndexEnabled)
	require.True(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1235)))
	require.True(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1236)))
	ps.Clear()
	require.True(t, ps.flowIndexEnabled)
	ps.AddPacket(flowPacket("a", 17, "1234"))
	require.True(t, ps.HasRelatedPacket(flowEnvelope("a", 17, 1234)))
}

func BenchmarkPacketFlowInactiveIngestion(b *testing.B) {
	batch := make([]components.PacketDisplay, 64)
	for i := range batch {
		batch[i] = flowPacket("hunter-a", 17, fmt.Sprint(10000+i))
	}
	for _, size := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("capacity_%d", size), func(b *testing.B) {
			ps := NewPacketStore(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ps.AddPacketBatch(batch)
			}
		})
	}
}
