package capture

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestCaptureFragmentsAcrossInterfacesAndFamilies(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, reassemble := range []bool{false, true} {
			name := "ipv4"
			if ipv6 {
				name = "ipv6"
			}
			if reassemble {
				name += "/attempted"
			} else {
				name += "/disabled"
			}
			t.Run(name, func(t *testing.T) {
				payload := []byte("INVITE sip:alice@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
				frames := udpFragmentFrames(t, ipv6, 5060, payload)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				buffer := NewPacketBuffer(ctx, 4)
				defer buffer.Close()
				ip4 := NewIPv4Defragmenter()
				ip6 := NewIPv6Defragmenter()
				collector := newTelemetryCollector(nil)
				collector.ipv4 = ip4
				var wg sync.WaitGroup
				for i, frame := range frames {
					path := filepath.Join(t.TempDir(), "interface.pcap")
					f, err := os.Create(path)
					require.NoError(t, err)
					writer := pcapgo.NewWriter(f)
					require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeRaw))
					require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: len(frame), Length: len(frame)}, frame))
					require.NoError(t, f.Close())
					handle, err := pcap.OpenOffline(path)
					require.NoError(t, err)
					name := "eth0"
					if i == 1 {
						name = "eth1"
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer handle.Close()
						captureFromInterface(ctx, &mockPcapInterface{name: name, handle: handle}, "", buffer, ip4, ip6, collector, &sync.Mutex{}, CaptureOptions{ReassembleIPFragments: reassemble})
					}()
				}
				wg.Wait()
				buffer.CloseInputs()
				var output []PacketInfo
				for packet := range buffer.Receive() {
					output = append(output, packet)
				}
				if reassemble {
					require.Len(t, output, 1)
				} else {
					require.Len(t, output, 2)
				}
				snapshot := collector.report("eth0", 0, 0, 0, buffer)
				if ipv6 {
					require.Equal(t, uint64(1), snapshot.FragmentIngress["eth0"].IPv6Observed)
					require.Equal(t, uint64(1), snapshot.FragmentIngress["eth1"].IPv6Observed)
					attempted := uint64(0)
					if reassemble {
						attempted = 1
					}
					require.Equal(t, attempted, snapshot.FragmentIngress["eth0"].IPv6Attempted)
					require.Equal(t, attempted, snapshot.FragmentIngress["eth1"].IPv6Attempted)
				} else {
					require.Equal(t, uint64(1), snapshot.FragmentIngress["eth0"].IPv4Observed)
					require.Equal(t, uint64(1), snapshot.FragmentIngress["eth1"].IPv4Observed)
					attempted := uint64(0)
					if reassemble {
						attempted = 1
					}
					require.Equal(t, attempted, snapshot.FragmentIngress["eth0"].IPv4Attempted)
					require.Equal(t, attempted, snapshot.FragmentIngress["eth1"].IPv4Attempted)
					if reassemble {
						require.Equal(t, uint64(1), snapshot.IPv4Defrag.CompletedDatagrams)
					}
				}
			})
		}
	}
}

func TestCaptureInterleavedIPv4AndIPv6Fragments(t *testing.T) {
	payload := []byte("INVITE sip:alice@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	ip4 := udpFragmentFrames(t, false, 5060, payload)
	ip6 := udpFragmentFrames(t, true, 5060, payload)
	output := runFragmentCapture(t, [][]byte{ip4[0], ip6[0], ip4[1], ip6[1]}, layers.LinkTypeRaw, CaptureOptions{ReassembleIPFragments: true})
	require.Len(t, output, 2)
	var seen4, seen6 bool
	for _, packet := range output {
		if packet.Packet.Layer(layers.LayerTypeIPv4) != nil {
			seen4 = true
		}
		if packet.Packet.Layer(layers.LayerTypeIPv6) != nil {
			seen6 = true
		}
		require.Equal(t, payload, packet.Packet.TransportLayer().LayerPayload())
	}
	require.True(t, seen4)
	require.True(t, seen6)
}
