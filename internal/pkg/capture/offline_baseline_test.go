package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// BenchmarkOfflineOrderedBaseline measures the existing collect/sort/replay path.
// Generate fixtures outside the timer without retaining a packet-sized Go slice.
// Run each size in a fresh test process and measure child peak RSS externally.
// This excludes application analysis, bridge buffering, and terminal rendering.
func BenchmarkOfflineOrderedBaseline(b *testing.B) {
	for _, count := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("packets_%d", count), func(b *testing.B) {
			name := filepath.Join(b.TempDir(), "baseline.pcap")
			f, err := os.Create(name)
			require.NoError(b, err)
			w := pcapgo.NewWriter(f)
			require.NoError(b, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
			// Valid Ethernet/IPv4/UDP frame, 256 captured bytes, one fixed flow.
			raw := make([]byte, 256)
			copy(raw, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 242, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x27, 0x10, 0x4e, 0x20, 0, 222, 0, 0})
			for i := range count {
				require.NoError(b, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, int64(i)*1000), CaptureLength: len(raw), Length: len(raw)}, raw))
			}
			require.NoError(b, f.Close())
			b.ReportAllocs()
			b.SetBytes(int64(count * len(raw)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				f, err := os.Open(name)
				require.NoError(b, err)
				started := time.Now()
				seen := 0
				RunOfflineOrderedContext(context.Background(), []pcaptypes.PcapInterface{pcaptypes.CreateOfflineInterface(f)}, "", func(ch <-chan PacketInfo) {
					for range ch {
						if seen == 0 {
							b.ReportMetric(float64(time.Since(started).Nanoseconds()), "first-packet-ns")
						}
						seen++
					}
				})
				require.NoError(b, f.Close())
				require.Equal(b, count, seen)
			}
			b.ReportMetric(float64(count), "packets/op")
		})
	}
}
