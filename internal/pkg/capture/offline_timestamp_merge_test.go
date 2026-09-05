package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestRunOfflineOrderedPCAPNGTimestampResolution(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolution byte
		ticks      []uint64
		ngTimes    []time.Time
		pcapTimes  []time.Time
	}{
		{
			name:       "explicit seconds",
			resolution: 0,
			ticks:      []uint64{100, 102},
			ngTimes:    []time.Time{time.Unix(100, 0), time.Unix(102, 0)},
			pcapTimes:  []time.Time{time.Unix(99, 0), time.Unix(100, 0), time.Unix(101, 0)},
		},
		{
			name:       "binary fractions",
			resolution: 0x8a, // Each tick is exactly 1/1024 second.
			ticks:      []uint64{1023, 1024},
			ngTimes:    []time.Time{time.Unix(0, 999023437), time.Unix(1, 0)},
			pcapTimes:  []time.Time{time.Unix(0, 999023200), time.Unix(0, 999023437), time.Unix(0, 999023600)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Write nanosecond PCAP timestamps independently of the PCAPNG
			// conversion so sub-microsecond ordering errors remain observable.
			frame := make([]byte, 60)
			var pcapData bytes.Buffer
			pcapWriter := pcapgo.NewWriterNanos(&pcapData)
			require.NoError(t, pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet))
			for _, timestamp := range tc.pcapTimes {
				require.NoError(t, pcapWriter.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(frame), Length: len(frame)}, frame))
			}

			var ngData bytes.Buffer
			ngWriter, err := pcapgo.NewNgWriter(&ngData, layers.LinkTypeEthernet)
			require.NoError(t, err)
			for range tc.ticks {
				require.NoError(t, ngWriter.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(frame), Length: len(frame)}, frame))
			}
			require.NoError(t, ngWriter.Flush())
			// pcapgo's writer uses a fixed resolution. Set the wire resolution
			// and raw ticks directly instead of sharing reader conversion code.
			data := ngData.Bytes()
			packetIndex := 0
			resolutionSet := false
			for offset := 0; offset < len(data); {
				size := int(binary.LittleEndian.Uint32(data[offset+4:]))
				switch binary.LittleEndian.Uint32(data[offset:]) {
				case 1:
					for option := offset + 16; option < offset+size-4; {
						code := binary.LittleEndian.Uint16(data[option:])
						length := int(binary.LittleEndian.Uint16(data[option+2:]))
						if code == 0 {
							break
						}
						if code == 9 {
							require.Equal(t, 1, length)
							data[option+4] = tc.resolution
							resolutionSet = true
						}
						option += 4 + ((length + 3) &^ 3)
					}
				case 6:
					ticks := tc.ticks[packetIndex]
					binary.LittleEndian.PutUint32(data[offset+12:], uint32(ticks>>32))
					binary.LittleEndian.PutUint32(data[offset+16:], uint32(ticks))
					packetIndex++
				}
				offset += size
			}
			require.True(t, resolutionSet)
			require.Equal(t, len(tc.ticks), packetIndex)
			dir := t.TempDir()
			ngPath, pcapPath := filepath.Join(dir, "source.pcapng"), filepath.Join(dir, "source.pcap")
			require.NoError(t, os.WriteFile(ngPath, data, 0600))
			require.NoError(t, os.WriteFile(pcapPath, pcapData.Bytes(), 0600))

			var got []PacketInfo
			err = RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, ngPath, pcapPath), "", func(packets <-chan PacketInfo) {
				for packet := range packets {
					got = append(got, packet)
				}
			})
			require.NoError(t, err)
			require.Len(t, got, 5)
			wantTimes := []time.Time{tc.pcapTimes[0], tc.ngTimes[0], tc.pcapTimes[1], tc.pcapTimes[2], tc.ngTimes[1]}
			wantPaths := []string{pcapPath, ngPath, pcapPath, pcapPath, ngPath}
			for i, packet := range got {
				require.True(t, wantTimes[i].Equal(packet.Packet.Metadata().Timestamp), "packet %d: want %s, got %s", i, wantTimes[i], packet.Packet.Metadata().Timestamp)
				require.Equal(t, wantPaths[i], packet.SourcePath, "packet %d; equal timestamps must retain source-argument order", i)
			}
		})
	}
}
