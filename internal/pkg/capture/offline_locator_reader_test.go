package capture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflinePCAPConsumedLocations(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, magic := range []uint32{0xa1b2c3d4, 0xa1b23c4d} {
			var input bytes.Buffer
			header := make([]byte, 24)
			order.PutUint32(header, magic)
			order.PutUint16(header[4:], 2)
			order.PutUint16(header[6:], 4)
			order.PutUint32(header[16:], 65535)
			order.PutUint32(header[20:], 1)
			input.Write(header)
			for i, size := range []int{3, 0, 8193, 1} {
				record := make([]byte, 16)
				order.PutUint32(record, uint32(100+i))
				order.PutUint32(record[4:], 123456)
				order.PutUint32(record[8:], uint32(size))
				order.PutUint32(record[12:], uint32(size+2))
				input.Write(record)
				input.Write(bytes.Repeat([]byte{byte(i + 1)}, size))
			}
			raw := input.Bytes()
			// An aggressively buffering reader must not change parser-owned offsets.
			reader, err := newOfflinePCAPReader(bufio.NewReaderSize(bytes.NewReader(raw), 32768))
			require.NoError(t, err)
			wantOrder := offline.CaptureLittleEndian
			if order == binary.BigEndian {
				wantOrder = offline.CaptureBigEndian
			}
			wantExponent := uint8(6)
			if magic == 0xa1b23c4d {
				wantExponent = 9
			}
			require.Equal(t, offline.CaptureContext{Format: offline.CaptureFormatPCAP, ByteOrder: wantOrder, LinkType: 1, Snaplen: 65535, TimestampResolutionBase: 10, TimestampResolutionExponent: wantExponent}, reader.context)
			oracle, err := pcapgo.NewReader(bytes.NewReader(raw))
			require.NoError(t, err)
			offset := int64(24)
			for ordinal := uint64(0); ordinal < 4; ordinal++ {
				data, ci, err := reader.ReadPacketData()
				require.NoError(t, err)
				wantData, wantCI, err := oracle.ReadPacketData()
				require.NoError(t, err)
				require.Equal(t, wantData, data)
				require.Equal(t, wantCI, ci)
				loc := reader.PacketLocation()
				require.Equal(t, offlinePacketLocation{PayloadOffset: offset + 16, PhysicalOrdinal: ordinal, CaptureInfo: ci, Context: reader.context}, loc)
				require.Equal(t, data, raw[loc.PayloadOffset:loc.PayloadOffset+int64(ci.CaptureLength)])
				offset += 16 + int64(len(data))
			}
			_, _, err = reader.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)
			for _, cut := range []int{1, 15, 16} {
				truncated, err := newOfflinePCAPReader(bytes.NewReader(raw[:24+cut]))
				require.NoError(t, err)
				_, _, err = truncated.ReadPacketData()
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
		}
	}
}

func TestOfflineNGConsumedLocations(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, typ := range []uint32{2, 3, 6} {
			raw := readerTestNGCapture(order, nil, -4, 1, typ, []uint64{1000000, 2000000, 3000000}, 8193)
			framing := &checkedNGReader{reader: bufio.NewReaderSize(bytes.NewReader(raw), 65536), ctx: context.Background()}
			ng, err := pcapgo.NewNgReader(framing, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
			require.NoError(t, err)
			reader := &offlineNGPacketReader{reader: ng, framing: framing}
			// Locate blocks directly from fixture framing, independently of reader state.
			offset := int64(0)
			for packet := uint64(0); packet < 3; {
				size := int64(order.Uint32(raw[offset+4:]))
				blockType := order.Uint32(raw[offset:])
				if blockType == typ {
					payloadOffset := offset + 28
					if typ == 3 {
						payloadOffset = offset + 12
					}
					data, ci, err := reader.ReadPacketData()
					require.NoError(t, err)
					loc := reader.PacketLocation()
					require.Equal(t, payloadOffset, loc.PayloadOffset)
					require.Equal(t, packet, loc.PhysicalOrdinal)
					require.Equal(t, ci, loc.CaptureInfo)
					require.Equal(t, offline.CaptureFormatPCAPNG, loc.Context.Format)
					require.Equal(t, uint32(65535), loc.Context.Snaplen)
					require.Equal(t, uint8(10), loc.Context.TimestampResolutionBase)
					require.Equal(t, uint8(6), loc.Context.TimestampResolutionExponent)
					require.Equal(t, int64(-4), loc.Context.TimestampOffset)
					require.Equal(t, typ == 3, loc.Context.TimestampMissing)
					wantOrder := offline.CaptureLittleEndian
					if order == binary.BigEndian {
						wantOrder = offline.CaptureBigEndian
					}
					require.Equal(t, wantOrder, loc.Context.ByteOrder)
					require.Equal(t, raw[payloadOffset:payloadOffset+int64(ci.CaptureLength)], data)
					require.Equal(t, typ == 3, ci.Timestamp.IsZero())
					packet++
				}
				offset += size
			}
			_, _, err = reader.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)
		}
	}
}

func TestOfflineNGRejectsInvalidLocatorFraming(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{"interface", func(raw []byte) { binary.LittleEndian.PutUint32(raw[64+8:], 1) }, "unknown interface"},
		{"length", func(raw []byte) { binary.LittleEndian.PutUint32(raw[64+20:], 8) }, "captured length"},
		{"trailer", func(raw []byte) { raw[len(raw)-1] = 1 }, "trailer mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readerTestNGCapture(binary.LittleEndian, nil, 0, 1, 6, []uint64{1}, 3)
			tc.mutate(raw)
			framing := &checkedNGReader{reader: bytes.NewReader(raw), ctx: context.Background()}
			ng, err := pcapgo.NewNgReader(framing, pcapgo.NgReaderOptions{})
			require.NoError(t, err)
			_, _, err = ng.ReadPacketData()
			require.ErrorContains(t, err, tc.want)
		})
	}
}
