package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// Construct raw blocks so the fixture's timestamp resolution is independent of
// pcapgo's writer (which always emits nanoseconds).
func readerTestNGCapture(order binary.ByteOrder, resolution *byte, offset int64, linkType uint16, packetType uint32, ticks []uint64, frameSize int) []byte {
	var capture bytes.Buffer
	writeBlock := func(typ uint32, body []byte) {
		size := 12 + len(body)
		block := make([]byte, size)
		order.PutUint32(block, typ)
		order.PutUint32(block[4:], uint32(size))
		copy(block[8:], body)
		order.PutUint32(block[size-4:], uint32(size))
		capture.Write(block)
	}
	section := make([]byte, 16)
	order.PutUint32(section, 0x1a2b3c4d)
	order.PutUint16(section[4:], 1)
	order.PutUint64(section[8:], ^uint64(0))
	writeBlock(0x0a0d0d0a, section)
	intf := make([]byte, 8)
	order.PutUint16(intf, linkType)
	order.PutUint32(intf[4:], 65535)
	if resolution != nil {
		option := make([]byte, 8)
		order.PutUint16(option, 9)
		order.PutUint16(option[2:], 1)
		option[4] = *resolution
		intf = append(intf, option...)
	}
	option := make([]byte, 12)
	order.PutUint16(option, 14)
	order.PutUint16(option[2:], 8)
	order.PutUint64(option[4:], uint64(offset))
	intf = append(intf, option...)
	intf = append(intf, make([]byte, 4)...)
	writeBlock(1, intf)
	for i, tick := range ticks {
		headerSize := 20
		if packetType == 3 {
			headerSize = 4
		}
		body := make([]byte, headerSize+((frameSize+3)&^3))
		if packetType == 3 {
			order.PutUint32(body, uint32(frameSize))
		} else {
			order.PutUint32(body[4:], uint32(tick>>32))
			order.PutUint32(body[8:], uint32(tick))
			order.PutUint32(body[12:], uint32(frameSize))
			order.PutUint32(body[16:], uint32(frameSize))
		}
		for j := headerSize; j < headerSize+frameSize; j++ {
			body[j] = byte(i + 1)
		}
		writeBlock(packetType, body)
	}
	return capture.Bytes()
}

func TestOfflineCursorPCAPNGTimestampPrecision(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, packetType := range []uint32{2, 6} {
			for _, tc := range []struct {
				name       string
				resolution byte
				absent     bool
				offset     int64
				ticks      uint64
				seconds    int64
				nanos      int64
			}{
				{name: "default microseconds", absent: true, ticks: 100123456, seconds: 100, nanos: 123456000},
				{name: "explicit seconds", resolution: 0, ticks: 100, seconds: 100},
				{name: "seconds negative offset", resolution: 0, ticks: 100, offset: -200, seconds: -100},
				{name: "nanoseconds", resolution: 9, ticks: 100123456789, seconds: 100, nanos: 123456789},
				{name: "decimal high resolution", resolution: 19, ticks: ^uint64(0), seconds: 1, nanos: 844674407},
				{name: "binary seconds", resolution: 0x80, ticks: 100, seconds: 100},
				{name: "binary fractional", resolution: 0x8a, ticks: 1023, nanos: 999023437},
				{name: "binary subnanosecond", resolution: 0x9f, ticks: 2147483647, nanos: 999999999},
				{name: "binary high resolution", resolution: 0xbf, ticks: ^uint64(0), seconds: 1, nanos: 999999999},
			} {
				t.Run(order.String()+"/"+string(rune('0'+packetType))+"/"+tc.name, func(t *testing.T) {
					resolution := &tc.resolution
					if tc.absent {
						resolution = nil
					}
					data := readerTestNGCapture(order, resolution, tc.offset, 1, packetType, []uint64{tc.ticks}, 60)
					c, err := cursorFromBytes(t, data)
					require.NoError(t, err)
					packet, err := c.Next(context.Background())
					require.NoError(t, err)
					require.Equal(t, time.Unix(tc.seconds, tc.nanos).UTC(), packet.Packet.Metadata().Timestamp)
					_, err = c.Next(context.Background())
					require.ErrorIs(t, err, io.EOF)
				})
			}
		}
	}
}

func TestOfflineCursorPCAPNGTimestampReadAlignment(t *testing.T) {
	for _, size := range []int{60, 8192} {
		resolution := byte(0)
		c, err := cursorFromBytes(t, readerTestNGCapture(binary.LittleEndian, &resolution, -1, 1, 6, []uint64{100, 101, 102}, size))
		require.NoError(t, err)
		for i := int64(0); i < 3; i++ {
			packet, err := c.Next(context.Background())
			require.NoError(t, err)
			require.Equal(t, time.Unix(99+i, 0).UTC(), packet.Packet.Metadata().Timestamp)
			require.Equal(t, bytes.Repeat([]byte{byte(i + 1)}, size), packet.Packet.Data())
		}
		_, err = c.Next(context.Background())
		require.ErrorIs(t, err, io.EOF)
	}
}

func TestOfflineCursorPCAPNGSimplePacketTimestamp(t *testing.T) {
	resolution := byte(0)
	c, err := cursorFromBytes(t, readerTestNGCapture(binary.LittleEndian, &resolution, 100, 1, 3, []uint64{0}, 60))
	require.NoError(t, err)
	packet, err := c.Next(context.Background())
	require.NoError(t, err)
	require.True(t, packet.Packet.Metadata().Timestamp.IsZero(), "simple packets have no timestamp, regardless of interface offset")
}

func TestOfflineCursorRejectsWidePCAPNGLinkTypes(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, linkType := range []uint16{257, 276} {
			_, err := cursorFromBytes(t, readerTestNGCapture(order, nil, 0, linkType, 6, []uint64{100}, 60))
			require.ErrorContains(t, err, "unsupported PCAPNG link type")
		}
	}
}

func TestOfflineCursorPCAPNativeLinkType(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, compressed := range []bool{false, true} {
			for _, nano := range []bool{false, true} {
				for _, linkType := range []uint32{1, 0x24000001, 257, 276} {
					header := make([]byte, 24+16+60)
					magic := uint32(0xa1b2c3d4)
					if nano {
						magic = 0xa1b23c4d
					}
					order.PutUint32(header, magic)
					order.PutUint16(header[4:], 2)
					order.PutUint16(header[6:], 4)
					order.PutUint32(header[16:], 65535)
					order.PutUint32(header[20:], linkType)
					order.PutUint32(header[24:], 100)
					order.PutUint32(header[32:], 60)
					order.PutUint32(header[36:], 60)
					if compressed {
						var out bytes.Buffer
						z := gzip.NewWriter(&out)
						_, err := z.Write(header)
						require.NoError(t, err)
						require.NoError(t, z.Close())
						header = out.Bytes()
					}
					c, err := cursorFromBytes(t, header)
					if linkType&0xffff > 255 {
						require.ErrorContains(t, err, "unsupported PCAP link type")
						continue
					}
					require.NoError(t, err)
					packet, err := c.Next(context.Background())
					require.NoError(t, err)
					require.Equal(t, layers.LinkTypeEthernet, packet.LinkType)
					require.Equal(t, time.Unix(100, 0).UTC(), packet.Packet.Metadata().Timestamp)
					_, err = c.Next(context.Background())
					require.ErrorIs(t, err, io.EOF)
				}
			}
		}
	}
}
