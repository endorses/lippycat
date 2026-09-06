package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// offlinePacketLocation describes the last successfully parsed physical packet.
// Offsets count bytes consumed by the parser, never a buffered file's seek head.
type offlinePacketLocation struct {
	PayloadOffset   int64
	PhysicalOrdinal uint64
	CaptureInfo     gopacket.CaptureInfo
	Context         offline.CaptureContext
}

type offlinePCAPReader struct {
	reader   io.Reader
	order    binary.ByteOrder
	factor   uint32
	snaplen  uint32
	linkType layers.LinkType
	offset   int64
	ordinal  uint64
	location offlinePacketLocation
	context  offline.CaptureContext
}

func newOfflinePCAPReader(reader io.Reader) (*offlinePCAPReader, error) {
	var header [24]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("read PCAP header: %w", err)
	}
	r := &offlinePCAPReader{reader: reader, offset: 24, factor: 1000}
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1":
		r.order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4":
		r.order = binary.BigEndian
	case "\x4d\x3c\xb2\xa1":
		r.order, r.factor = binary.LittleEndian, 1
	case "\xa1\xb2\x3c\x4d":
		r.order, r.factor = binary.BigEndian, 1
	default:
		return nil, fmt.Errorf("unrecognized PCAP magic %x", header[:4])
	}
	if major := r.order.Uint16(header[4:6]); major != 2 {
		return nil, fmt.Errorf("unknown PCAP major version %d", major)
	}
	if minor := r.order.Uint16(header[6:8]); minor != 4 {
		return nil, fmt.Errorf("unknown PCAP minor version %d", minor)
	}
	linkType := r.order.Uint32(header[20:24]) & 0xffff
	if linkType > 255 {
		return nil, fmt.Errorf("unsupported PCAP link type %d: packet decoder supports only 8-bit link types", linkType)
	}
	r.linkType = layers.LinkType(linkType)
	r.context = offline.CaptureContext{Format: offline.CaptureFormatPCAP, ByteOrder: offline.CaptureLittleEndian, LinkType: linkType, Snaplen: r.order.Uint32(header[16:20]), TimestampResolutionBase: 10, TimestampResolutionExponent: 6}
	if r.order == binary.BigEndian {
		r.context.ByteOrder = offline.CaptureBigEndian
	}
	if r.factor == 1 {
		r.context.TimestampResolutionExponent = 9
	}
	r.snaplen = min(r.order.Uint32(header[16:20]), offlineMaxPacketBytes)
	return r, nil
}

func (r *offlinePCAPReader) LinkType() layers.LinkType { return r.linkType }
func (r *offlinePCAPReader) Snaplen() uint32           { return r.snaplen }
func (r *offlinePCAPReader) PacketLocation() offlinePacketLocation {
	return r.location
}

func (r *offlinePCAPReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var header [16]byte
	var ci gopacket.CaptureInfo
	if _, err := io.ReadFull(r.reader, header[:]); err != nil {
		return nil, ci, err
	}
	// Match pcapgo's timestamp conversion, including its uint32 multiplication.
	ci.Timestamp = time.Unix(int64(r.order.Uint32(header[:4])), int64(r.order.Uint32(header[4:8])*r.factor)).UTC()
	caplen, original := r.order.Uint32(header[8:12]), r.order.Uint32(header[12:16])
	if uint64(caplen) > uint64(math.MaxInt) || uint64(original) > uint64(math.MaxInt) {
		return nil, ci, fmt.Errorf("PCAP packet lengths exceed addressable memory")
	}
	ci.CaptureLength = int(caplen)
	ci.Length = int(original)
	if ci.CaptureLength > int(r.snaplen) {
		return nil, ci, fmt.Errorf("capture length exceeds snap length: %d > %d", ci.CaptureLength, r.snaplen)
	}
	if ci.CaptureLength > ci.Length {
		return nil, ci, fmt.Errorf("capture length exceeds original packet length: %d > %d", ci.CaptureLength, ci.Length)
	}
	if r.offset > math.MaxInt64-16-int64(ci.CaptureLength) || r.ordinal == math.MaxUint64 {
		return nil, ci, fmt.Errorf("PCAP packet location overflow")
	}
	data := make([]byte, ci.CaptureLength)
	if _, err := io.ReadFull(r.reader, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, ci, err
	}
	r.location = offlinePacketLocation{PayloadOffset: r.offset + 16, PhysicalOrdinal: r.ordinal, CaptureInfo: ci, Context: r.context}
	r.offset += 16 + int64(ci.CaptureLength)
	r.ordinal++
	return data, ci, nil
}
