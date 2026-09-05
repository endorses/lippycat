package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// checkedNGReader validates framing before pcapgo can allocate from a claimed
// packet length. Phase 1 deliberately rejects multiple reassembly domains;
// libpcap otherwise silently conflates same-link-type PCAPNG interfaces.
type checkedNGReader struct {
	reader               io.Reader
	ctx                  context.Context
	order                binary.ByteOrder
	pending              []byte
	sections, interfaces int
	snaplen              uint32
	resolution           byte
	timestampOffset      int64
	packetTimestamp      time.Time
}

// pcapgo v1.1.19 treats explicit second resolution as microseconds and rounds
// binary resolutions before scaling, changing packet order across sources.
// Use the framing reader's exact conversion of the original packet ticks.
type offlineNGPacketReader struct {
	reader  *pcapgo.NgReader
	framing *checkedNGReader
}

func (r *offlineNGPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := r.reader.ReadPacketData()
	if err == nil {
		ci.Timestamp = r.framing.packetTimestamp
	}
	return data, ci, err
}

func (r *checkedNGReader) timestamp(ticks uint64) time.Time {
	denominator := uint64(1)
	if r.resolution&0x80 != 0 {
		denominator <<= r.resolution & 0x7f
	} else {
		for i := byte(0); i < r.resolution; i++ {
			denominator *= 10
		}
	}
	// The intermediate product can exceed uint64 at high resolutions.
	hi, lo := bits.Mul64(ticks%denominator, 1_000_000_000)
	nanos, _ := bits.Div64(hi, lo, denominator)
	return time.Unix(int64(ticks/denominator)+r.timestampOffset, int64(nanos)).UTC()
}

func (r *checkedNGReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(r.pending) == 0 {
		var header [12]byte
		if _, err := io.ReadFull(r.reader, header[:8]); err != nil {
			return 0, err
		}
		section := string(header[:4]) == "\x0a\x0d\x0d\x0a"
		n := 8
		if section {
			if _, err := io.ReadFull(r.reader, header[8:]); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, fmt.Errorf("truncated PCAPNG section: %w", err)
			}
			n = 12
			switch string(header[8:]) {
			case "\x4d\x3c\x2b\x1a":
				r.order = binary.LittleEndian
			case "\x1a\x2b\x3c\x4d":
				r.order = binary.BigEndian
			default:
				return 0, fmt.Errorf("invalid PCAPNG byte order")
			}
			r.sections++
			if r.sections > 1 {
				return 0, fmt.Errorf("PCAPNG with multiple sections is unsupported; split sections into separate capture files")
			}
		}
		if r.order == nil {
			return 0, fmt.Errorf("PCAPNG is missing section header")
		}
		size := r.order.Uint32(header[4:8])
		typ := r.order.Uint32(header[:4])
		minimum := uint32(12)
		switch typ {
		case 0x0a0d0d0a:
			minimum = 28
		case 1:
			minimum = 20
		case 2, 6:
			minimum = 32
		case 3:
			minimum = 16
		case 5:
			minimum = 24
		}
		if size < minimum || size%4 != 0 || size > offlineMaxPacketBytes {
			return 0, fmt.Errorf("invalid or oversized PCAPNG block length %d (limit %d)", size, offlineMaxPacketBytes)
		}
		block := make([]byte, int(size))
		copy(block, header[:n])
		if _, err := io.ReadFull(r.reader, block[n:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, fmt.Errorf("truncated PCAPNG block: %w", err)
		}
		if r.order.Uint32(block[len(block)-4:]) != size {
			return 0, fmt.Errorf("PCAPNG block length trailer mismatch")
		}
		options := len(block) - 4
		switch typ {
		case 0x0a0d0d0a:
			options = 24
		case 1:
			r.interfaces++
			if r.interfaces > 1 {
				return 0, fmt.Errorf("PCAPNG with multiple interfaces is unsupported; split interfaces into separate capture files")
			}
			if linkType := r.order.Uint16(block[8:10]); linkType > 255 {
				return 0, fmt.Errorf("unsupported PCAPNG link type %d: packet decoder supports only 8-bit link types", linkType)
			}
			r.snaplen = r.order.Uint32(block[12:16])
			r.resolution = 6 // Default applies only when if_tsresol is absent.
			r.timestampOffset = 0
			options = 16
		case 2, 6:
			caplen := r.order.Uint32(block[20:24])
			original := r.order.Uint32(block[24:28])
			if caplen > original || uint64(caplen) > uint64(size)-32 {
				return 0, fmt.Errorf("invalid PCAPNG captured length %d", caplen)
			}
			options = 28 + int((uint64(caplen)+3)&^3)
		case 3:
			caplen := r.order.Uint32(block[8:12])
			if r.snaplen != 0 && caplen > r.snaplen {
				caplen = r.snaplen
			}
			if uint64(caplen) > uint64(size)-16 {
				return 0, fmt.Errorf("invalid PCAPNG simple packet length %d", caplen)
			}
		case 5:
			options = 20
		}
		for options < len(block)-4 {
			if options+4 > len(block)-4 {
				return 0, fmt.Errorf("truncated PCAPNG option header")
			}
			code := r.order.Uint16(block[options:])
			length := int(r.order.Uint16(block[options+2:]))
			options += 4
			if options+length > len(block)-4 {
				return 0, fmt.Errorf("PCAPNG option exceeds block length")
			}
			if code == 0 {
				if length != 0 {
					return 0, fmt.Errorf("invalid PCAPNG end option")
				}
				break
			}
			if typ == 1 {
				switch code {
				case 9:
					if length != 1 || (block[options]&0x80 == 0 && block[options] > 19) || block[options]&0x7f > 63 {
						return 0, fmt.Errorf("unsupported PCAPNG timestamp resolution")
					}
					r.resolution = block[options]
				case 11:
					if length < 1 {
						return 0, fmt.Errorf("invalid PCAPNG filter option length")
					}
				case 14:
					if length != 8 {
						return 0, fmt.Errorf("invalid PCAPNG timestamp offset length")
					}
					r.timestampOffset = int64(r.order.Uint64(block[options:]))
				}
			}
			if typ == 5 && code >= 2 && code <= 8 && length != 8 {
				return 0, fmt.Errorf("invalid PCAPNG statistics option length")
			}
			options += (length + 3) &^ 3
		}
		switch typ {
		case 2, 6:
			ticks := uint64(r.order.Uint32(block[12:16]))<<32 | uint64(r.order.Uint32(block[16:20]))
			r.packetTimestamp = r.timestamp(ticks)
		case 3:
			r.packetTimestamp = time.Time{}
		}
		r.pending = block
	}
	// Return at most one block per Read: pcapgo's buffered reads must not
	// advance packetTimestamp past the packet currently being decoded.
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
