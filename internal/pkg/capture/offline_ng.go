package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
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
			r.snaplen = r.order.Uint32(block[12:16])
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
				case 11:
					if length < 1 {
						return 0, fmt.Errorf("invalid PCAPNG filter option length")
					}
				case 14:
					if length != 8 {
						return 0, fmt.Errorf("invalid PCAPNG timestamp offset length")
					}
				}
			}
			if typ == 5 && code >= 2 && code <= 8 && length != 8 {
				return 0, fmt.Errorf("invalid PCAPNG statistics option length")
			}
			options += (length + 3) &^ 3
		}
		r.pending = block
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
