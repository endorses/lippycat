package capture

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Offline readers accept bounded records and fail explicitly when fragment state
// cannot fit. These are independent from the eventual dataset/cache budget.
const offlineMaxPacketBytes = 16 << 20
const offlineMaxFragmentBytes = 16 << 20
const offlineMaxFragmentFlows = 4096

type offlinePacketReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}
type offlineCursor struct {
	reader           offlinePacketReader
	closer           io.Closer
	decompressor     io.Closer
	linkType         layers.LinkType
	bpf              *pcap.BPF
	path             string
	sourceIndex      uint32
	sequence         uint64
	previous         time.Time
	hasPrevious      bool
	ip4              *IPv4Defragmenter
	ip6              *IPv6Defragmenter
	cleanup          time.Time
	closed           bool
	spiCache         *ttlCache[uint32, layers.IPProtocol]
	fragCache        *ttlCache[uint32, ipv6FragInfo]
	fragmentEstimate int
}

func newOfflineCursor(ctx context.Context, dev pcaptypes.PcapInterface, filter string, sourceIndex uint32) (_ *offlineCursor, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := &offlineCursor{path: dev.Name(), sourceIndex: sourceIndex, ip4: NewIPv4Defragmenter(), ip6: NewIPv6Defragmenter()}
	c.spiCache = newTTLCache[uint32, layers.IPProtocol](5 * time.Minute)
	c.fragCache = newTTLCache[uint32, ipv6FragInfo](30 * time.Second)
	info, err := os.Stat(c.path)
	if err != nil {
		return nil, fmt.Errorf("stat offline source %q: %w", c.path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("offline source %q must be a regular capture file", c.path)
	}
	f, err := os.Open(c.path)
	if err != nil {
		return nil, fmt.Errorf("open offline source %q: %w", c.path, err)
	}
	c.closer = f
	defer func() {
		if err != nil {
			err = fmt.Errorf("offline source %q: %w", c.path, errors.Join(err, c.Close()))
		}
	}()
	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("read capture header: %w", err)
	}
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		framing := &checkedNGReader{reader: br, ctx: ctx}
		r, e := pcapgo.NewNgReader(framing, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
		if e != nil {
			return nil, fmt.Errorf("read PCAPNG header: %w", e)
		}
		c.reader, c.linkType = &offlineNGPacketReader{reader: r, framing: framing}, r.LinkType()
	} else {
		// Inspect the native link type before pcapgo narrows it to uint8.
		// Keep its existing support for gzip-compressed classic PCAP inputs.
		if magic[0] == 0x1f && magic[1] == 0x8b {
			z, e := gzip.NewReader(br)
			if e != nil {
				return nil, fmt.Errorf("read compressed PCAP header: %w", e)
			}
			c.decompressor = z
			br = bufio.NewReader(z)
		}
		if e := validateOfflinePCAPHeader(br); e != nil {
			return nil, e
		}
		r, e := pcapgo.NewReader(br)
		if e != nil {
			return nil, fmt.Errorf("read PCAP header: %w", e)
		}
		if r.Snaplen() > offlineMaxPacketBytes {
			r.SetSnaplen(offlineMaxPacketBytes)
		}
		c.reader, c.linkType = r, r.LinkType()
	}
	if filter != "" {
		bpfLinkType, e := offlineBPFLinkType(c.linkType)
		if e != nil {
			return nil, e
		}
		c.bpf, err = pcap.NewBPF(bpfLinkType, offlineMaxPacketBytes, filter)
		if err != nil {
			return nil, fmt.Errorf("compile BPF %q: %w", filter, err)
		}
	}
	return c, nil
}

// Capture files use portable LINKTYPE values, whereas libpcap's BPF compiler
// takes native DLT values. Keep the file value for decoding and packet metadata.
func offlineBPFLinkType(linkType layers.LinkType) (layers.LinkType, error) {
	var name string
	switch linkType {
	case layers.LinkTypeRaw:
		name = "RAW"
	case layers.LinkTypeATM_RFC1483:
		name = "ATM_RFC1483"
	case layers.LinkTypeLoop:
		name = "LOOP"
	default:
		return linkType, nil
	}
	native := pcap.DatalinkNameToVal(name)
	if native < 0 || native > 255 {
		return 0, fmt.Errorf("unsupported native BPF link type %d for %s", native, name)
	}
	return layers.LinkType(native), nil
}

func validateOfflinePCAPHeader(reader *bufio.Reader) error {
	header, err := reader.Peek(24)
	if err != nil {
		return fmt.Errorf("read PCAP header: %w", err)
	}
	var order binary.ByteOrder
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
	default:
		return fmt.Errorf("unrecognized PCAP magic %x", header[:4])
	}
	// The upper 16 bits carry additional information such as FCS length.
	linkType := order.Uint32(header[20:24]) & 0xffff
	if linkType > 255 {
		return fmt.Errorf("unsupported PCAP link type %d: packet decoder supports only 8-bit link types", linkType)
	}
	return nil
}

func (c *offlineCursor) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.ip4 = nil
	c.ip6 = nil
	c.spiCache = nil
	c.fragCache = nil
	c.reader = nil
	c.bpf = nil
	var err error
	if c.decompressor != nil {
		err = c.decompressor.Close()
	}
	if c.closer != nil {
		err = errors.Join(err, c.closer.Close())
	}
	return err
}

func (c *offlineCursor) Next(ctx context.Context) (PacketInfo, error) {
	if c.closed {
		return PacketInfo{}, errors.New("offline cursor is closed")
	}
	for {
		if err := ctx.Err(); err != nil {
			return PacketInfo{}, err
		}
		data, ci, err := c.reader.ReadPacketData()
		if err != nil {
			if err == io.EOF && ci.CaptureLength == 0 {
				return PacketInfo{}, io.EOF
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return PacketInfo{}, fmt.Errorf("read source %q: %w", c.path, err)
		}
		if err := ctx.Err(); err != nil {
			return PacketInfo{}, err
		}
		// Match original on-disk frames before reassembly/decapsulation, as libpcap does.
		if c.bpf != nil && !c.bpf.Matches(ci, data) {
			continue
		}
		if c.cleanup.IsZero() || ci.Timestamp.Sub(c.cleanup) >= time.Second {
			c.ip4.DiscardOlderThan(ci.Timestamp.Add(-30 * time.Second))
			c.ip6.DiscardOlderThan(ci.Timestamp.Add(-30 * time.Second))
			c.spiCache.Sweep()
			c.fragCache.Sweep()
			c.cleanup = ci.Timestamp
		}
		newPacket := gopacket.NewPacket(data, c.linkType, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
		newPacket.Metadata().CaptureInfo = ci
		// Reassemble IPv4 fragments before any further processing. A fragmented
		// SIP message would otherwise have its SDP body stranded in a later
		// fragment and never parsed.
		if ipLayer := newPacket.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip4 := ipLayer.(*layers.IPv4)
			if ip4.Flags&layers.IPv4MoreFragments != 0 || ip4.FragOffset > 0 {
				c.fragmentEstimate += 2 * len(data)
				if int(ip4.Length) < int(ip4.IHL)*4 || int(ip4.Length)-int(ip4.IHL)*4 > len(ip4.Payload) {
					return PacketInfo{}, fmt.Errorf("offline source %q contains a truncated IPv4 fragment", c.path)
				}
				reassembledIP, err := c.ip4.DefragIPv4WithTimestamp(ip4, ci.Timestamp)
				if err != nil {
					return PacketInfo{}, fmt.Errorf("offline source %q IPv4 reassembly: %w", c.path, err)
				}
				if reassembledIP == nil {
					if err := c.checkFragments(); err != nil {
						return PacketInfo{}, err
					}
					continue // Still waiting for more fragments
				}
				reassembled := rebuildReassembledPacket(newPacket, reassembledIP, c.linkType)
				reassembled.Metadata().Timestamp = newPacket.Metadata().Timestamp
				newPacket = reassembled
			}
		}

		// Reassemble plain (non-ESP) IPv6 fragments. gopacket has no built-in
		// IPv6 reassembly; ESP-encapsulated fragments are handled by
		// decapsulateIPv6FragmentESP below.
		if fragLayer := newPacket.Layer(layers.LayerTypeIPv6Fragment); fragLayer != nil {
			if frag, ok := fragLayer.(*layers.IPv6Fragment); ok && frag.NextHeader != layers.IPProtocolESP {
				if ip6Layer := newPacket.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
					ip6 := ip6Layer.(*layers.IPv6)
					c.fragmentEstimate += 2 * len(data)
					// The decoder clips truncated payloads to the captured bytes.
					// Reject them before the final fragment's clipped length can
					// be mistaken for the complete reassembled datagram length.
					capturedPayload := len(ip6.Payload)
					if ip6.HopByHop != nil {
						// gopacket removes this extension from IPv6.Payload, but
						// the advertised IPv6 length still includes its bytes.
						capturedPayload += ip6.HopByHop.ActualLength
					}
					if int(ip6.Length) > capturedPayload {
						return PacketInfo{}, fmt.Errorf("offline source %q contains a truncated IPv6 fragment", c.path)
					}
					reassembledIP6, err := c.ip6.DefragIPv6WithTimestamp(ip6, frag, ci.Timestamp)
					if err != nil {
						return PacketInfo{}, fmt.Errorf("offline source %q IPv6 reassembly: %w", c.path, err)
					}
					if reassembledIP6 == nil {
						if err := c.checkFragments(); err != nil {
							return PacketInfo{}, err
						}
						continue // Still waiting for more fragments
					}
					reassembled := rebuildReassembledIPv6Packet(newPacket, reassembledIP6, c.linkType)
					reassembled.Metadata().Timestamp = newPacket.Metadata().Timestamp
					newPacket = reassembled
				}
			}
		}

		// Handle VXLAN decapsulation - extract the inner Ethernet frame so all
		// downstream processing (SIP detection, RTP correlation, etc.) sees the
		// real traffic rather than the VXLAN tunnel wrapper.
		effectiveLinkType := c.linkType
		if inner, ok := decapsulateVXLAN(newPacket); ok {
			newPacket = inner
			effectiveLinkType = layers.LinkTypeEthernet
		}

		// Handle ESP with NULL cipher - common in IMS/VoLTE where ESP transport
		// mode provides integrity without encryption. Must run after VXLAN
		// decapsulation so it sees the inner packets from VXLAN tunnels.
		if ESPDecapEnabled() {
			if inner, ok := decapsulateESPNullWithCache(newPacket, c.spiCache); ok {
				newPacket = inner
				newPacket.Metadata().CaptureLength = len(newPacket.Data())
				newPacket.Metadata().Length = len(newPacket.Data())
			} else if inner, ok := decapsulateIPv6FragmentESPWithCaches(newPacket, c.spiCache, c.fragCache); ok {
				newPacket = inner
				newPacket.Metadata().CaptureLength = len(newPacket.Data())
				newPacket.Metadata().Length = len(newPacket.Data())
			}
		}

		if c.spiCache.Len()+c.fragCache.Len() > offlineMaxFragmentFlows {
			return PacketInfo{}, fmt.Errorf("offline source %q ESP state limit exceeded (%d entries)", c.path, offlineMaxFragmentFlows)
		}
		if c.hasPrevious && newPacket.Metadata().Timestamp.Before(c.previous) {
			return PacketInfo{}, &offline.TimestampRegressionError{Source: offline.SourcePosition{Path: c.path, ArgumentIndex: c.sourceIndex, Sequence: c.sequence}, Previous: c.previous, Current: newPacket.Metadata().Timestamp}
		}
		c.previous = newPacket.Metadata().Timestamp
		c.hasPrevious = true
		c.sequence++
		return PacketInfo{LinkType: effectiveLinkType, Packet: newPacket, Interface: filepath.Base(c.path), SourcePath: c.path, SourceIndex: c.sourceIndex, SourceSequence: c.sequence - 1, SourceInterfaceID: uint32(ci.InterfaceIndex)}, nil
	}
}

func (c *offlineCursor) checkFragments() error {
	flows := len(c.ip4.ipFlows) + len(c.ip6.ipFlows)
	if flows <= offlineMaxFragmentFlows && c.fragmentEstimate <= offlineMaxFragmentBytes {
		return nil
	}
	bytes := 0
	for _, f := range c.ip4.ipFlows {
		for e := f.List.Front(); e != nil; e = e.Next() {
			ip := e.Value.(*layers.IPv4)
			bytes += cap(ip.Contents) + cap(ip.Payload)
		}
	}
	for _, f := range c.ip6.ipFlows {
		for _, p := range f.pieces {
			bytes += cap(p.data)
		}
	}
	c.fragmentEstimate = bytes
	if flows > offlineMaxFragmentFlows || bytes > offlineMaxFragmentBytes {
		return fmt.Errorf("offline source %q fragment budget exceeded (%d flows, %d bytes); supported limits are %d flows and %d bytes", c.path, flows, bytes, offlineMaxFragmentFlows, offlineMaxFragmentBytes)
	}
	return nil
}
