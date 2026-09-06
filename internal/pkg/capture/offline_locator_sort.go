package capture

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const locatorKeyBytes = 192
const locatorHeaderBytes = 16

var locatorHeader = [locatorHeaderBytes]byte{'L', 'C', 'L', 'O', 'R', 'D', 'E', 'R', 1, 0, 192, 0}

const locatorRunKeys = 2048
const locatorReadBuffer = 16 << 10
const locatorPrefetchBytes = 1 << 20

type locatorKey [locatorKeyBytes]byte

func (k locatorKey) less(b locatorKey) bool {
	asec, bsec := int64(binary.LittleEndian.Uint64(k[:])), int64(binary.LittleEndian.Uint64(b[:]))
	if asec != bsec {
		return asec < bsec
	}
	for _, off := range []int{8, 12} {
		a, v := binary.LittleEndian.Uint32(k[off:]), binary.LittleEndian.Uint32(b[off:])
		if a != v {
			return a < v
		}
	}
	return binary.LittleEndian.Uint64(k[16:]) < binary.LittleEndian.Uint64(b[16:])
}
func encodeLocatorKey(p PacketInfo) (k locatorKey, err error) {
	v := p.Provenance
	if v == nil {
		return k, errors.New("normalized packet has no backing provenance")
	}
	ci, original := v.EffectiveCapture, v.OriginalCapture
	for _, n := range []int{ci.CaptureLength, ci.Length, original.CaptureLength, original.Length} {
		if n < 0 || uint64(n) > math.MaxUint32 {
			return k, errors.New("invalid locator capture length")
		}
	}
	if len(p.Packet.Data()) > offlineMaxPacketBytes {
		return k, errors.New("locator packet exceeds supported allocation limit")
	}
	put32 := func(off int, n uint32) { binary.LittleEndian.PutUint32(k[off:], n) }
	put64 := func(off int, n uint64) { binary.LittleEndian.PutUint64(k[off:], n) }
	put64(0, uint64(ci.Timestamp.Unix()))
	put32(8, uint32(ci.Timestamp.Nanosecond()))
	put32(12, p.SourceIndex)
	put64(16, p.SourceSequence)
	put32(24, v.Locator.BackingID)
	put64(28, uint64(v.Locator.Offset))
	put32(36, v.Locator.Length)
	copy(k[40:72], v.Locator.Digest[:])
	put32(72, uint32(ci.CaptureLength))
	put32(76, uint32(ci.Length))
	put32(80, uint32(ci.InterfaceIndex))
	k[84] = byte(p.LinkType)
	if v.Derived {
		k[85] = 1
	}
	k[86] = byte(v.OriginalLinkType)
	put64(88, v.PhysicalOrdinal)
	put64(96, uint64(original.Timestamp.Unix()))
	put32(104, uint32(original.Timestamp.Nanosecond()))
	put32(108, uint32(original.CaptureLength))
	put32(112, uint32(original.Length))
	put32(116, uint32(original.InterfaceIndex))
	c := v.Context
	k[120] = byte(c.Format)
	k[121] = byte(c.ByteOrder)
	k[122] = c.TimestampResolutionBase
	k[123] = c.TimestampResolutionExponent
	put32(124, c.SectionID)
	put32(128, c.InterfaceID)
	put32(132, c.LinkType)
	put32(136, c.Snaplen)
	put64(140, uint64(c.TimestampOffset))
	if c.TimestampMissing {
		k[148] = 1
	}
	put32(188, crc32.ChecksumIEEE(k[:188]))
	return k, nil
}
func (k locatorKey) validate(sources int) error {
	if crc32.ChecksumIEEE(k[:188]) != binary.LittleEndian.Uint32(k[188:]) {
		return errors.New("offline locator ordering checksum mismatch")
	}
	if uint64(binary.LittleEndian.Uint32(k[12:])) >= uint64(sources) || binary.LittleEndian.Uint32(k[8:]) >= 1e9 || binary.LittleEndian.Uint32(k[104:]) >= 1e9 || k.locator().Offset < 0 || k.locator().Length > offlineMaxPacketBytes || binary.LittleEndian.Uint32(k[72:]) != k.locator().Length {
		return errors.New("invalid offline locator ordering record")
	}
	if binary.LittleEndian.Uint32(k[132:]) > 255 || binary.LittleEndian.Uint32(k[116:]) != binary.LittleEndian.Uint32(k[128:]) || (k[122] != 2 && k[122] != 10) || (k[122] == 2 && k[123] > 63) || (k[122] == 10 && k[123] > 19) {
		return errors.New("invalid offline locator decoding context")
	}
	if k[85] > 1 || k[87] != 0 || k[148] > 1 || k[120] < byte(offline.CaptureFormatPCAP) || k[120] > byte(offline.CaptureFormatPCAPNG) || k[121] < byte(offline.CaptureLittleEndian) || k[121] > byte(offline.CaptureBigEndian) {
		return errors.New("invalid offline locator context")
	}
	for _, b := range k[149:188] {
		if b != 0 {
			return errors.New("invalid offline locator reserved bytes")
		}
	}
	return nil
}
func (k locatorKey) locator() (l offline.Locator) {
	l.BackingID = binary.LittleEndian.Uint32(k[24:])
	l.Offset = int64(binary.LittleEndian.Uint64(k[28:]))
	l.Length = binary.LittleEndian.Uint32(k[36:])
	copy(l.Digest[:], k[40:72])
	return
}
func (k locatorKey) packet(data []byte, devices []pcaptypes.PcapInterface) PacketInfo {
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(k[off:]) }
	u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(k[off:]) }
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(int64(u64(0)), int64(u32(8))).UTC(), CaptureLength: int(u32(72)), Length: int(u32(76)), InterfaceIndex: int(u32(80))}
	source := u32(12)
	link := layers.LinkType(k[84])
	packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
	packet.Metadata().CaptureInfo = ci
	p := PacketInfo{Packet: packet, LinkType: link, SourceIndex: source, SourceSequence: u64(16), SourceInterfaceID: u32(116), SourcePath: devices[source].Name(), Interface: filepath.Base(devices[source].Name())}
	p.Provenance = &offline.PacketProvenance{Locator: k.locator(), Derived: k[85] != 0, SourceIndex: source, SourcePath: p.SourcePath, LogicalSequence: p.SourceSequence, PhysicalOrdinal: u64(88), EffectiveCapture: ci, EffectiveLinkType: link, OriginalLinkType: layers.LinkType(k[86]), OriginalCapture: gopacket.CaptureInfo{Timestamp: time.Unix(int64(u64(96)), int64(u32(104))).UTC(), CaptureLength: int(u32(108)), Length: int(u32(112)), InterfaceIndex: int(u32(116))}, Context: offline.CaptureContext{Format: offline.CaptureFormat(k[120]), ByteOrder: offline.CaptureByteOrder(k[121]), TimestampResolutionBase: k[122], TimestampResolutionExponent: k[123], SectionID: u32(124), InterfaceID: u32(128), LinkType: u32(132), Snaplen: u32(136), TimestampOffset: int64(u64(140)), TimestampMissing: k[148] != 0}}
	return p
}

type locatorRange struct{ start, end uint64 }

// OfflineLocatorStream owns validated source handles and compact ordering keys.
// Preparation finishes every normalized source and its hash before Replay can
// construct an analysis consumer. Close remains retryable on cleanup failure.
type OfflineLocatorStream struct {
	mu                  sync.Mutex
	reservation         io.Closer
	progress            func(OfflineSortProgress)
	state               OfflineSortProgress
	storage             *offline.Storage
	backings            *offline.BackingRegistry
	backingsTransferred bool
	files               offlineSortFiles
	index               *offline.ScratchFile
	devices             []pcaptypes.PcapInterface
	identities          []offline.SourceIdentity
	ranges              []locatorRange
	count               uint64
	ordering            string
	closed              bool
}

func (s *OfflineLocatorStream) Identities() []offline.SourceIdentity {
	return append([]offline.SourceIdentity(nil), s.identities...)
}
func (s *OfflineLocatorStream) Ordering() string { return s.ordering }

// Backings borrows the prepared source registry while the stream remains open.
// A completed-dataset builder may take ownership with TransferBackings after
// successfully accepting this registry. Call outside Replay callbacks.
func (s *OfflineLocatorStream) Backings() *offline.BackingRegistry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backings
}

// TransferBackings gives the caller cleanup ownership of the source registry.
// Replay continues borrowing it: its new owner must keep it open until Replay
// and stream cleanup finish. Transfer is serialized with Replay and Close.
func (s *OfflineLocatorStream) TransferBackings() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.backingsTransferred {
		return errors.New("offline locator backings already closed or transferred")
	}
	s.backingsTransferred = true
	return nil
}

func (s *OfflineLocatorStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	err := s.files.Close()
	if !s.backingsTransferred {
		err = errors.Join(err, s.backings.Close())
	}
	if s.reservation != nil {
		err = errors.Join(err, s.reservation.Close())
		s.reservation = nil
	}
	return err
}

// PrepareOfflineLocatorStream scans original sources once and stores only
// normalized locators. Ordinary source packet bytes are never written to sort
// scratch. The returned value on error, if non-nil, owns failed cleanup.
func PrepareOfflineLocatorStream(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, storage *offline.Storage, progress func(OfflineSortProgress)) (prepared *OfflineLocatorStream, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if storage == nil {
		return nil, errors.New("offline locator ordering requires storage")
	}
	if len(devices) > MaxOfflineSources {
		return nil, fmt.Errorf("offline capture supports at most %d sources", MaxOfflineSources)
	}
	s := &OfflineLocatorStream{storage: storage, backings: storage.NewBackingRegistry(), devices: append([]pcaptypes.PcapInterface(nil), devices...), ordering: "direct"}
	s.progress = progress
	retainedBytes := uint64(8192 + len(devices)*1024)
	for _, device := range devices {
		retainedBytes += uint64(len(device.Name()))
	}
	s.reservation, err = storage.ReserveTransient(ctx, retainedBytes)
	if err != nil {
		closeErr := s.Close()
		if closeErr == nil {
			return nil, err
		}
		return s, errors.Join(err, closeErr)
	}
	defer func() {
		if err != nil {
			closeErr := s.Close()
			err = errors.Join(err, closeErr)
			if closeErr == nil {
				prepared = nil
			}
		}
	}()
	// ScratchFile.Write charges bytes before admission, with no uncharged writer buffer.
	s.index, err = storage.NewScratchFile()
	if err != nil {
		return s, err
	}
	s.files.files = append(s.files.files, s.index)
	if _, err = s.index.Write(locatorHeader[:]); err != nil {
		return s, err
	}
	cfg, _ := ctx.Value(offlineBackingsKey{}).(offlineBackingsConfig)
	ctx = WithOfflineBackings(ctx, s.backings, cfg.policy)
	state := OfflineSortProgress{Phase: "Reading"}
	last := time.Time{}
	report := func(force bool) {
		if progress != nil && (force || time.Since(last) >= 250*time.Millisecond) {
			progress(state)
			last = time.Now()
		}
	}
	report(true)
	regressed := false
	for source, device := range devices {
		cursor, e := newOfflineCursor(ctx, device, filter, uint32(source))
		if e != nil {
			return s, e
		}
		cursor.allowRegression = true
		r := locatorRange{start: s.count}
		var previous locatorKey
		hasPrevious := false
		e = func() (readErr error) {
			defer func() { readErr = errors.Join(readErr, cursor.Close()) }()
			for {
				p, e := cursor.Next(ctx)
				if errors.Is(e, io.EOF) {
					identity, e := s.backings.Identity(cursor.backingID)
					if e != nil {
						return e
					}
					s.identities = append(s.identities, identity)
					return nil
				}
				if e != nil {
					return e
				}
				key, e := encodeLocatorKey(p)
				if e != nil {
					return e
				}
				if hasPrevious && key.less(previous) {
					regressed = true
				}
				previous = key
				hasPrevious = true
				if s.count >= (math.MaxInt64-locatorHeaderBytes)/locatorKeyBytes || state.BytesScanned > math.MaxInt64-uint64(len(p.Packet.Data())) {
					return errors.New("offline locator index exceeds addressable size")
				}
				if _, e = s.index.Write(key[:]); e != nil {
					return e
				}
				s.count++
				state.LogicalPackets = s.count
				state.BytesScanned += uint64(len(p.Packet.Data()))
				report(false)
			}
		}()
		if e != nil {
			return s, e
		}
		r.end = s.count
		s.ranges = append(s.ranges, r)
	}
	state.Phase = "Sorting"
	report(true)
	if regressed {
		s.ordering = "external"
		if err = s.externalSort(ctx); err != nil {
			return s, err
		}
	} else if len(devices) > 1 {
		s.ordering = "heap"
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	s.state = state
	return s, nil
}

func (s *OfflineLocatorStream) externalSort(ctx context.Context) (err error) {
	reservation, err := s.storage.ReserveTransient(ctx, locatorRunKeys*locatorKeyBytes+3*locatorReadBuffer)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, reservation.Close()) }()
	input := s.index
	output, err := s.storage.NewScratchFile()
	if err != nil {
		return err
	}
	s.files.files = append(s.files.files, output)
	if _, err := output.Write(locatorHeader[:]); err != nil {
		return err
	}
	keys := make([]locatorKey, locatorRunKeys)
	for start := uint64(0); start < s.count; start += locatorRunKeys {
		n := min(uint64(locatorRunKeys), s.count-start)
		for i := uint64(0); i < n; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := input.ReadAt(keys[i][:], locatorHeaderBytes+int64((start+i)*locatorKeyBytes)); err != nil {
				return err
			}
			if err := keys[i].validate(len(s.devices)); err != nil {
				return err
			}
		}
		sort.Slice(keys[:n], func(i, j int) bool { return keys[i].less(keys[j]) })
		for i := uint64(0); i < n; i++ {
			if _, err := output.Write(keys[i][:]); err != nil {
				return err
			}
		}
	}
	input, output = output, input
	for width := uint64(locatorRunKeys); width < s.count; width *= 2 {
		if err := output.Reset(); err != nil {
			return err
		}
		if _, err := output.Write(locatorHeader[:]); err != nil {
			return err
		}
		for start := uint64(0); start < s.count; start += 2 * width {
			mid, end := min(start+width, s.count), min(start+2*width, s.count)
			if err := mergeLocatorRuns(ctx, input, output, start, mid, end); err != nil {
				return err
			}
		}
		input, output = output, input
	}
	s.index = input
	return output.Close()
}
func mergeLocatorRuns(ctx context.Context, input *offline.ScratchFile, output io.Writer, start, mid, end uint64) error {
	readers := []*bufio.Reader{bufio.NewReaderSize(io.NewSectionReader(input, locatorHeaderBytes+int64(start*locatorKeyBytes), int64((mid-start)*locatorKeyBytes)), locatorReadBuffer), bufio.NewReaderSize(io.NewSectionReader(input, locatorHeaderBytes+int64(mid*locatorKeyBytes), int64((end-mid)*locatorKeyBytes)), locatorReadBuffer)}
	positions, ends := [2]uint64{start, mid}, [2]uint64{mid, end}
	var keys [2]locatorKey
	for i := range 2 {
		if positions[i] < ends[i] {
			if _, err := io.ReadFull(readers[i], keys[i][:]); err != nil {
				return err
			}
		}
	}
	for positions[0] < ends[0] || positions[1] < ends[1] {
		if err := ctx.Err(); err != nil {
			return err
		}
		i := 0
		if positions[0] == ends[0] || (positions[1] < ends[1] && keys[1].less(keys[0])) {
			i = 1
		}
		if _, err := output.Write(keys[i][:]); err != nil {
			return err
		}
		positions[i]++
		if positions[i] < ends[i] {
			if _, err := io.ReadFull(readers[i], keys[i][:]); err != nil {
				return err
			}
		}
	}
	return nil
}

type locatorHead struct {
	key    locatorKey
	source int
}
type locatorHeap []locatorHead

func (h locatorHeap) Len() int           { return len(h) }
func (h locatorHeap) Less(i, j int) bool { return h[i].key.less(h[j].key) }
func (h locatorHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *locatorHeap) Push(v any)        { *h = append(*h, v.(locatorHead)) }
func (h *locatorHeap) Pop() any          { a := *h; v := a[len(a)-1]; *h = a[:len(a)-1]; return v }

// Replay transfers independently owned packet byte slices to the existing
// analysis envelope. Batch read leases end only after all packets are sent;
// the copies remain valid when downstream analysis retains packet data. Two
// packet copies are charged for the producer/consumer handoff overlap; further
// retention after receipt belongs to the analyzer's existing state budgets.
// Replay is serialized with Close; consumers must not synchronously Close the
// stream from inside their callback.
func (s *OfflineLocatorStream) Replay(parent context.Context, processor func(context.Context, <-chan PacketInfo) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("offline locator stream closed")
	}
	if err := parent.Err(); err != nil {
		return err
	}
	var header [locatorHeaderBytes]byte
	if _, err := s.index.ReadAt(header[:], 0); err != nil {
		return err
	}
	if header != locatorHeader {
		return errors.New("incompatible offline locator ordering format")
	}
	if s.progress != nil {
		state := s.state
		state.Phase = "Replaying"
		s.progress(state)
	}
	ranges := s.ranges
	if s.ordering != "heap" {
		ranges = []locatorRange{{0, s.count}}
	}
	reservation, err := s.storage.ReserveTransient(parent, uint64(len(ranges))*(locatorReadBuffer+locatorKeyBytes+128)+64*(locatorKeyBytes+64))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, reservation.Close()) }()
	readers := make([]*bufio.Reader, len(ranges))
	remaining := make([]uint64, len(ranges))
	heads := make(locatorHeap, 0, len(ranges))
	readHead := func(i int) error {
		if remaining[i] == 0 {
			return nil
		}
		var k locatorKey
		if _, err := io.ReadFull(readers[i], k[:]); err != nil {
			return err
		}
		if err := k.validate(len(s.devices)); err != nil {
			return err
		}
		identity, err := s.backings.Identity(k.locator().BackingID)
		if err != nil {
			return err
		}
		if identity.SourceIndex != int(binary.LittleEndian.Uint32(k[12:])) {
			return errors.New("offline locator source context mismatch")
		}
		remaining[i]--
		if s.ordering == "heap" {
			heap.Push(&heads, locatorHead{k, i})
		} else {
			heads = append(heads, locatorHead{k, i})
		}
		return nil
	}
	for i, r := range ranges {
		readers[i] = bufio.NewReaderSize(io.NewSectionReader(s.index, locatorHeaderBytes+int64(r.start*locatorKeyBytes), int64((r.end-r.start)*locatorKeyBytes)), locatorReadBuffer)
		remaining[i] = r.end - r.start
		if err := readHead(i); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	packets := make(chan PacketInfo)
	done := make(chan error, 1)
	go func() { defer cancel(); done <- processor(ctx, packets) }()
	var previous locatorKey
	hasPrevious := false
	produceErr := func() error {
		for len(heads) > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			keys := make([]locatorKey, 0, 64)
			locs := make([]offline.Locator, 0, 64)
			var bytes uint64
			for len(heads) > 0 && len(keys) < 64 {
				next := heads[0].key
				length := uint64(next.locator().Length)
				if len(keys) > 0 && bytes+length > locatorPrefetchBytes {
					break
				}
				var head locatorHead
				if s.ordering == "heap" {
					head = heap.Pop(&heads).(locatorHead)
				} else {
					head = heads[0]
					heads = heads[:0]
				}
				if hasPrevious && head.key.less(previous) {
					return errors.New("offline locator replay order regressed")
				}
				previous = head.key
				hasPrevious = true
				keys = append(keys, head.key)
				locs = append(locs, head.key.locator())
				bytes += length
				if err := readHead(head.source); err != nil {
					return err
				}
			}
			var maxPacket uint64
			for _, loc := range locs {
				maxPacket = max(maxPacket, uint64(loc.Length))
			}
			copyReservation, err := s.storage.ReserveTransient(ctx, 2*maxPacket)
			if err != nil {
				return err
			}
			lease, data, err := s.backings.ReadBatch(ctx, locs, max(uint64(locatorPrefetchBytes), bytes))
			if err != nil {
				return errors.Join(err, copyReservation.Close())
			}
			err = func() (sendErr error) {
				defer func() { sendErr = errors.Join(sendErr, lease.Close(), copyReservation.Close()) }()
				for i, k := range keys {
					owned := append([]byte(nil), data[i]...)
					info := k.packet(owned, s.devices)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case packets <- info:
						observePacket(info)
					}
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	}()
	close(packets)
	if produceErr != nil {
		cancel()
	}
	consumerErr := <-done
	if consumerErr != nil {
		return errors.Join(produceErr, fmt.Errorf("offline consumer: %w", consumerErr))
	}
	if errors.Is(produceErr, context.Canceled) && parent.Err() == nil {
		return errors.Join(produceErr, ErrOfflineConsumerStopped)
	}
	return errors.Join(produceErr, parent.Err())
}
