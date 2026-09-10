package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"path/filepath"
	"sort"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const offlineSortKeyBytes = 64
const offlineSortRunKeys = 4096

// OfflineSortProgress describes preprocessing before stateful packet analysis.
// BytesScanned counts normalized packet bytes, not compressed source bytes.
type OfflineSortProgress struct {
	Phase          string
	LogicalPackets uint64
	BytesScanned   uint64
}

type offlineSortFiles struct{ files []*offline.ScratchFile }

func (f *offlineSortFiles) Close() (err error) {
	for _, file := range f.files {
		err = errors.Join(err, file.Close())
	}
	return err
}

type offlineSortKey [offlineSortKeyBytes]byte

func (k offlineSortKey) less(other offlineSortKey) bool {
	a, b := int64(binary.LittleEndian.Uint64(k[:8])), int64(binary.LittleEndian.Uint64(other[:8]))
	if a != b {
		return a < b
	}
	for _, offset := range []int{8, 12} {
		a, b := binary.LittleEndian.Uint32(k[offset:]), binary.LittleEndian.Uint32(other[offset:])
		if a != b {
			return a < b
		}
	}
	return binary.LittleEndian.Uint64(k[16:]) < binary.LittleEndian.Uint64(other[16:])
}

// RunOfflineSortedStream normalizes each source in its original record order,
// then externally sorts logical packets before delivering any to the analyzer.
// The strict streaming reader remains available through RunOfflineOrderedStream.
// Ordering uses timestamp, source argument, then original logical sequence.
// Memory is bounded by 4096 fixed-size keys, fixed I/O buffers and one packet;
// all temporary disk bytes share Storage's active/replacement dataset budget.
// A non-nil cleanup result owns a failed scratch cleanup and must be retried.
func RunOfflineSortedStream(ctx context.Context, devices []pcaptypes.PcapInterface, filter string,
	storage *offline.Storage, progress func(OfflineSortProgress),
	processor func(context.Context, <-chan PacketInfo) error) (cleanup io.Closer, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(devices) > MaxOfflineSources {
		return nil, fmt.Errorf("offline capture supports at most %d sources (got %d); use fewer input files", MaxOfflineSources, len(devices))
	}
	if storage == nil {
		return nil, errors.New("offline sorting requires storage")
	}
	files := &offlineSortFiles{}
	defer func() {
		if closeErr := files.Close(); closeErr != nil {
			cleanup = files
			err = errors.Join(err, closeErr)
		}
	}()
	for range 3 {
		file, e := storage.NewScratchFile()
		if e != nil {
			return nil, e
		}
		files.files = append(files.files, file)
	}
	raw, input, output := files.files[0], files.files[1], files.files[2]
	state := OfflineSortProgress{Phase: "Reading"}
	lastProgress := time.Time{}
	report := func(force bool) {
		if progress != nil && (force || time.Since(lastProgress) >= 250*time.Millisecond) {
			lastProgress = time.Now()
			progress(state)
		}
	}
	report(true)
	keys := make([]offlineSortKey, 0, offlineSortRunKeys)
	writer := bufio.NewWriterSize(input, 64<<10)
	flushRun := func() error {
		sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
		for i := range keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := writer.Write(keys[i][:]); err != nil {
				return err
			}
		}
		keys = keys[:0]
		return nil
	}
	for source, device := range devices {
		cursor, e := newOfflineCursor(ctx, device, filter, uint32(source))
		if e != nil {
			return nil, e
		}
		cursor.allowRegression = true
		e = func() (readErr error) {
			defer func() { readErr = errors.Join(readErr, cursor.Close()) }()
			for {
				packet, e := cursor.Next(ctx)
				if errors.Is(e, io.EOF) {
					return nil
				}
				if e != nil {
					return e
				}
				data, ci := packet.Packet.Data(), packet.Packet.Metadata().CaptureInfo
				if len(data) > offlineMaxPacketBytes || ci.CaptureLength < 0 || ci.Length < 0 || uint64(ci.Length) > math.MaxUint32 || uint64(ci.CaptureLength) > math.MaxUint32 {
					return fmt.Errorf("offline ordering record exceeds supported allocation/length limits in %q", cursor.path)
				}
				if state.LogicalPackets >= math.MaxInt64/offlineSortKeyBytes || state.BytesScanned > math.MaxInt64-uint64(len(data)) {
					return errors.New("offline ordering stream exceeds addressable file size")
				}
				var key offlineSortKey
				binary.LittleEndian.PutUint64(key[0:], uint64(ci.Timestamp.Unix()))
				binary.LittleEndian.PutUint32(key[8:], uint32(ci.Timestamp.Nanosecond()))
				binary.LittleEndian.PutUint32(key[12:], packet.SourceIndex)
				binary.LittleEndian.PutUint64(key[16:], packet.SourceSequence)
				binary.LittleEndian.PutUint64(key[24:], state.BytesScanned)
				binary.LittleEndian.PutUint32(key[32:], uint32(len(data)))
				binary.LittleEndian.PutUint32(key[36:], uint32(ci.CaptureLength))
				binary.LittleEndian.PutUint32(key[40:], uint32(ci.Length))
				binary.LittleEndian.PutUint32(key[44:], packet.SourceInterfaceID)
				key[48] = byte(packet.LinkType)
				binary.LittleEndian.PutUint32(key[52:], crc32.ChecksumIEEE(data))
				binary.LittleEndian.PutUint32(key[56:], crc32.ChecksumIEEE(key[:56]))
				if _, e := raw.Write(data); e != nil {
					return e
				}
				keys = append(keys, key)
				state.LogicalPackets++
				state.BytesScanned += uint64(len(data))
				if len(keys) == cap(keys) {
					if e := flushRun(); e != nil {
						return e
					}
				}
				report(false)
			}
		}()
		if e != nil {
			return nil, e
		}
	}
	if e := flushRun(); e != nil {
		return nil, e
	}
	if e := writer.Flush(); e != nil {
		return nil, e
	}
	state.Phase = "Sorting"
	report(true)
	for width := uint64(offlineSortRunKeys); width < state.LogicalPackets; width *= 2 {
		if e := output.Reset(); e != nil {
			return nil, e
		}
		writer.Reset(output)
		for start := uint64(0); start < state.LogicalPackets; start += 2 * width {
			mid := min(start+width, state.LogicalPackets)
			end := min(start+2*width, state.LogicalPackets)
			if e := mergeOfflineSortRuns(ctx, input, writer, start, mid, end, func() { report(false) }); e != nil {
				return nil, e
			}
		}
		if e := writer.Flush(); e != nil {
			return nil, e
		}
		input, output = output, input
	}
	// Drop the obsolete index before indexing begins, leaving more shared disk
	// budget for the completed dataset and any previously installed session.
	if e := output.Close(); e != nil {
		return nil, e
	}
	state.Phase = "Replaying"
	report(true)
	return nil, replayOfflineSorted(ctx, devices, raw, input, state.LogicalPackets, state.BytesScanned, processor)
}

func mergeOfflineSortRuns(ctx context.Context, input *offline.ScratchFile, output io.Writer, start, mid, end uint64, progress func()) error {
	left := bufio.NewReaderSize(io.NewSectionReader(input, int64(start*offlineSortKeyBytes), int64((mid-start)*offlineSortKeyBytes)), 64<<10)
	right := bufio.NewReaderSize(io.NewSectionReader(input, int64(mid*offlineSortKeyBytes), int64((end-mid)*offlineSortKeyBytes)), 64<<10)
	var a, b offlineSortKey
	l, r := start, mid
	read := func(reader io.Reader, key *offlineSortKey) error { _, err := io.ReadFull(reader, key[:]); return err }
	if l < mid {
		if err := read(left, &a); err != nil {
			return err
		}
	}
	if r < end {
		if err := read(right, &b); err != nil {
			return err
		}
	}
	for l < mid || r < end {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r == end || (l < mid && !b.less(a)) {
			if _, err := output.Write(a[:]); err != nil {
				return err
			}
			l++
			if l < mid {
				if err := read(left, &a); err != nil {
					return err
				}
			}
		} else {
			if _, err := output.Write(b[:]); err != nil {
				return err
			}
			r++
			if r < end {
				if err := read(right, &b); err != nil {
					return err
				}
			}
		}
		progress()
	}
	return nil
}

func replayOfflineSorted(parent context.Context, devices []pcaptypes.PcapInterface, raw, index *offline.ScratchFile, count, rawBytes uint64, processor func(context.Context, <-chan PacketInfo) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	packets := make(chan PacketInfo)
	done := make(chan error, 1)
	go func() { defer cancel(); done <- processor(ctx, packets) }()
	reader := bufio.NewReaderSize(io.NewSectionReader(index, 0, int64(count*offlineSortKeyBytes)), 64<<10)
	produceErr := func() error {
		for row := uint64(0); row < count; row++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			var key offlineSortKey
			if _, err := io.ReadFull(reader, key[:]); err != nil {
				return fmt.Errorf("read offline ordering index: %w", err)
			}
			if crc32.ChecksumIEEE(key[:56]) != binary.LittleEndian.Uint32(key[56:]) {
				return errors.New("offline ordering index checksum mismatch")
			}
			source := binary.LittleEndian.Uint32(key[12:])
			offset, length := binary.LittleEndian.Uint64(key[24:]), uint64(binary.LittleEndian.Uint32(key[32:]))
			if uint64(source) >= uint64(len(devices)) || length > offlineMaxPacketBytes || offset > rawBytes || length > rawBytes-offset || binary.LittleEndian.Uint32(key[8:]) >= 1e9 {
				return errors.New("invalid offline ordering index record")
			}
			data := make([]byte, int(length))
			if _, err := raw.ReadAt(data, int64(offset)); err != nil {
				return fmt.Errorf("read offline ordering packet: %w", err)
			}
			if crc32.ChecksumIEEE(data) != binary.LittleEndian.Uint32(key[52:]) {
				return errors.New("offline ordering packet checksum mismatch")
			}
			link := layers.LinkType(key[48])
			packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
			packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
				Timestamp:     time.Unix(int64(binary.LittleEndian.Uint64(key[:8])), int64(binary.LittleEndian.Uint32(key[8:]))).UTC(),
				CaptureLength: int(binary.LittleEndian.Uint32(key[36:])), Length: int(binary.LittleEndian.Uint32(key[40:])), InterfaceIndex: int(binary.LittleEndian.Uint32(key[44:])),
			}
			info := PacketInfo{Packet: packet, LinkType: link, Interface: filepath.Base(devices[source].Name()), SourcePath: devices[source].Name(), SourceIndex: source, SourceSequence: binary.LittleEndian.Uint64(key[16:]), SourceInterfaceID: binary.LittleEndian.Uint32(key[44:])}
			observePacket(&info)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case packets <- info:
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
