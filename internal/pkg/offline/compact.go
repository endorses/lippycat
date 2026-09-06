package offline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// StatelessDecoder reconstructs packet-local details from owned effective bytes.
// Implementations capture immutable settings and must not advance live analyzers.
// The result must own all values; the backend applies finalized overrides last.
type StatelessDecoder func(context.Context, []byte, Summary) (types.PacketDisplay, error)

const compactHeaderBytes = 32
const compactBlockHeaderBytes = 72
const compactRows = 128
const compactIndexBytes = 64

type compactState struct {
	registries         compactRegistries
	registry           *BackingRegistry
	decode             StatelessDecoder
	sources            []SourcePosition
	rows               [][]byte
	rowMemory, rowDisk uint64
	sourceMemory       uint64
	pendingAmend       bool
	first              PacketID
}

type compactRow struct {
	NodeRef, DeviceRef, ContextRef uint32
	Argument                       uint32
	Interface                      uint32
	Sequence                       uint64
	Locator                        Locator
	Context                        CaptureContext
	PhysicalOrdinal                uint64
	OriginalCaptured, OriginalWire uint32
	OriginalLink                   uint32
	Derived                        bool
	Captured, Original             uint32
	Timestamp                      time.Time
	SrcIP, DstIP, SrcPort, DstPort string
	Protocol, Info, Node, Device   string
	Transport                      uint8
	Length                         int
	LinkType                       layers.LinkType
	Projection                     compactProjection
}

type compactMetadata struct {
	VoIP  *types.VoIPMetadata
	DNS   *types.DNSMetadata
	Email *types.EmailMetadata
	TLS   *types.TLSMetadata
	HTTP  *types.HTTPMetadata
}

type compactOverrides struct {
	Mask     uint8
	Metadata compactMetadata
}

func metadataOf(p types.PacketDisplay) compactMetadata {
	return compactMetadata{p.VoIPData, p.DNSData, p.EmailData, p.TLSData, p.HTTPData}
}
func (m compactMetadata) apply(p *types.PacketDisplay) {
	p.VoIPData = m.VoIP
	p.DNSData = m.DNS
	p.EmailData = m.Email
	p.TLSData = m.TLS
	p.HTTPData = m.HTTP
}
func (r compactRow) summary(id PacketID) Summary {
	p := types.PacketDisplay{Timestamp: r.Timestamp, SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, Protocol: r.Protocol, Info: r.Info, NodeID: r.Node, Interface: r.Device, Transport: r.Transport, Length: r.Length, LinkType: r.LinkType}
	r.Projection.apply(&p)
	return Summary{ID: id, packet: p}
}
func (r compactRow) source(c *compactState) (SourcePosition, error) {
	if uint64(r.Argument) >= uint64(len(c.sources)) {
		return SourcePosition{}, errors.New("compact invalid source reference")
	}
	s := c.sources[r.Argument]
	s.ArgumentIndex = r.Argument
	s.InterfaceID = r.Interface
	s.Sequence = r.Sequence
	return s, nil
}
func (d *diskDataset) schemaVersion() uint16 {
	if d.compact != nil {
		return 2
	}
	return RecordSchemaVersion
}

// NewCompactBuilder is an internal migration entry point. Ownership of registry
// transfers only on success. Persistent reuse and production cutover are separate.
func (s *Storage) NewCompactBuilder(g DatasetGeneration, sources []SourcePosition, registry *BackingRegistry, decode StatelessDecoder) (*Builder, error) {
	if registry == nil || decode == nil {
		return nil, errors.New("compact builder requires backing registry and stateless decoder")
	}
	if registry.storage != s {
		return nil, errors.New("compact backing registry belongs to another storage owner")
	}
	var sourceMemory uint64
	if err := measureMemory(reflect.ValueOf(sources), &sourceMemory, s.limits.MaxRecordBytes); err != nil {
		return nil, err
	}
	sourceMemory += uint64(len(sources))*uint64(reflect.TypeOf(SourcePosition{}).Size()) + 256
	if err := s.reserveMemory(context.Background(), sourceMemory); err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.releaseMemory(sourceMemory)
		}
	}()
	b, err := s.NewBuilder(g, sources)
	if err != nil {
		return nil, err
	}
	for kind, f := range []*os.File{b.d.summaries, b.d.details, b.d.offsets} {
		var h [compactHeaderBytes]byte
		copy(h[:], "LCOV2DAT")
		binary.LittleEndian.PutUint16(h[8:], 2)
		binary.LittleEndian.PutUint16(h[12:], uint16(kind+1))
		binary.LittleEndian.PutUint64(h[16:], uint64(g))
		if err = f.Truncate(0); err == nil {
			s.releaseDisk(streamHeaderBytes)
			b.d.ownedBytes -= streamHeaderBytes
			_, err = f.Seek(0, io.SeekStart)
		}
		if err == nil {
			err = b.write(f, h[:])
		}
		if err != nil {
			return nil, errors.Join(err, b.Close())
		}
	}
	b.summaryEnd = compactHeaderBytes
	b.detailEnd = compactHeaderBytes
	b.d.compact = &compactState{registry: registry, decode: decode, sources: b.sources, sourceMemory: sourceMemory}
	transferred = true
	return b, nil
}

func (b *Builder) AppendCompact(ctx context.Context, detail Detail, provenance PacketProvenance) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return errors.New("offline builder closed")
	}
	if b.failure != nil {
		return b.failure
	}
	defer func() {
		if err != nil {
			b.failure = err
		}
	}()
	if b.d.compact == nil {
		return errors.New("AppendCompact requires compact builder")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if detail.Packet.Length >= 0 && uint64(detail.Packet.Length) > math.MaxUint64-b.accumulator.stats.Bytes {
		return errors.New("compact packet byte total exceeds uint64 range")
	}
	if b.d.count >= (math.MaxInt64-compactHeaderBytes)/compactIndexBytes {
		return errors.New("compact packet count overflow")
	}
	if err = b.validateCompactDetail(ctx, detail, provenance); err != nil {
		return err
	}
	return b.storeCompact(ctx, PacketID(b.d.count), detail, provenance, false)
}

// Apply the same invariants to initial rows and generic amendments. Finish need
// not reread every unamended row, so builders must reject unreadable values here.
func (b *Builder) validateCompactDetail(ctx context.Context, detail Detail, provenance PacketProvenance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if uint64(detail.Source.ArgumentIndex) >= uint64(len(b.d.compact.sources)) {
		return errors.New("compact invalid source argument")
	}
	if detail.Packet.Length < 0 {
		return errors.New("compact invalid packet length")
	}
	if err := validateCompactContext(provenance.Context, uint32(provenance.OriginalLinkType)); err != nil {
		return err
	}
	if provenance.OriginalCapture.CaptureLength < 0 || provenance.OriginalCapture.Length < 0 || uint64(provenance.OriginalCapture.CaptureLength) > math.MaxUint32 || uint64(provenance.OriginalCapture.Length) > math.MaxUint32 {
		return errors.New("compact invalid original capture lengths")
	}
	locator := provenance.Locator
	if detail.CapturedLength != locator.Length {
		return errors.New("compact captured length differs from locator")
	}
	if uint64(len(detail.Packet.RawData)) != uint64(locator.Length) || sha256.Sum256(detail.Packet.RawData) != locator.Digest {
		return errors.New("compact locator does not match effective bytes")
	}
	desc, err := b.d.compact.registry.Describe(locator.BackingID)
	if err != nil {
		return err
	}
	if desc.Source.SourceIndex != int(detail.Source.ArgumentIndex) {
		return errors.New("compact source argument does not match backing")
	}
	if detail.Source.Path != b.d.compact.sources[detail.Source.ArgumentIndex].Path {
		return errors.New("compact source path does not match registered argument")
	}
	if locator.Offset < 0 || uint64(locator.Offset) > uint64(desc.Size) || uint64(locator.Length) > uint64(desc.Size)-uint64(locator.Offset) {
		return errors.New("compact locator exceeds backing bounds")
	}
	return nil
}

func validateCompactContext(ctx CaptureContext, originalLink uint32) error {
	if ctx.LinkType > math.MaxUint8 || originalLink > math.MaxUint8 || ctx.Format > CaptureFormatPCAPNG || ctx.ByteOrder > CaptureBigEndian {
		return errors.New("compact invalid original decoding context")
	}
	return nil
}

func (b *Builder) storeCompact(ctx context.Context, id PacketID, detail Detail, provenance PacketProvenance, amend bool) error {
	loc := provenance.Locator
	d := b.d
	max := d.storage.limits.MaxRecordBytes
	reservation := max*5 + 4096
	if err := d.storage.reserveMemory(ctx, reservation); err != nil {
		return err
	}
	defer d.storage.releaseMemory(reservation)
	if _, err := compactRecordMemory(&detail, max); err != nil {
		return err
	}
	summary := NewSummary(id, detail.Packet)
	decoded, err := d.compact.decode(ctx, detail.Packet.RawData, summary)
	if err != nil {
		return fmt.Errorf("compact stateless baseline: %w", err)
	}
	overrides := metadataDifference(metadataOf(detail.Packet), metadataOf(decoded))
	meta, err := encodeCompactValue(overrides, max)
	if err != nil {
		return err
	}
	var off, size uint64
	if overrides.Mask != 0 {
		off, size, err = b.writeCompactBlock(d.details, 4, id, [][]byte{meta})
		if err != nil {
			return err
		}
		b.detailEnd += size
	}
	r := compactRow{Argument: detail.Source.ArgumentIndex, Interface: detail.Source.InterfaceID, Sequence: detail.Source.Sequence, Locator: loc, Context: provenance.Context, PhysicalOrdinal: provenance.PhysicalOrdinal, OriginalCaptured: uint32(provenance.OriginalCapture.CaptureLength), OriginalWire: uint32(provenance.OriginalCapture.Length), OriginalLink: uint32(provenance.OriginalLinkType), Derived: provenance.Derived, Captured: detail.CapturedLength, Original: detail.OriginalLength, Timestamp: detail.Packet.Timestamp, SrcIP: detail.Packet.SrcIP, DstIP: detail.Packet.DstIP, SrcPort: detail.Packet.SrcPort, DstPort: detail.Packet.DstPort, Protocol: detail.Packet.Protocol, Info: detail.Packet.Info, Node: detail.Packet.NodeID, Device: detail.Packet.Interface, Transport: detail.Packet.Transport, Length: detail.Packet.Length, LinkType: detail.Packet.LinkType, Projection: projectionOf(summary.packet)}
	if err = b.internCompactRow(ctx, &r); err != nil {
		return err
	}
	row, err := encodeCompactValue(r, max)
	if err != nil {
		return err
	}
	c := d.compact
	// Each pending row includes its sparse metadata reference. Both owned heap
	// capacity and eventual on-disk bytes are admitted before buffering.
	encoded := make([]byte, 16+len(row))
	binary.LittleEndian.PutUint64(encoded, off)
	binary.LittleEndian.PutUint64(encoded[8:], size)
	copy(encoded[16:], row)
	cost := uint64(cap(encoded)) + 32
	admission := uint64(len(encoded)) + uint64(len(compactFieldNames[reflect.TypeOf(compactRow{})])+2)*40 + compactBlockHeaderBytes + compactIndexBytes
	if len(c.rows) > 0 && (len(c.rows) >= compactRows || c.rowDisk+admission > max) {
		if err = b.flushCompact(); err != nil {
			return err
		}
	}
	if admission > max {
		return errors.New("compact first row exceeds block limit")
	}
	if err = d.storage.reserveMemory(ctx, cost); err != nil {
		return err
	}
	if err = d.storage.reserveDisk(admission); err != nil {
		d.storage.releaseMemory(cost)
		return err
	}
	if len(c.rows) == 0 {
		c.first = id
		c.pendingAmend = amend
	}
	c.rows = append(c.rows, encoded)
	c.rowMemory += cost
	c.rowDisk += admission
	if amend {
		b.amended = true
		if err = b.flushCompact(); err != nil {
			return err
		}
	} else {
		b.accumulator.Add(summary)
		d.count++
	}
	return nil
}

func metadataDifference(a, b compactMetadata) compactOverrides {
	result := compactOverrides{}
	av, bv, rv := reflect.ValueOf(a), reflect.ValueOf(b), reflect.ValueOf(&result.Metadata).Elem()
	for i := 0; i < 5; i++ {
		if !reflect.DeepEqual(av.Field(i).Interface(), bv.Field(i).Interface()) {
			result.Mask |= 1 << i
			rv.Field(i).Set(av.Field(i))
		}
	}
	return result
}
func (o compactOverrides) apply(p *types.PacketDisplay) {
	v := reflect.ValueOf(&o.Metadata).Elem()
	m := metadataOf(*p)
	target := reflect.ValueOf(&m).Elem()
	for i := 0; i < 5; i++ {
		if o.Mask&(1<<i) != 0 {
			target.Field(i).Set(v.Field(i))
		}
	}
	m.apply(p)
}

func (b *Builder) flushCompact() error {
	c := b.d.compact
	if c == nil || len(c.rows) == 0 {
		return nil
	}
	if err := b.d.storage.reserveMemory(context.Background(), c.rowDisk+compactBlockHeaderBytes); err != nil {
		return err
	}
	scratch := c.rowDisk + compactBlockHeaderBytes
	defer b.d.storage.releaseMemory(scratch)
	// Already-admitted bytes move from the pending buffer to the file owner.
	b.d.storage.releaseDisk(c.rowDisk)
	off, size, err := b.writeCompactBlock(b.d.summaries, 1, c.first, c.rows)
	if err == nil {
		for i := range c.rows {
			var entry [compactIndexBytes]byte
			binary.LittleEndian.PutUint64(entry[:], off)
			binary.LittleEndian.PutUint64(entry[8:], size)
			copy(entry[16:32], c.rows[i][:16])
			id := uint64(c.first) + uint64(i)
			checksum, e := b.d.compactIndexChecksum(entry[:32], PacketID(id))
			if e != nil {
				err = e
				break
			}
			copy(entry[32:], checksum[:])
			if c.pendingAmend {
				n, e := b.d.offsets.WriteAt(entry[:], compactHeaderBytes+int64(id)*compactIndexBytes)
				if e == nil && n != len(entry) {
					e = io.ErrShortWrite
				}
				err = e
			} else {
				err = b.write(b.d.offsets, entry[:])
			}
			if err != nil {
				break
			}
		}
	}
	b.d.storage.releaseMemory(c.rowMemory)
	c.rows = nil
	c.rowMemory = 0
	c.rowDisk = 0
	c.pendingAmend = false
	b.summaryEnd += size
	return err
}

func (d *diskDataset) validateCompactStreams() error {
	for i, f := range []*os.File{d.summaries, d.details, d.offsets} {
		var h [32]byte
		if _, err := f.ReadAt(h[:], 0); err != nil {
			return err
		}
		if string(h[:8]) != "LCOV2DAT" || binary.LittleEndian.Uint16(h[8:]) != 2 || binary.LittleEndian.Uint16(h[10:]) != 0 || binary.LittleEndian.Uint16(h[12:]) != uint16(i+1) || binary.LittleEndian.Uint16(h[14:]) != 0 || binary.LittleEndian.Uint64(h[16:]) != uint64(d.generation) || binary.LittleEndian.Uint64(h[24:]) != 0 {
			return errors.New("invalid compact stream header/version")
		}
	}
	return nil
}

func (d *diskDataset) compactOffsets(id PacketID) ([4]uint64, error) {
	var result [4]uint64
	if uint64(id) >= d.count {
		return result, errors.New("compact packet ID out of range")
	}
	var data [compactIndexBytes]byte
	if _, err := d.offsets.ReadAt(data[:], compactHeaderBytes+int64(id)*compactIndexBytes); err != nil {
		return result, err
	}
	checksum, err := d.compactIndexChecksum(data[:32], id)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(data[32:], checksum[:]) {
		return result, errors.New("compact row directory checksum mismatch")
	}
	for i := range result {
		result[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	return result, nil
}

func (d *diskDataset) readCompactRow(ctx context.Context, id PacketID, withMetadata bool) (compactRow, compactOverrides, uint64, error) {
	var row compactRow
	var overrides compactOverrides
	offsets, err := d.compactOffsets(id)
	if err != nil {
		return row, overrides, 0, err
	}
	p, held, err := d.compactBlock(ctx, d.summaries, offsets[0], offsets[1], 1, id)
	if err != nil {
		return row, overrides, 0, err
	}
	if len(p) < 16 {
		d.storage.releaseMemory(held)
		return row, overrides, 0, errors.New("compact truncated row")
	}
	if binary.LittleEndian.Uint64(p) != offsets[2] || binary.LittleEndian.Uint64(p[8:]) != offsets[3] {
		d.storage.releaseMemory(held)
		return row, overrides, 0, errors.New("compact inconsistent metadata directory reference")
	}
	err = decodeCompactValue(p[16:], &row, d.storage.limits.MaxRecordBytes)
	if err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	if err = d.compact.resolveCompactRow(&row); err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	if _, err = row.source(d.compact); err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	if err = validateCompactContext(row.Context, row.OriginalLink); err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	desc, e := d.compact.registry.Describe(row.Locator.BackingID)
	if e != nil || row.Locator.Offset < 0 || uint64(row.Locator.Offset) > uint64(desc.Size) || uint64(row.Locator.Length) > uint64(desc.Size)-uint64(row.Locator.Offset) || desc.Source.SourceIndex != int(row.Argument) {
		d.storage.releaseMemory(held)
		return row, overrides, 0, errors.Join(e, errors.New("compact invalid backing reference"))
	}
	if row.Length < 0 || row.Locator.Offset < 0 || row.Captured != row.Locator.Length {
		d.storage.releaseMemory(held)
		return row, overrides, 0, errors.New("compact invalid row bounds")
	}
	rowMemory := uint64(reflect.TypeOf(row).Size())
	if err = measureMemory(reflect.ValueOf(row), &rowMemory, d.storage.limits.MaxRecordBytes); err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	d.storage.releaseMemory(held - rowMemory)
	held = rowMemory
	// The authoritative metadata reference lives in the mutable row directory;
	// amendments replace this narrow reference without copying source bytes.
	if !withMetadata || (offsets[2] == 0 && offsets[3] == 0) {
		return row, overrides, held, nil
	}
	p2, more, err := d.compactBlock(ctx, d.details, offsets[2], offsets[3], 4, id)
	if err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	err = decodeCompactValue(p2, &overrides, d.storage.limits.MaxRecordBytes)
	held += more
	if err != nil || overrides.Mask&^uint8(31) != 0 {
		d.storage.releaseMemory(held)
		return row, overrides, 0, errors.Join(err, errors.New("compact invalid metadata override"))
	}
	metadataMemory := uint64(reflect.TypeOf(overrides).Size())
	if err = measureMemory(reflect.ValueOf(overrides), &metadataMemory, d.storage.limits.MaxRecordBytes); err != nil {
		d.storage.releaseMemory(held)
		return row, overrides, 0, err
	}
	d.storage.releaseMemory(more - metadataMemory)
	held -= more - metadataMemory
	return row, overrides, held, nil
}

func (d *diskDataset) readCompact(ctx context.Context, id PacketID, kind uint16, value any) (uint64, error) {
	row, overrides, held, err := d.readCompactRow(ctx, id, kind == 2)
	if err != nil {
		return 0, err
	}
	fail := func(e error) (uint64, error) { d.storage.releaseMemory(held); return 0, e }
	summary, summaryHeld, err := d.materializeCompactSummary(ctx, row, id)
	if err != nil {
		return fail(err)
	}
	held += summaryHeld
	if kind == 1 {
		target, ok := value.(*Summary)
		if !ok {
			return fail(errors.New("compact summary destination mismatch"))
		}
		*target = summary
	} else {
		target, ok := value.(*Detail)
		if !ok {
			return fail(errors.New("compact detail destination mismatch"))
		}
		lease, e := d.compact.registry.Read(ctx, row.Locator)
		if e != nil {
			return fail(e)
		}
		if e = d.storage.reserveMemory(ctx, uint64(len(lease.Bytes))); e != nil {
			return fail(errors.Join(e, lease.Close()))
		}
		held += uint64(len(lease.Bytes))
		raw := append([]byte(nil), lease.Bytes...)
		if e = lease.Close(); e != nil {
			return fail(e)
		}
		if e = d.storage.reserveMemory(ctx, d.storage.limits.MaxRecordBytes); e != nil {
			return fail(e)
		}
		held += d.storage.limits.MaxRecordBytes
		packet, e := d.compact.decode(ctx, raw, summary)
		if e != nil {
			return fail(e)
		}
		// Search/list scalar semantics are finalized by the ingestion adapter.
		metadata := metadataOf(packet)
		packet = summary.DisplayFields()
		metadata.apply(&packet)
		overrides.apply(&packet)
		packet.RawData = raw
		source, e := row.source(d.compact)
		if e != nil {
			return fail(e)
		}
		*target = Detail{ID: id, Source: source, CapturedLength: row.Captured, OriginalLength: row.Original, Packet: packet}
	}
	actual, e := compactRecordMemory(value, d.storage.limits.MaxRecordBytes)
	if e != nil {
		return fail(e)
	}
	if actual > held {
		if e = d.storage.reserveMemory(ctx, actual-held); e != nil {
			return fail(e)
		}
	} else {
		d.storage.releaseMemory(held - actual)
	}
	return actual, nil
}

func (d *diskDataset) readCompactRaw(ctx context.Context, id PacketID) (Detail, uint64, error) {
	if err := d.validateCompactStreams(); err != nil {
		return Detail{}, 0, err
	}
	row, _, held, err := d.readCompactRow(ctx, id, false)
	if err != nil {
		return Detail{}, 0, err
	}
	defer d.storage.releaseMemory(held)
	lease, err := d.compact.registry.Read(ctx, row.Locator)
	if err != nil {
		return Detail{}, 0, err
	}
	n := uint64(len(lease.Bytes)) + 512
	if err = d.storage.reserveMemory(ctx, n); err != nil {
		return Detail{}, 0, errors.Join(err, lease.Close())
	}
	raw := append([]byte(nil), lease.Bytes...)
	if err = lease.Close(); err != nil {
		d.storage.releaseMemory(n)
		return Detail{}, 0, err
	}
	source, err := row.source(d.compact)
	if err != nil {
		d.storage.releaseMemory(n)
		return Detail{}, 0, err
	}
	return Detail{ID: id, Source: source, CapturedLength: row.Captured, OriginalLength: row.Original, Packet: types.PacketDisplay{Timestamp: row.Timestamp, LinkType: row.LinkType, RawData: raw}}, n, nil
}

func (d *diskDataset) closeCompact() error {
	c := d.compact
	d.releaseCompactRegistries()
	if c.sourceMemory != 0 {
		d.storage.releaseMemory(c.sourceMemory)
		c.sourceMemory = 0
	}
	c.sources = nil
	if c.rowMemory > 0 {
		d.storage.releaseMemory(c.rowMemory)
		c.rowMemory = 0
	}
	if c.rowDisk > 0 {
		d.storage.releaseDisk(c.rowDisk)
		c.rowDisk = 0
	}
	c.rows = nil
	return c.registry.Close()
}

func (b *Builder) updateCompact(ctx context.Context, id PacketID, mutate func(*Detail) error) error {
	if err := b.flushCompact(); err != nil {
		return err
	}
	detail, held, err := b.d.readDetail(ctx, id)
	if err != nil {
		return err
	}
	defer b.d.storage.releaseMemory(held)
	row, _, rowHeld, err := b.d.readCompactRow(ctx, id, false)
	if err != nil {
		return err
	}
	defer b.d.storage.releaseMemory(rowHeld)
	// The callback may grow the detail up to MaxRecordBytes. Keep that
	// capacity charged until serialization completes, alongside the source row.
	callbackMemory := b.d.storage.limits.MaxRecordBytes
	if err = b.d.storage.reserveMemory(ctx, callbackMemory); err != nil {
		return err
	}
	defer b.d.storage.releaseMemory(callbackMemory)
	if err = mutate(&detail); err != nil {
		return err
	}
	detail.ID, detail.Token = id, Token{}
	provenance := PacketProvenance{Locator: row.Locator, Context: row.Context, PhysicalOrdinal: row.PhysicalOrdinal, Derived: row.Derived, OriginalLinkType: layers.LinkType(row.OriginalLink), OriginalCapture: gopacket.CaptureInfo{CaptureLength: int(row.OriginalCaptured), Length: int(row.OriginalWire)}}
	if err = b.validateCompactDetail(ctx, detail, provenance); err != nil {
		return err
	}
	b.amended = true
	return b.storeCompact(ctx, id, detail, provenance, true)
}

// AmendVoIP finalizes SIP/EOF metadata without reading or decoding source bytes.
func (b *Builder) AmendVoIP(ctx context.Context, id PacketID, protocol, info string, metadata *types.VoIPMetadata) (err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return errors.New("offline builder closed")
	}
	if b.failure != nil {
		return b.failure
	}
	defer func() {
		if err != nil {
			b.failure = err
		}
	}()
	if b.d.compact == nil {
		return errors.New("AmendVoIP requires compact builder")
	}
	if err = b.flushCompact(); err != nil {
		return err
	}
	row, overrides, held, err := b.d.readCompactRow(ctx, id, true)
	if err != nil {
		return err
	}
	defer b.d.storage.releaseMemory(held)
	max := b.d.storage.limits.MaxRecordBytes
	if err = b.d.storage.reserveMemory(ctx, max*4); err != nil {
		return err
	}
	defer b.d.storage.releaseMemory(max * 4)
	row.Protocol = protocol
	row.Info = info
	p := row.summary(id).packet
	p.VoIPData = metadata
	row.Projection = projectionOf(p)
	overrides.Mask |= 1
	overrides.Metadata.VoIP = metadata
	meta, err := encodeCompactValue(overrides, max)
	if err != nil {
		return err
	}
	off, size, err := b.writeCompactBlock(b.d.details, 4, id, [][]byte{meta})
	if err != nil {
		return err
	}
	if err = b.internCompactRow(ctx, &row); err != nil {
		return err
	}
	encoded, err := encodeCompactValue(row, max)
	if err != nil {
		return err
	}
	data := make([]byte, 16+len(encoded))
	binary.LittleEndian.PutUint64(data, off)
	binary.LittleEndian.PutUint64(data[8:], size)
	copy(data[16:], encoded)
	so, sn, err := b.writeCompactBlock(b.d.summaries, 1, id, [][]byte{data})
	if err != nil {
		return err
	}
	var entry [compactIndexBytes]byte
	for i, v := range []uint64{so, sn, off, size} {
		binary.LittleEndian.PutUint64(entry[i*8:], v)
	}
	checksum, err := b.d.compactIndexChecksum(entry[:32], id)
	if err != nil {
		return err
	}
	copy(entry[32:], checksum[:])
	n, err := b.d.offsets.WriteAt(entry[:], compactHeaderBytes+int64(id)*compactIndexBytes)
	if err == nil && n != len(entry) {
		err = io.ErrShortWrite
	}
	b.amended = true
	return err
}

type compactProjection struct {
	Presence                                                          uint8
	User, From, To, CallID, Method, Codec, FromTag, ToTag, IMSI, IMEI string
	Status                                                            int
	IsRTP                                                             bool
	SequenceNum                                                       uint16
	SSRC                                                              uint32
	QueryName, QueryType                                              string
	QueryResponseTimeMs                                               int64
	AnswerPresent                                                     bool
	TTL                                                               uint32
	SNI, JA3                                                          string
	Host, Path, HTTPMethod                                            string
	StatusCode                                                        int
	ContentLength                                                     int64
}

func projectionOf(p types.PacketDisplay) compactProjection {
	r := compactProjection{}
	if v := p.VoIPData; v != nil {
		r.Presence |= 1
		r.User = v.User
		r.From = v.From
		r.To = v.To
		r.CallID = v.CallID
		r.Method = v.Method
		r.Codec = v.Codec
		r.FromTag = v.FromTag
		r.ToTag = v.ToTag
		r.IMSI = v.IMSI
		r.IMEI = v.IMEI
		r.Status = v.Status
		r.IsRTP = v.IsRTP
		r.SequenceNum = v.SequenceNum
		r.SSRC = v.SSRC
	}
	if v := p.DNSData; v != nil {
		r.Presence |= 2
		r.QueryName = v.QueryName
		r.QueryType = v.QueryType
		r.QueryResponseTimeMs = v.QueryResponseTimeMs
		if len(v.Answers) > 0 {
			r.AnswerPresent = true
			r.TTL = v.Answers[0].TTL
		}
	}
	if p.EmailData != nil {
		r.Presence |= 4
	}
	if v := p.TLSData; v != nil {
		r.Presence |= 8
		r.SNI = v.SNI
		r.JA3 = v.JA3Fingerprint
	}
	if v := p.HTTPData; v != nil {
		r.Presence |= 16
		r.Host = v.Host
		r.Path = v.Path
		r.HTTPMethod = v.Method
		r.StatusCode = v.StatusCode
		r.ContentLength = v.ContentLength
	}
	return r
}
func (r compactProjection) apply(p *types.PacketDisplay) {
	if r.Presence&1 != 0 {
		p.VoIPData = &types.VoIPMetadata{User: r.User, From: r.From, To: r.To, CallID: r.CallID, Method: r.Method, Codec: r.Codec, FromTag: r.FromTag, ToTag: r.ToTag, IMSI: r.IMSI, IMEI: r.IMEI, Status: r.Status, IsRTP: r.IsRTP, SequenceNum: r.SequenceNum, SSRC: r.SSRC}
	}
	if r.Presence&2 != 0 {
		p.DNSData = &types.DNSMetadata{QueryName: r.QueryName, QueryType: r.QueryType, QueryResponseTimeMs: r.QueryResponseTimeMs}
		if r.AnswerPresent {
			p.DNSData.Answers = []types.DNSAnswer{{TTL: r.TTL}}
		}
	}
	if r.Presence&4 != 0 {
		p.EmailData = &types.EmailMetadata{}
	}
	if r.Presence&8 != 0 {
		p.TLSData = &types.TLSMetadata{SNI: r.SNI, JA3Fingerprint: r.JA3}
	}
	if r.Presence&16 != 0 {
		p.HTTPData = &types.HTTPMetadata{Host: r.Host, Path: r.Path, Method: r.HTTPMethod, StatusCode: r.StatusCode, ContentLength: r.ContentLength}
	}
}

// Authenticate directory references and packet identity together with complete
// block headers. The headers contain payload hashes, so valid-looking header
// corruption cannot silently remap an ID to another row in the same block.
func (d *diskDataset) compactIndexChecksum(refs []byte, id PacketID) ([32]byte, error) {
	var input [8 + 32 + 72*2]byte
	binary.LittleEndian.PutUint64(input[:8], uint64(id))
	copy(input[8:40], refs)
	for i, f := range []*os.File{d.summaries, d.details} {
		off := binary.LittleEndian.Uint64(refs[i*16:])
		size := binary.LittleEndian.Uint64(refs[i*16+8:])
		if i == 1 && off == 0 && size == 0 {
			continue
		}
		if off < compactHeaderBytes || off > math.MaxInt64-72 || size < 72 || size-72 > d.storage.limits.MaxRecordBytes {
			return [32]byte{}, errors.New("compact invalid directory block reference")
		}
		target := input[40+i*72 : 40+(i+1)*72]
		kind := uint16(17)
		if i == 1 {
			kind = 20
		}
		if cached := d.storage.cached(cacheKey{dataset: d, id: PacketID(off), kind: kind}); len(cached) >= 72 {
			copy(target, cached[:72])
		} else if _, err := f.ReadAt(target, int64(off)); err != nil {
			return [32]byte{}, err
		}
	}
	return sha256.Sum256(input[:]), nil
}
