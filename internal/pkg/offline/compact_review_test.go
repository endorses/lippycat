package offline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestCompactReviewManifestAndNoPacketCopy(t *testing.T) {
	_, b, detail, provenance := compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	data, err := os.ReadFile(filepath.Join(d.dir, "manifest"))
	require.NoError(t, err)
	var manifest struct {
		Version  uint16
		Complete bool
		Compact  compactCompletion
	}
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.EqualValues(t, 2, manifest.Version)
	require.True(t, manifest.Complete)
	require.True(t, manifest.Compact.BaseComplete)
	require.True(t, manifest.Compact.AnalysisComplete)
	require.EqualValues(t, 1, manifest.Compact.AnalysisRevision)
	require.Len(t, manifest.Compact.FileSHA256, 3)
	for name, want := range manifest.Compact.FileSHA256 {
		data, err := os.ReadFile(filepath.Join(d.dir, name))
		require.NoError(t, err)
		digest := sha256.Sum256(data)
		require.Equal(t, want, hex.EncodeToString(digest[:]))
		require.False(t, bytes.Contains(data, detail.Packet.RawData), "ordinary effective packet bytes must stay in the source")
	}
	require.Len(t, manifest.Compact.Backings, 1)
	require.Equal(t, provenance.Locator.BackingID, manifest.Compact.Backings[0].ID)
	require.Empty(t, manifest.Compact.Backings[0].OwnedSHA256, "external source bytes are identified by their scan digest")
	require.NotEmpty(t, manifest.Compact.Backings[0].SourceSHA256)
}

func TestCompactReviewSourceMutationAfterCache(t *testing.T) {
	_, b, detail, provenance := compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	owned, err := d.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	info, err := os.Stat(detail.Source.Path)
	require.NoError(t, err)
	mutated := append([]byte(nil), detail.Packet.RawData...)
	mutated[0] ^= 0xff
	require.NoError(t, os.WriteFile(detail.Source.Path, mutated, 0600))
	require.NoError(t, os.Chtimes(detail.Source.Path, info.ModTime(), info.ModTime()))
	_, err = d.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.ErrorIs(t, err, ErrSourceChanged, "cached blocks must not bypass effective-byte validation")
	q, err := AllPackets(context.Background(), d, Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	visits := 0
	err = IterateRaw(context.Background(), q, func(RawRecord) error { visits++; return nil })
	require.ErrorIs(t, err, ErrSourceChanged)
	require.Zero(t, visits)
	require.Equal(t, detail.Packet.RawData, owned.Packet.RawData, "previously owned bytes survive source mutation")
}

func TestCompactReviewCorruptStorage(t *testing.T) {
	for _, mode := range []string{"version", "reserved", "block-checksum", "row-offset-overflow", "short-block", "short-directory"} {
		t.Run(mode, func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
			dataset, err := b.Finish(context.Background())
			require.NoError(t, err)
			d := dataset.(*diskDataset)
			t.Cleanup(func() { require.NoError(t, d.Close()) })
			file := d.summaries
			if mode == "row-offset-overflow" || mode == "short-directory" {
				file = d.offsets
			}
			f, err := os.OpenFile(file.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			switch mode {
			case "version":
				_, err = f.WriteAt([]byte{255, 255}, 8)
			case "reserved":
				_, err = f.WriteAt([]byte{1}, 24)
			case "block-checksum":
				_, err = f.WriteAt([]byte{255}, compactHeaderBytes+40)
			case "row-offset-overflow":
				var value [8]byte
				binary.LittleEndian.PutUint64(value[:], ^uint64(0))
				_, err = f.WriteAt(value[:], compactHeaderBytes)
			case "short-block", "short-directory":
				err = f.Truncate(compactHeaderBytes + 1)
			}
			require.NoError(t, err)
			require.NoError(t, f.Close())
			_, err = d.Detail(context.Background(), Token{Dataset: 17}, 0)
			require.Error(t, err)
			require.NoError(t, d.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestCompactReviewRegistryBoundsAndReferences(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	for i := 0; i < compactRegistryEntries+2; i++ {
		row := compactRow{Node: strings.Repeat("x", i+1), Device: "fixed"}
		before := row
		require.NoError(t, b.internCompactRow(context.Background(), &row))
		require.NoError(t, b.d.compact.resolveCompactRow(&row))
		require.Equal(t, before, row)
	}
	require.LessOrEqual(t, len(b.d.compact.registries.Labels), compactRegistryEntries)
	require.LessOrEqual(t, b.d.compact.registries.textBytes, uint64(compactLabelBytes))
	require.Error(t, b.d.compact.resolveCompactRow(&compactRow{NodeRef: ^uint32(0)}))
	require.Error(t, b.d.compact.resolveCompactRow(&compactRow{NodeRef: 1, Node: "conflicting inline value"}))
	require.Error(t, b.d.compact.resolveCompactRow(&compactRow{ContextRef: ^uint32(0)}))
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func compactReviewBuilder(t *testing.T) (*Storage, *Builder, Detail, PacketProvenance) {
	t.Helper()
	ctx := context.Background()
	s, registry, path := backingFixture(t)
	in, err := registry.Open(ctx, path, 0, BackingSource, false)
	require.NoError(t, err)
	require.NoError(t, in.Close())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	loc, err := registry.Locator(in.ID, 0, raw)
	require.NoError(t, err)
	b, err := s.NewCompactBuilder(17, []SourcePosition{{Path: path}}, registry, func(_ context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		p := summary.DisplayFields()
		p.RawData = raw
		return p, nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	stamp := time.Unix(1700000000, 123).UTC()
	d := Detail{Source: SourcePosition{Path: path}, CapturedLength: uint32(len(raw)), OriginalLength: uint32(len(raw)), Packet: types.PacketDisplay{Timestamp: stamp, Length: len(raw), LinkType: layers.LinkTypeEthernet, RawData: raw, Protocol: "UDP", Info: "exact searchable information", SrcPort: "", DstPort: "0"}}
	ci := gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(raw), Length: len(raw)}
	provenance := PacketProvenance{Locator: loc, SourcePath: path, OriginalCapture: ci, EffectiveCapture: ci, OriginalLinkType: layers.LinkTypeEthernet, EffectiveLinkType: layers.LinkTypeEthernet, Context: CaptureContext{Format: CaptureFormatPCAP, ByteOrder: CaptureLittleEndian, LinkType: uint32(layers.LinkTypeEthernet), Snaplen: 65535, TimestampResolutionBase: 10, TimestampResolutionExponent: 9}}
	return s, b, d, provenance
}

func TestCompactReviewAdmissionAndPoisoning(t *testing.T) {
	for _, mode := range []string{"disk", "oversized", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			ctx := context.Background()
			switch mode {
			case "disk":
				s.limits.DiskBytes = s.Resources().DiskBytes
			case "oversized":
				detail.Packet.Info = strings.Repeat("x", int(s.limits.MaxRecordBytes)+1)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			require.Error(t, b.AppendCompact(ctx, detail, provenance))
			require.Error(t, b.AppendCompact(context.Background(), detail, provenance))
			_, err := b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
			require.NoError(t, b.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestCompactReviewPageLimitAndCleanupRetry(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	q, err := AllPackets(context.Background(), d, Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	_, err = q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 1, MaxBytes: 64})
	require.Error(t, err, "an oversized first row must fail instead of returning an empty page")
	require.NoError(t, q.Close())
	original := d.dir
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	d.dir = filepath.Join(blocker, "child")
	require.Error(t, d.Close())
	require.NotZero(t, s.Resources().DiskBytes)
	d.dir = original
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
	require.Zero(t, s.Resources().PinnedBytes)
}
