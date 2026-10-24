package offline

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestObservationDomainStorageRoundTrip(t *testing.T) {
	for _, compact := range []bool{false, true} {
		for _, domain := range []uint32{0, 7, ^uint32(0)} {
			for _, known := range []bool{false, true} {
				t.Run(fmt.Sprintf("compact-%t/domain-%d/known-%t", compact, domain, known), func(t *testing.T) {
					ctx := context.Background()
					var storage *Storage
					var builder *Builder
					var original Detail
					var provenance PacketProvenance
					if compact {
						storage, builder, original, provenance = compactReviewBuilder(t)
					} else {
						storage = newTestStorage(t)
						var err error
						builder, err = storage.NewBuilder(17, nil)
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, builder.Close()) })
						original.Packet = types.PacketDisplay{Protocol: "UDP", RawData: []byte{1, 2, 3}, Length: 3}
					}
					original.Packet.ObservationDomain = domain
					original.Packet.ObservationDomainKnown = known
					if compact {
						require.NoError(t, builder.AppendCompact(ctx, original, provenance))
					} else {
						require.NoError(t, builder.Append(ctx, original))
					}
					dataset, err := builder.Finish(ctx)
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, dataset.Close()) })
					disk := dataset.(*diskDataset)
					assertDomain := func(packet types.PacketDisplay) {
						t.Helper()
						require.Equal(t, domain, packet.ObservationDomain)
						require.Equal(t, known, packet.ObservationDomainKnown, "known domain zero must remain distinct from unknown")
					}
					for i := 0; i < 2; i++ {
						storage.discardDatasetCache(disk)
						got, err := dataset.Detail(ctx, Token{Dataset: 17}, 0)
						require.NoError(t, err)
						assertDomain(got.Packet)
						require.Equal(t, original.Packet.RawData, got.Packet.RawData)
						summary, held, err := disk.readSummary(ctx, 0)
						require.NoError(t, err)
						assertDomain(summary.DisplayFields())
						storage.releaseMemory(held)
					}
					query, err := AllPackets(ctx, dataset, Token{Dataset: 17, Query: 1})
					require.NoError(t, err)
					page, err := query.Page(ctx, PageRequest{Token: query.Token(), Limit: 1, MaxBytes: 16 << 10})
					require.NoError(t, err)
					require.Len(t, page.Rows, 1)
					assertDomain(page.Rows[0].DisplayFields())
					require.NoError(t, page.Close())
					require.NoError(t, query.Close())
					manifest, err := os.ReadFile(filepath.Join(disk.dir, "manifest"))
					require.NoError(t, err)
					var version struct {
						Version uint16
						Compact struct{ SchemaMajor, SchemaMinor uint16 }
					}
					require.NoError(t, json.Unmarshal(manifest, &version))
					if compact {
						require.EqualValues(t, 2, version.Version)
						require.EqualValues(t, 2, version.Compact.SchemaMajor)
						require.EqualValues(t, 5, version.Compact.SchemaMinor)
					} else {
						require.EqualValues(t, 6, version.Version)
					}
				})
			}
		}
	}
}

func TestCodecObservationDomainVersionRejection(t *testing.T) {
	original := Detail{ID: 7, Packet: types.PacketDisplay{ObservationDomainKnown: true}}
	var record, stream bytes.Buffer
	_, err := writeRecord(&record, recordKindDetail, original.ID, original, 1<<20)
	require.NoError(t, err)
	_, err = writeStreamHeader(&stream, recordKindDetail)
	require.NoError(t, err)
	require.EqualValues(t, 6, binary.LittleEndian.Uint16(record.Bytes()[4:6]))
	require.EqualValues(t, 6, binary.LittleEndian.Uint16(stream.Bytes()[8:10]))
	for _, version := range []uint16{0, 1, 2, 3, 4, 5, 7, 65535} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			encoded := bytes.Clone(record.Bytes())
			binary.LittleEndian.PutUint16(encoded[4:6], version)
			untouched := Detail{ID: 99, Packet: types.PacketDisplay{ObservationDomain: 23}}
			got := untouched
			_, err := readRecordAt(bytes.NewReader(encoded), 0, recordKindDetail, original.ID, 1<<20, &got)
			require.ErrorContains(t, err, "version")
			require.Equal(t, untouched, got, "unsupported versions must fail before decoding metadata")
			encoded = bytes.Clone(stream.Bytes())
			binary.LittleEndian.PutUint16(encoded[8:10], version)
			require.ErrorContains(t, readStreamHeader(bytes.NewReader(encoded), recordKindDetail), "version")
		})
	}
}
