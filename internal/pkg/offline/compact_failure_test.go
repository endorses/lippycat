package offline

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactMalformedColumnsWithValidChecksum(t *testing.T) {
	for _, mode := range []string{"field", "wire", "flags", "count", "overlap", "overflow", "arena-block", "arena-flags", "arena-offset", "arena-length"} {
		t.Run(mode, func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
			dataset, err := b.Finish(context.Background())
			require.NoError(t, err)
			d := dataset.(*diskDataset)
			t.Cleanup(func() { require.NoError(t, d.Close()) })
			offsets, err := d.compactOffsets(0)
			require.NoError(t, err)
			f, err := os.OpenFile(d.summaries.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			block := make([]byte, offsets[1])
			_, err = f.ReadAt(block, int64(offsets[0]))
			require.NoError(t, err)
			payload := block[compactBlockHeaderBytes:]
			descriptor := payload[:24]
			message := "column descriptor"
			switch mode {
			case "field":
				binary.LittleEndian.PutUint16(descriptor, 0xffff)
			case "wire":
				descriptor[2] = 255
			case "flags":
				descriptor[3] = 1
			case "count":
				binary.LittleEndian.PutUint32(descriptor[4:], 4096)
			case "overlap":
				binary.LittleEndian.PutUint64(descriptor[8:], 0)
			case "overflow":
				binary.LittleEndian.PutUint64(descriptor[16:], ^uint64(0))
			default:
				message = "arena reference"
				columns := int(binary.LittleEndian.Uint16(block[20:]))
				var ref []byte
				for col := 0; col < columns; col++ {
					desc := payload[col*24 : (col+1)*24]
					if desc[2] == 7 {
						start := binary.LittleEndian.Uint64(desc[8:])
						ref = payload[start : start+16]
						break
					}
				}
				require.Len(t, ref, 16)
				switch mode {
				case "arena-block":
					binary.LittleEndian.PutUint32(ref, 1)
				case "arena-flags":
					binary.LittleEndian.PutUint32(ref[12:], 255)
				case "arena-offset":
					binary.LittleEndian.PutUint32(ref[4:], ^uint32(0))
				case "arena-length":
					binary.LittleEndian.PutUint32(ref[8:], ^uint32(0))
				}
			}
			checksum := sha256.Sum256(payload)
			copy(block[40:72], checksum[:])
			_, err = f.WriteAt(block, int64(offsets[0]))
			require.NoError(t, err)
			require.NoError(t, f.Close())
			// Keep directory authentication valid as well: these cases exercise
			// descriptor/reference validation beyond both integrity checks.
			directory, err := os.OpenFile(d.offsets.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			var entry [compactIndexBytes]byte
			_, err = directory.ReadAt(entry[:], compactHeaderBytes)
			require.NoError(t, err)
			checksum, err = d.compactIndexChecksum(entry[:32], 0)
			require.NoError(t, err)
			copy(entry[32:], checksum[:])
			_, err = directory.WriteAt(entry[:], compactHeaderBytes)
			require.NoError(t, err)
			require.NoError(t, directory.Close())
			_, err = d.Detail(context.Background(), Token{Dataset: 17}, 0)
			require.ErrorContains(t, err, message)
			require.NoError(t, d.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestCompactFailureNeverPublishes(t *testing.T) {
	for _, stage := range []string{"metadata-write", "buffered-flush", "sync", "readonly-reopen", "manifest-create", "manifest-write", "manifest-rename"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			s, b, detail, provenance := compactReviewBuilder(t)
			switch stage {
			case "metadata-write":
				full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if os.IsNotExist(err) {
					t.Skip("requires /dev/full")
				}
				require.NoError(t, err)
				original := b.d.details
				b.d.details = full
				detail.Packet.VoIPData = &types.VoIPMetadata{CallID: "retained-result"}
				err = b.AppendCompact(ctx, detail, provenance)
				// Buffered metadata may defer the OS failure until Finish.
				if err == nil {
					_, err = b.Finish(ctx)
				}
				require.ErrorIs(t, err, syscall.ENOSPC)
				b.d.details = original
				require.NoError(t, full.Close())
			case "buffered-flush":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
				if os.IsNotExist(err) {
					t.Skip("requires /dev/full")
				}
				require.NoError(t, err)
				original := b.d.summaries
				b.d.summaries = full
				_, err = b.Finish(ctx)
				require.ErrorIs(t, err, syscall.ENOSPC)
				b.d.summaries = original
				require.NoError(t, full.Close())
			case "sync":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				reader, writer, err := os.Pipe()
				require.NoError(t, err)
				original := b.d.details
				b.d.details = writer
				_, err = b.Finish(ctx)
				require.ErrorContains(t, err, "flush offline stream")
				b.d.details = original
				require.NoError(t, reader.Close())
				require.NoError(t, writer.Close())
			case "readonly-reopen":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				require.NoError(t, os.Remove(b.d.summaries.Name()))
				_, err := b.Finish(ctx)
				require.ErrorContains(t, err, "open completed offline stream")
			case "manifest-create":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				require.NoError(t, os.Mkdir(filepath.Join(b.d.dir, "manifest.tmp"), 0700))
				_, err := b.Finish(ctx)
				require.Error(t, err)
			case "manifest-write":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				require.NoError(t, b.flushCompact())
				s.limits.DiskBytes = s.Resources().DiskBytes
				_, err := b.Finish(ctx)
				require.ErrorContains(t, err, "disk budget exhausted")
			case "manifest-rename":
				require.NoError(t, b.AppendCompact(ctx, detail, provenance))
				require.NoError(t, os.Mkdir(filepath.Join(b.d.dir, "manifest"), 0700))
				_, err := b.Finish(ctx)
				require.Error(t, err)
			}
			require.Error(t, b.AppendCompact(ctx, detail, provenance), "failure must poison admission")
			dataset, err := b.Finish(ctx)
			require.Error(t, err)
			require.Nil(t, dataset)
			manifest, err := os.Stat(filepath.Join(b.d.dir, "manifest"))
			if stage == "manifest-rename" {
				require.NoError(t, err)
				require.True(t, manifest.IsDir())
			} else {
				require.True(t, os.IsNotExist(err))
			}
			require.NoError(t, b.Close())
			require.NoError(t, b.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}
