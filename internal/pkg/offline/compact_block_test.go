package offline

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactTypedBlockIntegrity(t *testing.T) {
	cases := map[string]func([]byte){
		"column-flags": func(p []byte) { p[3] = 1 },
		"column-id":    func(p []byte) { binary.LittleEndian.PutUint16(p, 1000) },
		"column-type":  func(p []byte) { p[2] = 255 },
		"column-count": func(p []byte) { binary.LittleEndian.PutUint32(p[4:], 0) },
		"overlap":      func(p []byte) { binary.LittleEndian.PutUint64(p[24+8:], 0) },
		"reference-flags": func(p []byte) {
			for i := 0; i < 36; i++ {
				desc := p[i*24:]
				if desc[2] == 7 {
					off := binary.LittleEndian.Uint64(desc[8:])
					binary.LittleEndian.PutUint32(p[off+12:], 2)
					return
				}
			}
		},
		"reference-overflow": func(p []byte) {
			for i := 0; i < 36; i++ {
				desc := p[i*24:]
				if desc[2] == 7 {
					off := binary.LittleEndian.Uint64(desc[8:])
					binary.LittleEndian.PutUint32(p[off+8:], ^uint32(0))
					return
				}
			}
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			storage := newTestStorage(t)
			var decodes atomic.Int64
			dataset := compactRawDataset(t, storage, 1, &decodes)
			d := dataset.(*diskDataset)
			defer func() { require.NoError(t, d.Close()); require.NoError(t, storage.Close()) }()
			refs, err := d.compactOffsets(0)
			require.NoError(t, err)
			f, err := os.OpenFile(d.summaries.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			block := make([]byte, refs[1])
			_, err = f.ReadAt(block, int64(refs[0]))
			require.NoError(t, err)
			corrupt(block[72:])
			sum := sha256.Sum256(block[72:])
			copy(block[40:72], sum[:])
			_, err = f.WriteAt(block, int64(refs[0]))
			require.NoError(t, err)
			require.NoError(t, f.Close())
			directory, err := os.OpenFile(d.offsets.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			var entry [compactIndexBytes]byte
			_, err = directory.ReadAt(entry[:], compactHeaderBytes)
			require.NoError(t, err)
			checksum, err := d.compactIndexChecksum(entry[:32], 0)
			require.NoError(t, err)
			copy(entry[32:], checksum[:])
			_, err = directory.WriteAt(entry[:], compactHeaderBytes)
			require.NoError(t, err)
			require.NoError(t, directory.Close())
			before := storage.Resources().InFlightBytes
			_, err = d.Detail(context.Background(), Token{Dataset: 1}, 0)
			require.Error(t, err)
			require.Equal(t, before, storage.Resources().InFlightBytes)
		})
	}
}

func TestCompactDirectoryIntegrity(t *testing.T) {
	storage := newTestStorage(t)
	var decodes atomic.Int64
	dataset := compactRawDataset(t, storage, 1, &decodes)
	d := dataset.(*diskDataset)
	defer func() { require.NoError(t, d.Close()); require.NoError(t, storage.Close()) }()
	f, err := os.OpenFile(d.offsets.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{1}, compactHeaderBytes+16)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = d.Detail(context.Background(), Token{Dataset: 1}, 0)
	require.ErrorContains(t, err, "directory")
}

func TestCompactHeaderCannotRemapRows(t *testing.T) {
	storage := newTestStorage(t)
	var decodes atomic.Int64
	dataset := compactRawDataset(t, storage, 1, &decodes)
	d := dataset.(*diskDataset)
	defer func() { require.NoError(t, d.Close()); require.NoError(t, storage.Close()) }()
	refs, err := d.compactOffsets(1)
	require.NoError(t, err)
	f, err := os.OpenFile(d.summaries.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	// A payload checksum alone would accept this header and reinterpret row 0 as
	// packet 1. Directory authentication binds both the header and requested ID.
	var first [8]byte
	binary.LittleEndian.PutUint64(first[:], 1)
	_, err = f.WriteAt(first[:], int64(refs[0])+8)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = d.Detail(context.Background(), Token{Dataset: 1}, 1)
	require.ErrorContains(t, err, "directory checksum")
}
