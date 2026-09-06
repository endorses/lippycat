package offline

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackingScanIdentity(t *testing.T) {
	for _, policy := range []BackingPolicy{BackingSource, BackingSnapshot} {
		for _, compressed := range []bool{false, true} {
			t.Run(string(policy)+map[bool]string{false: "plain", true: "gzip"}[compressed], func(t *testing.T) {
				_, r, path := backingFixture(t)
				original := []byte("original packet content")
				if compressed {
					var out bytes.Buffer
					z := gzip.NewWriter(&out)
					_, err := z.Write(original)
					require.NoError(t, err)
					require.NoError(t, z.Close())
					original = out.Bytes()
					require.NoError(t, os.WriteFile(path, original, 0600))
				}
				input, err := r.OpenScan(context.Background(), path, 0, policy, false)
				require.NoError(t, err)
				defer func() { require.NoError(t, input.Close()) }()
				if policy == BackingSource && !compressed {
					_, err = r.Identity(input.ID)
					require.ErrorContains(t, err, "incomplete")
					require.Zero(t, input.scan.bytes)
				}
				derived, err := r.AppendDerived(context.Background(), 0, []byte("derived"))
				require.NoError(t, err)
				data, err := io.ReadAll(input.Reader)
				require.NoError(t, err)
				require.Equal(t, "original packet content", string(data))
				require.NoError(t, input.FinishScan(context.Background()))
				identity, err := r.Identity(input.ID)
				require.NoError(t, err)
				require.Equal(t, sha256.Sum256(original), identity.Digest)
				derivedID, err := r.Identity(derived.BackingID)
				require.NoError(t, err)
				require.Equal(t, identity, derivedID)
			})
		}
	}
}

func TestBackingScanCancellationAndTrailingBytes(t *testing.T) {
	_, r, path := backingFixture(t)
	input, err := r.OpenScan(context.Background(), path, 0, BackingSource, false)
	require.NoError(t, err)
	defer func() { require.NoError(t, input.Close()) }()
	prefix := make([]byte, 3)
	_, err = io.ReadFull(input.Reader, prefix)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, input.FinishScan(ctx), context.Canceled)
	_, err = r.Identity(input.ID)
	require.Error(t, err)
	require.NoError(t, input.FinishScan(context.Background()))
	identity, err := r.Identity(input.ID)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte("original packet content")), identity.Digest)
}

func TestBackingBatchBoundedOwnership(t *testing.T) {
	_, r, path := backingFixture(t)
	input, err := r.Open(context.Background(), path, 0, BackingSource, false)
	require.NoError(t, err)
	require.NoError(t, input.Close())
	a, err := r.Locator(input.ID, 0, []byte("original"))
	require.NoError(t, err)
	b, err := r.Locator(input.ID, 9, []byte("packet"))
	require.NoError(t, err)
	for _, limit := range []uint64{14, 15} {
		lease, packets, err := r.ReadBatch(context.Background(), []Locator{a, b}, limit)
		require.NoError(t, err)
		require.Equal(t, [][]byte{[]byte("original"), []byte("packet")}, packets)
		require.Len(t, lease.Bytes, int(limit))
		require.NoError(t, lease.Close())
	}
	_, _, err = r.ReadBatch(context.Background(), []Locator{a, b}, 13)
	require.ErrorContains(t, err, "byte limit")
	b.Digest[0] ^= 1
	_, _, err = r.ReadBatch(context.Background(), []Locator{a, b}, 15)
	require.ErrorIs(t, err, ErrSourceChanged)
}
