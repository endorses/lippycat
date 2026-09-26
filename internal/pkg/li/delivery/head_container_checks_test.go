//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func testContainer(t *testing.T) (string, string, *containerKernel) {
	t.Helper()
	root, key, err := newKernelDirectory(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "journal")
	k, err := openContainerKernel(dir, key, true)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, k.close()); require.NoError(t, os.RemoveAll(root)) })
	return dir, key, k
}

func TestHeadContainerRootAndRoundTrip(t *testing.T) {
	dir, key, k := testContainer(t)
	data, err := k.dir.Read(".head", containerMaxBytes)
	require.NoError(t, err)
	require.Len(t, data, 381)
	root, batch, err := k.decodeContainer(data)
	require.NoError(t, err)
	require.Empty(t, batch)
	require.Equal(t, uint64(0), root.Head.Revision)
	require.Equal(t, sha256.Sum256(nil), root.BatchHash)
	_, err = openContainerKernel(dir, key, true)
	require.Error(t, err)
	for i := 0; i < 3; i++ {
		pdus, err := kernelProducts(2, uint64(i))
		require.NoError(t, err)
		calls := 0
		out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
			calls++
			require.Equal(t, securestore.Committed, out)
			require.NoError(t, err)
		})
		require.Equal(t, securestore.Committed, out)
		require.NoError(t, err)
		require.Equal(t, 2, calls)
	}
	require.NoError(t, k.close())
	reopened, err := openContainerKernel(dir, key, false)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.close()) }()
	require.Equal(t, uint64(3), reopened.head.Revision)
	require.Equal(t, uint64(6), reopened.head.LastID)
	require.Equal(t, k.selectedHash, reopened.selectedHash)
}

func TestHeadContainerCallbackOutcomes(t *testing.T) {
	for _, stage := range []string{"success", "candidate", "displaced", "uncertain", "committed-cleanup"} {
		t.Run(stage, func(t *testing.T) {
			dir, key, k := testContainer(t)
			publish := k.publish
			injected := errors.New("synthetic container publication failure")
			published := 0
			calls := 0
			k.publish = func(stageName, head, archive string, data []byte) (securestore.Outcome, error) {
				published++
				require.Zero(t, calls)
				if stage == "candidate" || stage == "displaced" {
					out, err := k.dir.Create(stageName, data)
					if err != nil {
						return out, err
					}
					if stage == "candidate" {
						return securestore.NotCommitted, injected
					}
					require.NoError(t, unix.Renameat2(unix.AT_FDCWD, filepath.Join(dir, stageName), unix.AT_FDCWD, filepath.Join(dir, head), unix.RENAME_EXCHANGE))
					return securestore.Uncertain, injected
				}
				out, err := publish(stageName, head, archive, data)
				if err == nil && stage == "uncertain" {
					return securestore.Uncertain, injected
				}
				if err == nil && stage == "committed-cleanup" {
					return securestore.Committed, injected
				}
				return out, err
			}
			want := securestore.Committed
			if stage == "candidate" {
				want = securestore.NotCommitted
			}
			if stage == "displaced" || stage == "uncertain" {
				want = securestore.Uncertain
			}
			pdus, err := kernelProducts(2, 0)
			require.NoError(t, err)
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				calls++
				require.Equal(t, want, out)
				require.Equal(t, stage == "success", err == nil)
			})
			require.Equal(t, want, out)
			require.Equal(t, 2, calls)
			require.Equal(t, stage == "success", err == nil)
			if stage != "success" {
				require.Equal(t, want, securestore.OutcomeOf(err))
				_, err = k.commit(pdus, func(out securestore.Outcome, err error) {
					require.Equal(t, securestore.NotCommitted, out)
					require.Error(t, err)
				})
				require.Error(t, err)
				require.Equal(t, 1, published)
			}
			require.NoError(t, k.close())
			reopened, err := openContainerKernel(dir, key, false)
			if stage == "candidate" || stage == "displaced" {
				var staged *containerStageError
				require.ErrorAs(t, err, &staged)
				expected := "unpublished candidate"
				if stage == "displaced" {
					expected = "displaced predecessor"
				}
				require.Equal(t, expected, staged.kind)
				matches, err := filepath.Glob(filepath.Join(dir, ".lch-stage-*"))
				require.NoError(t, err)
				require.Len(t, matches, 1)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(1), reopened.head.Revision)
				require.NoError(t, reopened.close())
			}
		})
	}
}

func TestHeadContainerAuthenticatedCodecBounds(t *testing.T) {
	_, _, k := testContainer(t)
	pdus, err := kernelProducts(2, 0)
	require.NoError(t, err)
	id, batch, err := k.encodeBatch(pdus)
	require.NoError(t, err)
	h := k.head
	h.Revision = 1
	h.LastID = 2
	candidate := kernelContainer{ID: id, Previous: k.selected.ID, PreviousHash: k.selectedHash, BatchHash: sha256.Sum256(batch), Head: h}
	data, err := k.encodeContainer(candidate, batch)
	require.NoError(t, err)
	_, _, err = k.decodeContainer(data)
	require.NoError(t, err)
	for _, offset := range []int{0, 4, 5, 6, 7, 8, 24, 28, 32, 40, 48, len(data) - 1} {
		changed := bytes.Clone(data)
		changed[offset] ^= 1
		_, _, err = k.decodeContainer(changed)
		require.Error(t, err, "byte %d", offset)
	}
	for _, length := range []int{0, 47, 48, len(data) - 1} {
		_, _, err = k.decodeContainer(data[:length])
		require.Error(t, err)
	}
	_, _, err = k.decodeContainer(append(bytes.Clone(data), 0))
	require.Error(t, err)
	_, _, err = k.decodeContainer(make([]byte, containerMaxBytes+1))
	require.Error(t, err)
	headStart := containerPrefixBytes + len(batch)
	plain, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), data[headStart:], containerHeadBytes)
	require.NoError(t, err)
	for _, mutation := range []string{"magic", "version", "reserved", "prefix", "store", "revision-overflow", "id-overflow", "self-predecessor", "zero-predecessor", "zero-call", "batch-digest", "root-confusion", "batch-length-overflow", "head-length-overflow"} {
		t.Run(mutation, func(t *testing.T) {
			changed := bytes.Clone(data)
			p := bytes.Clone(plain)
			switch mutation {
			case "magic":
				p[0] ^= 1
			case "version":
				p[5]++
			case "reserved":
				p[6] = 1
			case "prefix":
				p[8+8] ^= 1
			case "store":
				p[56] ^= 1
			case "revision-overflow":
				binary.BigEndian.PutUint64(p[72:80], ^uint64(0))
			case "id-overflow":
				binary.BigEndian.PutUint64(p[160:168], ^uint64(0))
			case "self-predecessor":
				copy(p[80:96], id[:])
			case "zero-predecessor":
				clear(p[80:96])
			case "zero-call":
				clear(p[168:184])
			case "batch-digest":
				p[128] ^= 1
			case "root-confusion":
				changed[6] = 0
				copy(p[8:56], changed[:48])
			case "batch-length-overflow":
				binary.BigEndian.PutUint32(changed[24:28], ^uint32(0))
				copy(p[8:56], changed[:48])
			case "head-length-overflow":
				binary.BigEndian.PutUint32(changed[28:32], ^uint32(0))
				copy(p[8:56], changed[:48])
			}
			sealed, err := k.writer.Seal(securestore.JournalState, k.binding("journal-state"), p)
			require.NoError(t, err)
			copy(changed[headStart:], sealed)
			_, _, err = k.decodeContainer(changed)
			require.Error(t, err)
		})
	}
	wrongPurpose, err := k.writer.Seal(securestore.JournalBatchIndex, k.binding("journal-state"), plain)
	require.NoError(t, err)
	changed := bytes.Clone(data)
	copy(changed[headStart:], wrongPurpose)
	_, _, err = k.decodeContainer(changed)
	require.Error(t, err)
	// Reach inner product authentication even with an authentic container digest.
	corruptBatch := bytes.Clone(batch)
	corruptBatch[len(corruptBatch)-1] ^= 1
	candidate.BatchHash = sha256.Sum256(corruptBatch)
	changed, err = k.encodeContainer(candidate, corruptBatch)
	require.NoError(t, err)
	decoded, embedded, err := k.decodeContainer(changed)
	require.NoError(t, err)
	_, _, _, err = k.readBatch(decoded.ID, decoded.Head.Revision, decoded.Head.LastID, embedded)
	require.Error(t, err)
}

func TestHeadContainerRecoveryFailsClosed(t *testing.T) {
	for _, mutation := range []string{"missing-predecessor", "corrupt-predecessor", "wrong-predecessor-hash", "changed-call", "orphan-archive", "partial-stage", "multiple-stages", "unknown-name", "wrong-archive-identity"} {
		t.Run(mutation, func(t *testing.T) {
			dir, key, k := testContainer(t)
			for i := 0; i < 2; i++ {
				pdus, err := kernelProducts(2, uint64(i))
				require.NoError(t, err)
				_, err = k.commit(pdus, func(securestore.Outcome, error) {})
				require.NoError(t, err)
			}
			switch mutation {
			case "missing-predecessor":
				_, err := k.dir.Remove(containerArchive(k.selected.Previous))
				require.NoError(t, err)
			case "corrupt-predecessor":
				name := containerArchive(k.selected.Previous)
				data, err := k.dir.Read(name, containerMaxBytes)
				require.NoError(t, err)
				data[len(data)-1] ^= 1
				_, err = k.dir.Replace(name, data)
				require.NoError(t, err)
			case "wrong-predecessor-hash", "changed-call":
				data, err := k.dir.Read(".head", containerMaxBytes)
				require.NoError(t, err)
				c, b, err := k.decodeContainer(data)
				require.NoError(t, err)
				if mutation == "changed-call" {
					c.Head.Call = uuid.New()
				} else {
					c.PreviousHash[0] ^= 1
				}
				data, err = k.encodeContainer(c, b)
				require.NoError(t, err)
				_, err = k.dir.Replace(".head", data)
				require.NoError(t, err)
			case "orphan-archive", "wrong-archive-identity":
				name := containerArchive(k.selected.Previous)
				data, err := k.dir.Read(name, containerMaxBytes)
				require.NoError(t, err)
				if mutation == "wrong-archive-identity" {
					_, err = k.dir.Remove(name)
					require.NoError(t, err)
				}
				_, err = k.dir.Create(containerArchive(uuid.New()), data)
				require.NoError(t, err)
			case "partial-stage", "multiple-stages":
				_, err := k.dir.Create(containerStage(uuid.New()), []byte("incomplete"))
				require.NoError(t, err)
				if mutation == "multiple-stages" {
					_, err = k.dir.Create(containerStage(uuid.New()), []byte("incomplete"))
					require.NoError(t, err)
				}
			case "unknown-name":
				_, err := k.dir.Create("unexpected", []byte("synthetic"))
				require.NoError(t, err)
			}
			before, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.NoError(t, k.close())
			reopened, err := openContainerKernel(dir, key, false)
			if reopened != nil {
				require.NoError(t, reopened.close())
			}
			require.Error(t, err)
			after, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Equal(t, len(before), len(after), "recovery must preserve evidence")
		})
	}
}

func TestHeadContainerAdmissionBudgetAndHighwater(t *testing.T) {
	for _, kind := range []string{"capacity", "revision", "record-id"} {
		t.Run(kind, func(t *testing.T) {
			_, _, k := testContainer(t)
			pdus, err := kernelProducts(2, 0)
			require.NoError(t, err)
			switch kind {
			case "capacity":
				k.retained = containerDiskBudget
			case "revision":
				k.head.Revision = ^uint64(0)
			case "record-id":
				k.head.LastID = ^uint64(0)
			}
			k.publish = func(string, string, string, []byte) (securestore.Outcome, error) {
				t.Fatal("invalid admission reached publication")
				return securestore.Committed, nil
			}
			callbacks := 0
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				require.Equal(t, securestore.NotCommitted, out)
				require.Error(t, err)
			})
			require.Error(t, err)
			require.Equal(t, securestore.NotCommitted, out)
			require.Equal(t, 2, callbacks)
		})
	}
}

func TestHeadContainerAuthenticatesCurrentHeadBeforeMutation(t *testing.T) {
	_, _, k := testContainer(t)
	old, err := k.dir.Read(".head", containerMaxBytes)
	require.NoError(t, err)
	old[len(old)-1] ^= 1
	_, err = k.dir.Replace(".head", old)
	require.NoError(t, err)
	k.publish = func(string, string, string, []byte) (securestore.Outcome, error) {
		t.Fatal("corrupted selected head reached exchange")
		return securestore.Committed, nil
	}
	pdus, err := kernelProducts(2, 0)
	require.NoError(t, err)
	out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
		require.Equal(t, securestore.NotCommitted, out)
		require.Error(t, err)
	})
	require.Equal(t, securestore.NotCommitted, out)
	require.ErrorContains(t, err, "changed")
}
