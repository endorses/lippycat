//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func segmentTestKernel(t *testing.T) (string, string, *segmentKernel) {
	t.Helper()
	root, key, err := newKernelDirectory(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "journal")
	k, err := openSegmentKernel(dir, key, true)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, k.close()) })
	return dir, key, k
}

func segmentTestWrite(t *testing.T, dir string, offset int64, data []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "segment.lsg"), os.O_WRONLY, 0)
	require.NoError(t, err)
	n, err := f.WriteAt(data, offset)
	require.NoError(t, err)
	require.Len(t, data, n)
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())
}

func segmentTestCommit(t *testing.T, k *segmentKernel, count int, ordinal uint64) {
	t.Helper()
	pdus, err := kernelProducts(count, ordinal)
	require.NoError(t, err)
	callbacks := 0
	out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
		callbacks++
		require.NoError(t, err)
		require.Equal(t, securestore.Committed, out)
	})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	require.Equal(t, count, callbacks)
}

func TestSegmentKernelBootstrapAndRecovery(t *testing.T) {
	dir, key, k := segmentTestKernel(t)
	require.EqualValues(t, 0, k.heads[0].Generation)
	require.EqualValues(t, 1, k.heads[1].Generation)
	require.EqualValues(t, 1, k.active)
	require.Equal(t, sha256.Sum256(k.slots[0]), k.heads[1].Previous)
	require.GreaterOrEqual(t, k.file.AllocatedBytes(), int64(segmentSize))
	require.LessOrEqual(t, k.file.AllocatedBytes(), int64(64<<20))
	for i := range 3 {
		segmentTestCommit(t, k, 2, uint64(i*2))
		require.NoError(t, k.recoverSegment())
	}
	want := k.head
	require.EqualValues(t, 3, want.Revision)
	require.EqualValues(t, 6, want.LastID)
	require.NoError(t, k.close())
	reopened, err := openSegmentKernel(dir, key, false)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.close()) }()
	require.Equal(t, want, reopened.head)
	segmentTestCommit(t, reopened, 2, 6)
	require.EqualValues(t, 8, reopened.head.LastID)
}

func TestSegmentKernelCallbacksAndFaultStop(t *testing.T) {
	for _, stage := range []string{"success", "data-only", "head-torn", "uncertain-after-sync", "committed-cleanup"} {
		t.Run(stage, func(t *testing.T) {
			dir, key, k := segmentTestKernel(t)
			pdus, err := kernelProducts(2, 0)
			require.NoError(t, err)
			injected := errors.New("synthetic segment boundary failure")
			callbacks, publications := 0, 0
			publish := k.publish
			k.publish = func(data, head []byte) (securestore.Outcome, error) {
				publications++
				require.Zero(t, callbacks, "no callback before durability result")
				if stage == "data-only" || stage == "head-torn" {
					segmentTestWrite(t, dir, segmentDataStart, data[:128])
					if stage == "data-only" {
						return securestore.NotCommitted, injected
					}
					segmentTestWrite(t, dir, segmentBlock, head[:128])
					return securestore.Uncertain, injected
				}
				out, err := publish(data, head)
				require.NoError(t, err)
				if stage == "uncertain-after-sync" {
					return securestore.Uncertain, injected
				}
				if stage == "committed-cleanup" {
					return securestore.Committed, injected
				}
				return out, err
			}
			want := securestore.Committed
			if stage == "data-only" {
				want = securestore.NotCommitted
			}
			if stage == "head-torn" || stage == "uncertain-after-sync" {
				want = securestore.Uncertain
			}
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				require.Equal(t, want, out)
				if stage == "success" {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, injected)
					require.Equal(t, want, securestore.OutcomeOf(err))
				}
			})
			require.Equal(t, want, out)
			require.Equal(t, 2, callbacks)
			if stage != "success" {
				require.Error(t, err)
				if want == securestore.Committed {
					require.EqualValues(t, 1, k.head.Revision)
					require.EqualValues(t, 2, k.head.LastID)
				}
				out, err = k.commit(pdus, func(out securestore.Outcome, err error) {
					callbacks++
					require.Equal(t, securestore.NotCommitted, out)
					require.Error(t, err)
					require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
				})
				require.Error(t, err)
				require.Equal(t, securestore.NotCommitted, out)
				require.Equal(t, 4, callbacks)
				require.Equal(t, 1, publications, "faulted owner cannot publish a second attempt")
			}
			require.NoError(t, k.close())
			reopened, err := openSegmentKernel(dir, key, false)
			if stage == "data-only" || stage == "head-torn" {
				require.Error(t, err)
				require.Nil(t, reopened)
				var tail *segmentTailError
				if stage == "data-only" {
					require.ErrorAs(t, err, &tail)
				} else {
					require.False(t, errors.As(err, &tail), "invalid peer must not be discarded as a tail")
				}
			} else {
				require.NoError(t, err)
				require.EqualValues(t, 1, reopened.head.Revision)
				require.EqualValues(t, 2, reopened.head.LastID)
				require.NoError(t, reopened.close())
			}
		})
	}
}

func segmentTestReseal(t *testing.T, k *segmentKernel, raw []byte, change func([]byte)) []byte {
	t.Helper()
	changed := bytes.Clone(raw)
	n := binary.BigEndian.Uint32(changed[8:12])
	p, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), changed[16:16+n], segmentHeadPayload)
	require.NoError(t, err)
	change(p)
	sealed, err := k.writer.Seal(securestore.JournalState, k.binding("journal-state"), p)
	require.NoError(t, err)
	require.EqualValues(t, n, len(sealed))
	copy(changed[16:], sealed)
	return changed
}

func TestSegmentKernelAuthenticatedHeadAndPairBounds(t *testing.T) {
	_, _, k := segmentTestKernel(t)
	root := bytes.Clone(k.slots[0])
	segmentTestCommit(t, k, 2, 0)
	product := bytes.Clone(k.slots[k.active])
	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"magic", 0, 0}, {"version", 5, 2}, {"kind", 6, 2}, {"reserved", 7, 1}, {"copied-prefix", 8, 0},
		{"store", 24, 99}, {"segment", 40, 99}, {"header-digest", 56, 99},
		{"generation-overflow", 88, 255}, {"generation-parity", 95, 3},
		{"cursor-overflow", 128, 255}, {"cursor-unaligned", 135, 1},
		{"offset-overflow", 136, 255}, {"length-overflow", 144, 255},
		{"transactions-overflow", 148, 255}, {"id-overflow", 200, 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := segmentTestReseal(t, k, product, func(p []byte) {
				if tc.value == 99 {
					p[tc.offset] ^= 1
				} else {
					p[tc.offset] = tc.value
				}
			})
			_, err := k.decodeSlot(changed, 0)
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"short", product[:segmentBlock-1]}, {"zero", make([]byte, segmentBlock)},
		{"future", func() []byte { b := bytes.Clone(product); b[4] = 2; return b }()},
		{"envelope-overflow", func() []byte { b := bytes.Clone(product); binary.BigEndian.PutUint32(b[8:12], ^uint32(0)); return b }()},
		{"padding", func() []byte { b := bytes.Clone(product); b[len(b)-1] = 1; return b }()},
		{"halfslot", func() []byte { b := bytes.Clone(product); clear(b[segmentBlock/2:]); clear(b[100:200]); return b }()},
	} {
		t.Run(tc.name, func(t *testing.T) { _, err := k.decodeSlot(tc.raw, 0); require.Error(t, err) })
	}
	for _, offset := range []int{96, 128, 136, 144, 148, 152, 168, 200} {
		changed := segmentTestReseal(t, k, root, func(p []byte) { p[offset] ^= 1 })
		_, err := k.decodeSlot(changed, 0)
		require.Error(t, err, "invalid root offset %d", offset)
	}
	for _, tc := range []struct {
		name string
		raw  [2][]byte
	}{
		{"valid", k.slots},
		{"zero-peer", [2][]byte{k.slots[0], make([]byte, segmentBlock)}},
		{"swapped", [2][]byte{k.slots[1], k.slots[0]}},
		{"wrong-predecessor", [2][]byte{segmentTestReseal(t, k, k.slots[0], func(p []byte) { p[96] ^= 1 }), k.slots[1]}},
		{"changed-controls", [2][]byte{segmentTestReseal(t, k, k.slots[0], func(p []byte) { p[224] ^= 1 }), k.slots[1]}},
		{"changed-call", [2][]byte{segmentTestReseal(t, k, k.slots[0], func(p []byte) { p[208] ^= 1 }), k.slots[1]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := k.decodePair(tc.raw)
			if tc.name == "valid" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSegmentKernelPurposeBindingHeaderAndGeneration(t *testing.T) {
	_, _, k := segmentTestKernel(t)
	segmentTestCommit(t, k, 2, 0)
	for _, tc := range []struct {
		name    string
		purpose securestore.Purpose
		object  string
	}{
		{"purpose", securestore.X3Product, "journal-state"},
		{"object", securestore.JournalState, "journal-statu"},
	} {
		raw := bytes.Clone(k.slots[k.active])
		n := binary.BigEndian.Uint32(raw[8:12])
		p, err := k.keys.Open(securestore.JournalState, k.binding("journal-state"), raw[16:16+n], segmentHeadPayload)
		require.NoError(t, err)
		sealed, err := k.writer.Seal(tc.purpose, k.binding(tc.object), p)
		require.NoError(t, err)
		require.EqualValues(t, n, len(sealed))
		copy(raw[16:], sealed)
		_, err = k.decodeSlot(raw, k.active)
		require.Error(t, err, tc.name)
	}
	header := k.header
	for _, offset := range []int{0, 4, 5, 6, 24, 32, 36, 40, 44, 48, 52, 56, 60, segmentBlock - 1} {
		changed := header
		changed[offset] ^= 1
		require.Error(t, k.validateHeader(changed[:]), "header offset %d", offset)
	}
	for _, generation := range []uint64{0, 1, 4, ^uint64(0)} {
		hi := k.heads[k.active]
		hi.Generation = generation
		hi.Transactions = uint32(generation - 1)
		raw := k.slots
		var err error
		raw[k.active], err = k.encodeSlot(hi)
		require.NoError(t, err)
		_, _, err = k.decodePair(raw)
		require.Error(t, err, "generation %d", generation)
	}
}

func TestSegmentKernelUsageFailureCannotMutateOrPublish(t *testing.T) {
	_, _, k := segmentTestKernel(t)
	before := k.slots
	stats := k.usage.Stats()
	require.NoError(t, k.usage.Close())
	pdus, err := kernelProducts(2, 0)
	require.NoError(t, err)
	k.publish = func([]byte, []byte) (securestore.Outcome, error) {
		t.Fatal("failed reservation reached publication")
		return securestore.Uncertain, nil
	}
	callbacks := 0
	out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
		callbacks++
		require.Equal(t, securestore.NotCommitted, out)
		require.ErrorIs(t, err, securestore.ErrUsageFault)
	})
	require.Equal(t, securestore.NotCommitted, out)
	require.Error(t, err)
	require.Equal(t, 2, callbacks)
	raw, _, _, err := k.readAuthority()
	require.NoError(t, err)
	require.Equal(t, before, raw)
	require.Equal(t, stats.Invocations, k.usage.Stats().Invocations)
	require.Equal(t, stats.Blocks, k.usage.Stats().Blocks)
}

func TestSegmentKernelSerializesConcurrentPreparations(t *testing.T) {
	_, _, k := segmentTestKernel(t)
	pdus, err := kernelProducts(2, 0)
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			callbacks := 0
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				if out != securestore.Committed || err != nil {
					t.Error("unexpected concurrent callback", out, err)
				}
			})
			if callbacks != 2 || out != securestore.Committed {
				t.Error("concurrent callback count/outcome", callbacks, out)
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	require.EqualValues(t, 8, k.head.Revision)
	require.EqualValues(t, 16, k.head.LastID)
	require.NoError(t, k.recoverSegment())
}

func TestSegmentKernelPDUPreflightBeforeDecode(t *testing.T) {
	for _, scenario := range []string{"large-header", "crossing-tlv"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, k := segmentTestKernel(t)
			pdus, err := kernelProducts(2, 0)
			require.NoError(t, err)
			var pdu x2x3.PDU
			require.NoError(t, pdu.UnmarshalBinary(pdus[0]))
			if scenario == "large-header" {
				pdu.AddAttribute(x2x3.TLVAttribute{Type: 42, Value: make([]byte, 4096)})
				pdus[0], err = pdu.MarshalBinary()
				require.NoError(t, err)
			} else {
				pdus[0] = bytes.Clone(pdus[0])
				binary.BigEndian.PutUint32(pdus[0][4:8], x2x3.HeaderMinSize+3)
				binary.BigEndian.PutUint32(pdus[0][8:12], uint32(len(pdus[0])-x2x3.HeaderMinSize-3))
			}
			before := k.usage.Stats()
			_, _, err = k.encodeBatch(pdus)
			require.ErrorIs(t, err, errSegmentPDU)
			require.Equal(t, before.Invocations, k.usage.Stats().Invocations, "preflight rejects before encryption")
			// Forge fully authenticated selected bytes using the unchanged legacy
			// benchmark codec, then require the segment reader's earlier guard.
			k.preflightPDU = nil
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, out)
			})
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			k.preflightPDU = segmentPDUPreflight
			require.ErrorIs(t, k.recoverSegment(), errSegmentPDU)
		})
	}
	maxHeader := make([]byte, segmentMaxPDUHeader)
	binary.BigEndian.PutUint32(maxHeader[4:8], segmentMaxPDUHeader)
	require.NoError(t, segmentPDUPreflight(maxHeader), "1,014 empty TLVs are bounded before decoding")
	for _, offset := range []int{4, 8} {
		changed := bytes.Clone(maxHeader)
		binary.BigEndian.PutUint32(changed[offset:offset+4], ^uint32(0))
		require.ErrorIs(t, segmentPDUPreflight(changed), errSegmentPDU)
	}
	require.ErrorIs(t, segmentPDUPreflight(append(maxHeader, 0)), errSegmentPDU)
}

func TestSegmentKernelAuthenticatesLowerBoundary(t *testing.T) {
	dir, _, k := segmentTestKernel(t)
	segmentTestCommit(t, k, 2, 0)
	segmentTestCommit(t, k, 2, 2)
	original := k.slots
	for _, field := range []string{"tip", "digest", "highwater"} {
		t.Run(field, func(t *testing.T) {
			low := k.heads[k.active^1]
			switch field {
			case "tip":
				low.Tip[0] ^= 1
			case "digest":
				low.Digest[0] ^= 1
			case "highwater":
				low.LastID--
			}
			lo, err := k.encodeSlot(low)
			require.NoError(t, err)
			hi := k.heads[k.active]
			hi.Previous = sha256.Sum256(lo)
			high, err := k.encodeSlot(hi)
			require.NoError(t, err)
			raw := original
			raw[k.active^1] = lo
			raw[k.active] = high
			_, _, err = k.decodePair(raw)
			require.NoError(t, err, "pair alone is insufficient proof")
			for i, b := range raw {
				segmentTestWrite(t, dir, int64(i+1)*segmentBlock, b)
			}
			err = k.recoverSegment()
			require.ErrorContains(t, err, "lower head selected boundary")
			for i, b := range original {
				segmentTestWrite(t, dir, int64(i+1)*segmentBlock, b)
			}
		})
	}
	require.NoError(t, k.recoverSegment())
}

func TestSegmentKernelSelectedDataAndTailNeverFallback(t *testing.T) {
	dir, _, k := segmentTestKernel(t)
	segmentTestCommit(t, k, 2, 0)
	selected := k.heads[k.active]
	for _, offset := range []uint64{segmentDataStart, segmentDataStart + 24, segmentDataStart + 32, segmentDataStart + 40, segmentDataStart + uint64(selected.LastLength) - 1, segmentDataStart + uint64(selected.LastLength)} {
		old := make([]byte, 1)
		require.NoError(t, k.file.ReadAt(old, int64(offset)))
		segmentTestWrite(t, dir, int64(offset), []byte{old[0] ^ 1})
		err := k.recoverSegment()
		require.Error(t, err)
		var tail *segmentTailError
		require.False(t, errors.As(err, &tail), "selected corruption cannot become an unselected tail")
		segmentTestWrite(t, dir, int64(offset), old)
	}
	for _, tc := range []struct {
		name  string
		delta uint64
		tail  bool
	}{
		{"first", 0, true}, {"attempt-last", kernelMaxFile - 1, true}, {"beyond-attempt", kernelMaxFile, false}, {"file-last", segmentSize - selected.Cursor - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offset := selected.Cursor + tc.delta
			segmentTestWrite(t, dir, int64(offset), []byte{0x55})
			err := k.recoverSegment()
			require.Error(t, err)
			var tail *segmentTailError
			require.Equal(t, tc.tail, errors.As(err, &tail))
			got := make([]byte, 1)
			require.NoError(t, k.file.ReadAt(got, int64(offset)))
			require.Equal(t, byte(0x55), got[0], "classification must not mutate tail")
			segmentTestWrite(t, dir, int64(offset), []byte{0})
		})
	}
	peer := k.active ^ 1
	segmentTestWrite(t, dir, int64(peer+1)*segmentBlock, make([]byte, segmentBlock))
	require.Error(t, k.recoverSegment(), "erased peer cannot downgrade a valid higher head")
	segmentTestWrite(t, dir, int64(peer+1)*segmentBlock, k.slots[peer])
	require.NoError(t, k.recoverSegment())
}

func TestSegmentKernelDirtyTailReopenAndInventory(t *testing.T) {
	for _, scenario := range []string{"bootstrap-tail", "committed-tail", "init-stage", "unknown", "missing-control"} {
		t.Run(scenario, func(t *testing.T) {
			dir, key, k := segmentTestKernel(t)
			if scenario == "committed-tail" {
				segmentTestCommit(t, k, 2, 0)
			}
			cursor := k.heads[k.active].Cursor
			if scenario == "bootstrap-tail" || scenario == "committed-tail" {
				segmentTestWrite(t, dir, int64(cursor), []byte{0x44})
			}
			if scenario == "init-stage" || scenario == "unknown" {
				name := "unknown"
				if scenario == "init-stage" {
					name = ".lsg-init-00112233445566778899aabbccddeeff.tmp"
				}
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("synthetic evidence"), 0600))
			}
			if scenario == "missing-control" {
				require.NoError(t, os.Remove(filepath.Join(dir, "control-0")))
			}
			require.NoError(t, k.close())
			before, err := os.ReadDir(dir)
			require.NoError(t, err)
			for range 2 {
				reopened, err := openSegmentKernel(dir, key, false)
				require.Error(t, err)
				require.Nil(t, reopened)
				var tail *segmentTailError
				require.Equal(t, scenario == "bootstrap-tail" || scenario == "committed-tail", errors.As(err, &tail))
				after, e := os.ReadDir(dir)
				require.NoError(t, e)
				require.Equal(t, before, after, "reopening must preserve evidence and not reconcile")
			}
		})
	}
}

func TestSegmentKernelAdmissionBoundsBeforePublication(t *testing.T) {
	for _, scenario := range []string{"empty", "count", "bytes", "transactions", "capacity"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, k := segmentTestKernel(t)
			pdus, err := kernelProducts(2, 0)
			require.NoError(t, err)
			switch scenario {
			case "empty":
				pdus = nil
			case "count":
				pdus = make([][]byte, 4096)
			case "bytes":
				pdus = [][]byte{make([]byte, kernelMaxPlain+1)}
			case "transactions":
				k.heads[k.active].Transactions = 40
			case "capacity":
				k.heads[k.active].Cursor = segmentSize
			}
			k.publish = func([]byte, []byte) (securestore.Outcome, error) {
				t.Fatal("out-of-bound admission reached publisher")
				return securestore.Uncertain, nil
			}
			callbacks := 0
			out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
				callbacks++
				require.Equal(t, securestore.NotCommitted, out)
				require.Error(t, err)
			})
			require.Error(t, err)
			require.Equal(t, securestore.NotCommitted, out)
			require.Equal(t, len(pdus), callbacks)
		})
	}
}
