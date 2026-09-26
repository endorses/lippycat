//go:build li && linux

package delivery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func segmentOracleAdd(h hash.Hash, pdu []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(pdu)))
	_, _ = h.Write(length[:]) // hash.Hash.Write is specified never to fail.
	_, _ = h.Write(pdu)
}

// Compare recovered original bytes with a digest of the exact admitted inputs,
// independent of the per-record digests stored inside the authenticated index.
func segmentVerifyByteOracle(k *segmentKernel, want []byte) (int, error) {
	h := sha256.New()
	var records int
	var cursor uint64 = segmentDataStart
	for batch := uint32(0); batch < k.heads[k.active].Transactions; batch++ {
		prefix := make([]byte, kernelPrefixBytes)
		if err := k.file.ReadAt(prefix, int64(cursor)); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint64(prefix[32:40])
		if n < kernelPrefixBytes || n > kernelMaxFile {
			return 0, errors.New("kernel oracle frame bounds")
		}
		data := make([]byte, int(n))
		if err := k.file.ReadAt(data, int64(cursor)); err != nil {
			return 0, err
		}
		offset := uint64(kernelPrefixBytes) + uint64(binary.BigEndian.Uint32(prefix[28:32]))
		frames := binary.BigEndian.Uint32(prefix[24:28])
		if frames < 2 || frames > 4096 || offset > n {
			return 0, errors.New("kernel oracle index bounds")
		}
		for frame := uint32(1); frame < frames; frame++ {
			if n-offset < 4 {
				return 0, errors.New("kernel oracle product framing")
			}
			length := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
			if length > n-offset {
				return 0, errors.New("kernel oracle product bounds")
			}
			records++
			plain, err := k.keys.Open(securestore.X3Product, k.binding(fmt.Sprintf("%d", records)), data[offset:offset+length], kernelMaxPlain)
			if err != nil {
				return 0, err
			}
			if len(plain) < 12 || string(plain[:4]) != "LRB2" {
				return 0, errors.New("kernel oracle product schema")
			}
			metadata := uint64(binary.BigEndian.Uint32(plain[4:8]))
			pduBytes := uint64(binary.BigEndian.Uint32(plain[8:12]))
			if metadata > uint64(len(plain)-12) || pduBytes != uint64(len(plain)-12)-metadata {
				return 0, errors.New("kernel oracle plaintext bounds")
			}
			segmentOracleAdd(h, plain[12+metadata:])
			offset += length
		}
		if offset != n {
			return 0, errors.New("kernel oracle trailing bytes")
		}
		cursor += (n + segmentBlock - 1) / segmentBlock * segmentBlock
	}
	if cursor != k.heads[k.active].Cursor || uint64(records) != k.head.LastID || !slices.Equal(h.Sum(nil), want) {
		return 0, errors.New("kernel external encoded-byte oracle mismatch")
	}
	return records, nil
}

func BenchmarkSegmentDurabilityKernel(b *testing.B) {
	parent := os.Getenv("LC_LI_STORAGE_BENCH_DIR")
	if parent == "" {
		b.Skip("set LC_LI_STORAGE_BENCH_DIR for the approved opt-in segment probe")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		b.Fatal(err)
	}
	if fs.Type != 0xef53 || fs.Bsize != 4096 || fs.Bavail*uint64(fs.Bsize) < 1<<30 {
		b.Fatal("segment probe requires reviewed 4096-byte ext4 and 1 GiB free")
	}
	for _, count := range []int{2, 200} {
		b.Run(fmt.Sprintf("records=%d", count), func(b *testing.B) {
			if b.N != 1 {
				b.Fatal("use -benchtime=1x")
			}
			root, key, err := newKernelDirectory(parent)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(root); err != nil {
					b.Error(err)
				}
			}()
			dir := filepath.Join(root, "journal")
			setupStart := time.Now()
			k, err := openSegmentKernel(dir, key, true)
			if err != nil {
				b.Fatal(err)
			}
			setup := time.Since(setupStart).Seconds()
			defer func() {
				if k != nil {
					if err := k.close(); err != nil {
						b.Error(err)
					}
				}
			}()
			allocation := k.file.AllocatedBytes()
			actual, _, err := calibrationAllocated(dir)
			if err != nil {
				b.Fatal(err)
			}
			charged := actual + (4 << 20)
			if charged > segmentDiskBudget {
				b.Fatal("segment setup artifact budget exceeded")
			}
			var latency, durable, ioTime calibrationHistogram
			publish := k.publish
			dataSyncTransactions := 0
			k.publish = func(data, head []byte) (securestore.Outcome, error) {
				start := time.Now()
				out, err := publish(data, head)
				ioTime.add(time.Since(start))
				if out == securestore.Committed {
					dataSyncTransactions++
				}
				return out, err
			}
			usageBefore := k.usage.Stats()
			const batches = 40
			const accumulation = 10 * time.Millisecond
			exact := make([]time.Duration, 0, batches*count)
			oracle := sha256.New()
			callbacks := 0
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			heapStart, heapPeak := memory.HeapAlloc, memory.HeapAlloc
			mallocsStart, allocatedStart := memory.Mallocs, memory.TotalAlloc
			rssPeak, err := calibrationRSS()
			if err != nil {
				b.Fatal(err)
			}
			var cpuStart, cpuEnd syscall.Rusage
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuStart); err != nil {
				b.Fatal(err)
			}
			start := time.Now()
			for batch := 0; batch < batches; batch++ {
				pdus, err := kernelProducts(count, uint64(batch*count/2))
				if err != nil {
					b.Fatal(err)
				}
				for _, pdu := range pdus {
					segmentOracleAdd(oracle, pdu)
				}
				arrived := time.Now()
				time.Sleep(accumulation)
				commitStart := time.Now()
				within := 0
				out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
					if out != securestore.Committed || err != nil {
						b.Errorf("segment callback %v: %v", out, err)
						return
					}
					// Every PDU exists at this actual admission instant. Do not
					// subtract a modeled per-record arrival schedule.
					elapsed := time.Since(arrived)
					exact = append(exact, elapsed)
					latency.add(elapsed)
					within++
					callbacks++
				})
				durable.add(time.Since(commitStart))
				if err != nil || out != securestore.Committed || within != count {
					b.Fatalf("segment commit %v, callbacks=%d: %v", out, within, err)
				}
				runtime.ReadMemStats(&memory)
				heapPeak = max(heapPeak, memory.HeapAlloc)
				rss, err := calibrationRSS()
				if err != nil {
					b.Fatal(err)
				}
				rssPeak = max(rssPeak, rss)
			}
			wall := time.Since(start).Seconds()
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuEnd); err != nil {
				b.Fatal(err)
			}
			cpu := calibrationCPU(cpuEnd) - calibrationCPU(cpuStart)
			usageAfter := k.usage.Stats()
			actual, files, err := calibrationAllocated(dir)
			if err != nil {
				b.Fatal(err)
			}
			charged = actual + (4 << 20)
			if allocation != k.file.AllocatedBytes() || charged > segmentDiskBudget || dataSyncTransactions != batches {
				b.Fatal("segment allocation, budget or sync count invariant")
			}
			if err := k.close(); err != nil {
				b.Fatal(err)
			}
			k = nil
			recoveryStart := time.Now()
			reopened, err := openSegmentKernel(dir, key, false)
			if err != nil {
				b.Fatal(err)
			}
			recovery := time.Since(recoveryStart).Seconds()
			if reopened.head.Revision != batches || reopened.head.LastID != uint64(callbacks) {
				b.Fatal("segment recovered highwater differs")
			}
			oracleStart := time.Now()
			verified, oracleErr := segmentVerifyByteOracle(reopened, oracle.Sum(nil))
			oracleSeconds := time.Since(oracleStart).Seconds()
			if err := errors.Join(oracleErr, reopened.close()); err != nil {
				b.Fatal(err)
			}
			if verified != callbacks {
				b.Fatal("segment external oracle count differs")
			}
			slices.Sort(exact)
			percentile := func(p int) float64 { return float64(exact[(len(exact)*p+99)/100-1]) / float64(time.Millisecond) }
			result := struct {
				Records, Batches, Callbacks, SuccessfulDataSyncTransactions, OracleVerifiedRecords                                                                int
				InitializationIncludingBootstrapFsyncSeconds, WallSeconds, CopiesPerSecond, CPUSeconds, CPUSecondsPerCopy, RecoverySeconds, ExternalOracleSeconds float64
				AllocatedBytes, ConservativeChargedBytes, DiskBudgetBytes, SegmentAllocatedBytes, CodecScratchReservationBytes                                    int64
				RetainedFiles, HeapStartBytes, HeapSampledPeakBytes, Mallocs, TotalAllocatedBytes                                                                 uint64
				RSSSampledPeakBytes                                                                                                                               int64
				Callback, CommitIncludingUsageCryptoAndValidation, AppendHeadValidationAndDataSync                                                                calibrationLatency
				CallbackP50ExactMS, CallbackP99ExactMS, CallbackMaxExactMS                                                                                        float64
				UsageBefore, UsageAfter                                                                                                                           securestore.UsageStats
			}{count, batches, callbacks, dataSyncTransactions, verified, setup, wall, float64(callbacks) / wall, cpu, cpu / float64(callbacks), recovery, oracleSeconds, actual, charged, segmentDiskBudget, allocation, segmentScratchBytes, files, heapStart, heapPeak, memory.Mallocs - mallocsStart, memory.TotalAlloc - allocatedStart, rssPeak, latency.summary(), durable.summary(), ioTime.summary(), percentile(50), percentile(99), percentile(100), usageBefore, usageAfter}
			encoded, err := json.Marshal(result)
			if err != nil {
				b.Fatal(err)
			}
			b.Logf("SEGMENT_KERNEL %s", encoded)
			b.ReportMetric(percentile(50), "callback-p50-ms-exact")
			b.ReportMetric(percentile(99), "callback-p99-ms-exact")
		})
	}
}

func TestSegmentKernelExternalByteOracle(t *testing.T) {
	_, _, k := segmentTestKernel(t)
	oracle := sha256.New()
	pdus, err := kernelProducts(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pdu := range pdus {
		segmentOracleAdd(oracle, pdu)
	}
	out, err := k.commit(pdus, func(securestore.Outcome, error) {})
	if err != nil || out != securestore.Committed {
		t.Fatal(out, err)
	}
	verified, err := segmentVerifyByteOracle(k, oracle.Sum(nil))
	if err != nil || verified != 2 {
		t.Fatal(verified, err)
	}
	wrong := oracle.Sum(nil)
	wrong[0] ^= 1
	if _, err := segmentVerifyByteOracle(k, wrong); err == nil {
		t.Fatal("independent changed input oracle accepted")
	}
}
