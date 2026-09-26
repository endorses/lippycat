//go:build li && linux

package delivery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func BenchmarkHeadContainerDurabilityKernel(b *testing.B) {
	parent := os.Getenv("LC_LI_STORAGE_BENCH_DIR")
	if parent == "" {
		b.Skip("set LC_LI_STORAGE_BENCH_DIR for opt-in durable kernel measurement")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		b.Fatal(err)
	}
	if fs.Type != 0xef53 || fs.Bsize != 4096 || fs.Bavail*uint64(fs.Bsize) < 1<<30 {
		b.Fatal("head-container probe requires reviewed 4096-byte ext4 and 1 GiB free")
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
			initializationStart := time.Now()
			k, err := openContainerKernel(dir, key, true)
			if err != nil {
				b.Fatal(err)
			}
			initialization := time.Since(initializationStart).Seconds()
			defer func() {
				if k != nil {
					if err := k.close(); err != nil {
						b.Error(err)
					}
				}
			}()
			var latency, durable, ioTime calibrationHistogram
			publish := k.publish
			k.publish = func(stage, head, archive string, data []byte) (securestore.Outcome, error) {
				start := time.Now()
				out, err := publish(stage, head, archive, data)
				ioTime.add(time.Since(start))
				return out, err
			}
			usageBefore := k.usage.Stats()
			const batches = 40
			const accumulation = 10 * time.Millisecond
			exact := make([]time.Duration, 0, batches*count)
			callbacks := 0
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			heapStart, heapPeak := memory.HeapAlloc, memory.HeapAlloc
			rssPeak, err := calibrationRSS()
			if err != nil {
				b.Fatal(err)
			}
			start := time.Now()
			for batch := 0; batch < batches; batch++ {
				pdus, err := kernelProducts(count, uint64(batch*count/2))
				if err != nil {
					b.Fatal(err)
				}
				arrived := time.Now()
				time.Sleep(accumulation)
				commitStart := time.Now()
				within := 0
				out, err := k.commit(pdus, func(out securestore.Outcome, err error) {
					if out != securestore.Committed || err != nil {
						b.Errorf("container callback %v: %v", out, err)
						return
					}
					elapsed := time.Since(arrived.Add(time.Duration(within) * accumulation / time.Duration(count)))
					exact = append(exact, elapsed)
					latency.add(elapsed)
					within++
					callbacks++
				})
				durable.add(time.Since(commitStart))
				if err != nil || out != securestore.Committed {
					b.Fatalf("container commit %v: %v", out, err)
				}
				// These samples are after callbacks and are included only in wall time;
				// they do not establish an intracommit peak or a production memory gate.
				runtime.ReadMemStats(&memory)
				heapPeak = max(heapPeak, memory.HeapAlloc)
				rss, err := calibrationRSS()
				if err != nil {
					b.Fatal(err)
				}
				rssPeak = max(rssPeak, rss)
			}
			wall := time.Since(start).Seconds()
			usageAfter := k.usage.Stats()
			charged := k.retained
			allocated, files, err := calibrationAllocated(dir)
			if err != nil {
				b.Fatal(err)
			}
			if allocated > containerDiskBudget || charged > containerDiskBudget {
				b.Fatal("container artifact budget exceeded")
			}
			if err := k.close(); err != nil {
				b.Fatal(err)
			}
			k = nil
			recoveryStart := time.Now()
			reopened, err := openContainerKernel(dir, key, false)
			if err != nil {
				b.Fatal(err)
			}
			recovery := time.Since(recoveryStart).Seconds()
			if reopened.head.Revision != batches || reopened.head.LastID != uint64(batches*count) {
				b.Fatal("wrong recovered highwater")
			}
			if err := reopened.close(); err != nil {
				b.Fatal(err)
			}
			slices.Sort(exact)
			percentile := func(p int) float64 { return float64(exact[(len(exact)*p+99)/100-1]) / float64(time.Millisecond) }
			result := struct {
				Records, Batches, Callbacks                                                             int
				InitializationSeconds, WallSeconds, CopiesPerSecond, RecoverySeconds                    float64
				AllocatedBytes, ConservativeChargedBytes, DiskBudgetBytes, CodecScratchReservationBytes int64
				RetainedFiles                                                                           uint64
				HeapStartBytes, HeapSampledPeakBytes                                                    uint64
				RSSSampledPeakBytes                                                                     int64
				Callback, CommitIncludingUsageCryptoAndValidation, ExchangeArchiveIO                    calibrationLatency
				CallbackP50ExactMS, CallbackP99ExactMS                                                  float64
				UsageBefore, UsageAfter                                                                 securestore.UsageStats
			}{count, batches, callbacks, initialization, wall, float64(callbacks) / wall, recovery, allocated, charged, containerDiskBudget, containerScratchBytes, files, heapStart, heapPeak, rssPeak, latency.summary(), durable.summary(), ioTime.summary(), percentile(50), percentile(99), usageBefore, usageAfter}
			data, err := json.Marshal(result)
			if err != nil {
				b.Fatal(err)
			}
			b.Logf("HEAD_CONTAINER_KERNEL %s", data)
			b.ReportMetric(percentile(50), "callback-p50-ms-exact")
			b.ReportMetric(percentile(99), "callback-p99-ms-exact")
		})
	}
}
