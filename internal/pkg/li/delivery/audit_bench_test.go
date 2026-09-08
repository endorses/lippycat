//go:build li

package delivery

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// BenchmarkAuditOutageQueue measures encoded admission and owner-drain cost for
// 100k variable-size PDUs. It deliberately excludes network and encoding costs;
// those need a deployment-specific end-to-end throughput measurement.
func BenchmarkAuditOutageQueue(b *testing.B) {
	const count = 100000
	did := uuid.New()
	cfg := DefaultClientConfig()
	cfg.QueueSize = count
	cfg.X2QueueBytes = 256 << 20
	cfg.X3QueueBytes = 256 << 20
	cfg.MemoryBudgetBytes = 1 << 30
	xid := uuid.New()
	destinations := []uuid.UUID{did}
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = make([]byte, 256+i*128)
	}
	b.ReportAllocs()
	b.SetBytes(count * 704)
	for n := 0; n < b.N; n++ {
		c := NewClient(auditOfflineManager(did), cfg)
		require.NoError(b, c.Err())
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		for i := 0; i < count; i++ {
			require.NoError(b, c.SendX3(xid, destinations, payloads[i%len(payloads)]))
		}
		admission := time.Since(start)
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(admission.Nanoseconds())/count, "ns/admission")
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/count, "heap-B/PDU")
		if data, err := os.ReadFile("/proc/self/statm"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) > 1 {
				if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					rss := pages * int64(os.Getpagesize())
					b.ReportMetric(float64(rss), "RSS-B")
					require.LessOrEqual(b, rss, cfg.MemoryBudgetBytes)
				}
			}
		}
		q := c.getOrCreateQueue(did)
		start = time.Now()
		for item := q.claim(PDUTypeX3); item != nil; item = q.claim(PDUTypeX3) {
			require.True(b, q.pop(item))
			c.resolveDrop(q, item, "benchmark_drain")
		}
		b.ReportMetric(float64(count)/time.Since(start).Seconds(), "owner-drain-PDU/s")
		c.Stop()
	}
}

// BenchmarkAuditStartedExpiryOutage includes the active expiry owner and
// disconnected dispatch/backoff owner while filling queues with age enabled.
func BenchmarkAuditStartedExpiryOutage(b *testing.B) {
	for _, count := range []int{10000, 100000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			cfg := DefaultClientConfig()
			cfg.QueueSize = count
			cfg.X3MaxAge = time.Hour
			cfg.ShutdownTimeout = time.Nanosecond
			did, xid := uuid.New(), uuid.New()
			destinations := []uuid.UUID{did}
			payload := make([]byte, 512)
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				c := NewClient(auditOfflineManager(did), cfg)
				c.Start()
				started := time.Now()
				for index := 0; index < count; index++ {
					require.NoError(b, c.SendX3(xid, destinations, payload))
				}
				b.ReportMetric(float64(time.Since(started).Nanoseconds())/float64(count), "ns/admission")
				require.Equal(b, count, c.QueueDepth())
				c.Stop()
			}
		})
	}
}
