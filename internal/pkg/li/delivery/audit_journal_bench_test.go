//go:build li

package delivery

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// BenchmarkAuditJournalAdmissionAndSync measures the real client admission path
// through encrypted journal fsync on the benchmark filesystem. It does not
// measure packet capture/encoding, MDF transport, or physical-drive durability.
func BenchmarkAuditJournalAdmissionAndSync(b *testing.B) {
	const count = 2048
	b.ReportAllocs()
	for iteration := 0; iteration < b.N; iteration++ {
		b.StopTimer()
		root := b.TempDir()
		key := filepath.Join(root, "key")
		require.NoError(b, os.WriteFile(key, bytes.Repeat([]byte{42}, 32), 0600))
		cfg := DefaultClientConfig()
		cfg.QueueSize = count
		cfg.X2QueueBytes = 8 << 20
		cfg.X3QueueBytes = 8 << 20
		cfg.MemoryBudgetBytes = 1 << 30
		cfg.X2SpoolDir = filepath.Join(root, "journal")
		cfg.X2SpoolKeyFile = key
		cfg.X2SpoolMaxBytes = 64 << 20
		did, xid := uuid.New(), uuid.New()
		client := NewClient(auditOfflineManager(did), cfg)
		require.NoError(b, client.Err())
		b.Cleanup(client.Stop)
		payloads := make([][]byte, count)
		payloadBytes := 0
		for i := range payloads {
			pdu := x2x3.NewX2SIPPDU(xid, 1)
			pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, uint32(i)))
			pdu.Payload = make([]byte, 512*(i%8+1))
			var err error
			payloads[i], err = pdu.MarshalBinary()
			require.NoError(b, err)
			payloadBytes += len(payloads[i])
		}
		b.SetBytes(int64(payloadBytes))
		destinations := []uuid.UUID{did}
		admissions := make([]int64, count)
		b.StartTimer()
		start := time.Now()
		for i := 0; i < count; i++ {
			admitted := time.Now()
			err := client.SendX2WithMetadata(xid, destinations, payloads[i%len(payloads)], DeliveryMetadata{TaskGeneration: 1})
			admissions[i] = time.Since(admitted).Nanoseconds()
			require.NoError(b, err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			stats := client.JournalStats()
			if stats.Persisted == count && stats.Pending == 0 {
				break
			}
			require.True(b, time.Now().Before(deadline), "journal failed to sync: %+v", stats)
			time.Sleep(time.Millisecond)
		}
		synced := time.Since(start)
		b.StopTimer()
		sort.Slice(admissions, func(i, j int) bool { return admissions[i] < admissions[j] })
		b.ReportMetric(float64(admissions[count/2]), "admission-p50-ns")
		b.ReportMetric(float64(admissions[count*99/100]), "admission-p99-ns")
		b.ReportMetric(float64(payloadBytes)/synced.Seconds()/1e6, "encoded-sync-MB/s")
		b.ReportMetric(float64(count)/synced.Seconds(), "persisted-PDU/s")
		var diskBytes int64
		entries, err := os.ReadDir(cfg.X2SpoolDir)
		require.NoError(b, err)
		for _, entry := range entries {
			info, err := entry.Info()
			require.NoError(b, err)
			diskBytes += info.Size()
		}
		b.ReportMetric(float64(diskBytes), "journal-file-B")
		require.LessOrEqual(b, client.JournalStats().Bytes, cfg.X2SpoolMaxBytes)
		client.Stop()
		recovered := NewClient(auditOfflineManager(did), cfg)
		require.NoError(b, recovered.Err())
		require.Equal(b, count, recovered.JournalStats().Held)
		recovered.Stop()
		b.StartTimer()
	}
}
