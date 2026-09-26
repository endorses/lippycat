//go:build li && linux

package delivery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
)

// BenchmarkJournalStorageCalibration is an opt-in, paced protocol calibration,
// not X3 qualification. The current journal accepts X2 only, so it receives X2
// envelopes with exactly the encoded length of our synthetic X3 RTP PDUs. Real
// journal encryption, sequence checkpoints, usage reservations, fsync, reads and
// durable deletion are retained. Independent destination readers replace MDF
// transport; no packets, sockets, or operational interception data are used.
//
// LC_LI_STORAGE_BENCH_DIR must name an existing durable filesystem directory.
// Run with -benchtime=1x. Every sub-benchmark removes its own private directory.
func BenchmarkJournalStorageCalibration(b *testing.B) {
	parent := os.Getenv("LC_LI_STORAGE_BENCH_DIR")
	if parent == "" {
		b.Skip("set LC_LI_STORAGE_BENCH_DIR to opt into durable disk calibration")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		b.Fatal(err)
	}
	if fs.Type == 0x01021994 || fs.Type == 0x858458f6 { // tmpfs / ramfs
		b.Fatal("durable storage calibration does not accept tmpfs or ramfs")
	}
	if fs.Bavail*uint64(fs.Bsize) < 2<<30 || fs.Ffree < 262144 {
		b.Fatal("calibration requires at least 2 GiB and 262144 free inodes")
	}
	stopLarger := false
	for _, calls := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("calls=%d/copies=%d", calls, calls*200), func(b *testing.B) {
			if stopLarger {
				b.Skip("lower paced load already failed throughput/latency; select this sub-benchmark explicitly to override")
			}
			if b.N != 1 {
				b.Fatal("fixed-duration calibration requires -benchtime=1x")
			}
			result, err := runStorageCalibration(parent, calls)
			if err != nil {
				b.Fatal(err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				b.Fatal(err)
			}
			b.Logf("STORAGE_CALIBRATION %s", encoded)
			b.ReportMetric(float64(result.Phases[1].Durable)/result.Phases[1].Seconds, "healthy-durable-copies/s")
			b.ReportMetric(result.Phases[1].Callback.P99MS, "healthy-callback-p99-ms")
			b.ReportMetric(float64(result.Phases[1].Rejected), "healthy-rejected")
			healthy := result.Phases[1]
			stopLarger = float64(healthy.Durable)/healthy.Seconds < float64(calls*200)*0.99 || healthy.Callback.MaxMS > 1000 || healthy.Rejected != 0
		})
	}
}

const calibrationMaxRecords = 131072
const calibrationMaxBytes = int64(512 << 20)

var calibrationXID = uuid.MustParse("00000000-0000-4000-8000-000000000001")
var calibrationDIDs = [2]uuid.UUID{
	uuid.MustParse("00000000-0000-4000-8000-000000000002"),
	uuid.MustParse("00000000-0000-4000-8000-000000000003"),
}

// Buckets have 16 subdivisions per power of two in microseconds. Quantiles are
// conservative bucket upper bounds (at most 6.25% rounding); max is exact.
// This bounds measurement memory independently of offered load and soak length.
type calibrationHistogram struct {
	Buckets [1024]uint64
	Count   uint64
	Max     time.Duration
}

func (h *calibrationHistogram) add(d time.Duration) {
	us := uint64(max(1, (d+time.Microsecond-1)/time.Microsecond))
	exponent := bits.Len64(us) - 1
	base := uint64(1) << exponent
	sub := (us - base) * 16 / base
	h.Buckets[exponent*16+int(sub)]++
	h.Count++
	h.Max = max(h.Max, d)
}

func (h *calibrationHistogram) quantile(percent uint64) float64 {
	if h.Count == 0 {
		return 0
	}
	target, count := (h.Count*percent+99)/100, uint64(0)
	for index, n := range h.Buckets {
		count += n
		if count >= target {
			base := uint64(1) << (index / 16)
			upper := base + (uint64(index%16+1)*base+15)/16
			return float64(upper) / 1000
		}
	}
	return float64(h.Max) / float64(time.Millisecond)
}

type calibrationLatency struct {
	Count uint64  `json:"count"`
	P50MS float64 `json:"p50_ms_upper"`
	P99MS float64 `json:"p99_ms_upper"`
	MaxMS float64 `json:"max_ms"`
}

func (h *calibrationHistogram) summary() calibrationLatency {
	return calibrationLatency{h.Count, h.quantile(50), h.quantile(99), float64(h.Max) / float64(time.Millisecond)}
}

type calibrationPhase struct {
	Name         string             `json:"name"`
	Seconds      float64            `json:"seconds"`
	Offered      uint64             `json:"offered_copies"`
	Accepted     uint64             `json:"accepted_copies"`
	Rejected     uint64             `json:"rejected_copies"`
	Durable      uint64             `json:"durable_callbacks_in_window"`
	Read         uint64             `json:"authenticated_reads_in_window"`
	MediaBytes   uint64             `json:"offered_media_bytes"`
	EncodedBytes uint64             `json:"offered_encoded_bytes"`
	PendingAtEnd int                `json:"pending_at_end"`
	DiskAtEnd    int                `json:"persisted_at_end"`
	Admission    calibrationLatency `json:"admission"`
	Callback     calibrationLatency `json:"callback_by_admission_phase"`
	ScheduleLag  calibrationLatency `json:"source_schedule_lag"`
}

type calibrationSample struct {
	Seconds        float64 `json:"seconds"`
	RSS            int64   `json:"rss_bytes"`
	Allocated      int64   `json:"allocated_bytes"`
	Files          uint64  `json:"files"`
	JournalCharged int64   `json:"journal_charged_bytes"`
	Pending        int     `json:"pending"`
	Persisted      int     `json:"persisted"`
}

type calibrationResult struct {
	Protocol         string              `json:"protocol"`
	Calls            int                 `json:"calls"`
	CopiesPerSecond  int                 `json:"target_copies_per_second"`
	Go               string              `json:"go"`
	GOMAXPROCS       int                 `json:"gomaxprocs"`
	MaxBytes         int64               `json:"max_journal_bytes"`
	MaxRecords       int                 `json:"max_records"`
	MaxPending       int                 `json:"max_pending"`
	Phases           []calibrationPhase  `json:"phases"`
	Samples          []calibrationSample `json:"samples"`
	WallSeconds      float64             `json:"wall_seconds"`
	CPUSeconds       float64             `json:"cpu_seconds"`
	CPUPer1000       float64             `json:"cpu_seconds_per_1000_durable"`
	AllocPerCopy     float64             `json:"allocated_bytes_per_durable"`
	ObjectsPerCopy   float64             `json:"allocated_objects_per_durable"`
	ReadsByDID       [2]uint64           `json:"authenticated_reads_by_destination"`
	RecoverRecords   int                 `json:"recover_records"`
	RecoverSeconds   float64             `json:"recover_seconds"`
	RecoveredRead    calibrationLatency  `json:"recovered_authenticated_read"`
	Purge            calibrationLatency  `json:"held_purge_sync_proxy"`
	AllocatedAtClose int64               `json:"allocated_after_reclaim"`
}

type calibrationCounters struct {
	mu        sync.Mutex
	phase     [5]calibrationPhase
	admission [5]calibrationHistogram
	callback  [5]calibrationHistogram
	schedule  [5]calibrationHistogram
	err       error
	reads     [2]uint64
}

func (c *calibrationCounters) fail(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
}

type calibrationTicket struct {
	id     uint64
	digest [32]byte
}

func runStorageCalibration(parent string, calls int) (_ calibrationResult, resultErr error) {
	root, err := os.MkdirTemp(parent, ".li-storage-calibration-")
	if err != nil {
		return calibrationResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(root)) }()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return calibrationResult{}, err
	}
	keyPath := filepath.Join(root, "key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return calibrationResult{}, err
	}
	clear(key)
	cfg := JournalConfig{Dir: filepath.Join(root, "journal"), KeyFile: keyPath, KeyID: "calibration", PreserveSequences: true,
		MaxBytes: calibrationMaxBytes, MaxRecords: calibrationMaxRecords, MaxPending: 4096}
	j, err := OpenJournal(cfg)
	if err != nil {
		return calibrationResult{}, err
	}
	defer func() {
		if j != nil {
			resultErr = errors.Join(resultErr, j.Close())
		}
	}()
	var counters calibrationCounters
	var phase atomic.Int32
	var readers sync.WaitGroup
	var tickets [2]chan calibrationTicket
	for destination := range tickets {
		tickets[destination] = make(chan calibrationTicket, calibrationMaxRecords/2)
		readers.Add(1)
		go func(destination int) {
			defer readers.Done()
			for ticket := range tickets[destination] {
				for phase.Load() == 2 { // Synthetic MDF outage: keep each copy independently.
					time.Sleep(time.Millisecond)
				}
				record, err := j.readRecord(ticket.id)
				if err == nil && (record.DID != calibrationDIDs[destination] || record.XID != calibrationXID || sha256.Sum256(record.Data) != ticket.digest) {
					err = errors.New("calibration record identity or payload changed")
				}
				if err == nil {
					err = j.Complete(ticket.id)
				}
				counters.fail(err)
				if err == nil {
					counters.mu.Lock()
					counters.phase[phase.Load()].Read++
					counters.reads[destination]++
					counters.mu.Unlock()
				}
			}
		}(destination)
	}
	start := time.Now()
	var memoryStart, memoryEnd runtime.MemStats
	runtime.ReadMemStats(&memoryStart)
	var cpuStart, cpuEnd syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuStart); err != nil {
		counters.fail(err)
	}
	samples := make([]calibrationSample, 0, 128)
	stopSamples := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			allocated, files, err := calibrationAllocated(cfg.Dir)
			counters.fail(err)
			rss, err := calibrationRSS()
			counters.fail(err)
			stats := j.Stats()
			if len(samples) == 1800 {
				counters.fail(errors.New("calibration exceeded bounded 30-minute sampling window"))
				return
			}
			samples = append(samples, calibrationSample{time.Since(start).Seconds(), rss, allocated, files, stats.Bytes, stats.Pending, stats.Persisted})
			select {
			case <-stopSamples:
				return
			case <-ticker.C:
			}
		}
	}()
	names := []string{"warmup", "healthy", "outage", "recovery", "settle"}
	durations := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}
	ordinal := uint64(0)
	for p, duration := range durations {
		phase.Store(int32(p))
		phaseStart := time.Now()
		count := int(duration/time.Second) * calls * 100
		for n := 0; n < count; n++ {
			due := phaseStart.Add(time.Duration(n) * time.Second / time.Duration(calls*100))
			if wait := time.Until(due); wait > 0 {
				time.Sleep(wait)
			}
			counters.mu.Lock()
			counters.schedule[p].add(time.Since(due))
			counters.mu.Unlock()
			data, mediaBytes, call, err := calibrationProduct(ordinal, calls, false)
			ordinal++
			if err != nil {
				counters.fail(err)
				break
			}
			digest := sha256.Sum256(data)
			for destination, did := range calibrationDIDs {
				admitted := time.Now()
				rec := JournalRecord{DID: did, XID: calibrationXID, TaskGeneration: 1, DestinationGeneration: 1, CallGeneration: 1,
					CallID: fmt.Sprintf("synthetic-call-%d", call), AdmittedAt: admitted, CapturedAt: admitted, Data: data}
				_, err := j.Admit(rec, func(id uint64, err error) {
					counters.mu.Lock()
					counters.callback[p].add(time.Since(admitted))
					if err == nil {
						counters.phase[phase.Load()].Durable++
					}
					counters.mu.Unlock()
					counters.fail(err)
					if err == nil {
						select {
						case tickets[destination] <- calibrationTicket{id, digest}:
						default:
							counters.fail(errors.New("bounded destination reader queue exhausted"))
						}
					}
				})
				counters.mu.Lock()
				counters.admission[p].add(time.Since(admitted))
				counters.phase[p].Offered++
				counters.phase[p].MediaBytes += uint64(mediaBytes)
				counters.phase[p].EncodedBytes += uint64(len(data))
				if err == nil {
					counters.phase[p].Accepted++
				} else {
					counters.phase[p].Rejected++
				}
				counters.mu.Unlock()
				if err != nil && !errors.Is(err, ErrJournalFull) {
					counters.fail(err)
				}
			}
		}
		if wait := time.Until(phaseStart.Add(duration)); wait > 0 {
			time.Sleep(wait)
		}
		stats := j.Stats()
		counters.mu.Lock()
		counters.phase[p].Seconds = time.Since(phaseStart).Seconds()
		counters.phase[p].PendingAtEnd, counters.phase[p].DiskAtEnd = stats.Pending, stats.Persisted
		counters.mu.Unlock()
	}
	phase.Store(4)
	settleStart := time.Now()
	counters.fail(j.Flush()) // All admission callbacks finish before closing readers.
	for _, queue := range tickets {
		close(queue)
	}
	readers.Wait()
	counters.fail(j.Flush()) // Include actual durable completion removal.
	counters.phase[4].Seconds = time.Since(settleStart).Seconds()
	close(stopSamples)
	sampler.Wait()
	runtime.ReadMemStats(&memoryEnd)
	counters.fail(syscall.Getrusage(syscall.RUSAGE_SELF, &cpuEnd))
	if counters.err != nil {
		return calibrationResult{}, counters.err
	}
	result := calibrationResult{Protocol: "X2 per-record protocol proxy; synthetic X3-sized PDUs; no MDF transport", Calls: calls,
		CopiesPerSecond: calls * 200, Go: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0), MaxBytes: cfg.MaxBytes,
		MaxRecords: cfg.MaxRecords, MaxPending: cfg.MaxPending, Samples: samples, WallSeconds: time.Since(start).Seconds(), ReadsByDID: counters.reads}
	var accepted, durable, read uint64
	for index := range counters.phase {
		p := counters.phase[index]
		p.Name, p.Admission, p.Callback, p.ScheduleLag = names[index], counters.admission[index].summary(), counters.callback[index].summary(), counters.schedule[index].summary()
		result.Phases = append(result.Phases, p)
		accepted, durable, read = accepted+p.Accepted, durable+p.Durable, read+p.Read
	}
	if accepted != durable || accepted != read || j.Stats().Persisted != 0 {
		return result, fmt.Errorf("calibration accounting mismatch: accepted=%d durable=%d read=%d persisted=%d", accepted, durable, read, j.Stats().Persisted)
	}
	result.CPUSeconds = calibrationCPU(cpuEnd) - calibrationCPU(cpuStart)
	if durable > 0 {
		result.CPUPer1000 = result.CPUSeconds * 1000 / float64(durable)
		result.AllocPerCopy = float64(memoryEnd.TotalAlloc-memoryStart.TotalAlloc) / float64(durable)
		result.ObjectsPerCopy = float64(memoryEnd.Mallocs-memoryStart.Mallocs) / float64(durable)
	}
	// A separate small held-record restart/reclaim probe exercises the real APIs.
	// This is deliberately not presented as the 100k/1m metadata recovery gate.
	const held = 128
	for i := 0; i < held; i++ {
		data, _, _, err := calibrationProduct(ordinal+uint64(i), calls, false)
		if err != nil {
			return result, err
		}
		if _, err := j.Admit(JournalRecord{DID: calibrationDIDs[i%2], XID: calibrationXID, Data: data}, nil); err != nil {
			return result, err
		}
	}
	if err := j.Close(); err != nil {
		return result, err
	}
	j = nil
	restart := time.Now()
	j, err = OpenJournal(cfg)
	if err != nil {
		return result, err
	}
	result.RecoverSeconds, result.RecoverRecords = time.Since(restart).Seconds(), j.Stats().Held
	if result.RecoverRecords != held {
		return result, errors.New("held record restart count mismatch")
	}
	var recoveredRead, purge calibrationHistogram
	if err := j.VisitHeld(func(record JournalRecord) error {
		started := time.Now()
		if _, err := j.readRecord(record.ID); err != nil {
			return err
		}
		recoveredRead.add(time.Since(started))
		started = time.Now()
		if err := j.Purge(record.ID); err != nil {
			return err
		}
		purge.add(time.Since(started))
		return nil
	}); err != nil {
		return result, err
	}
	result.RecoveredRead, result.Purge = recoveredRead.summary(), purge.summary()
	result.AllocatedAtClose, _, err = calibrationAllocated(cfg.Dir)
	return result, err
}

// Each proxy has exactly the same encoded length and raw RTP bytes as its X3
// counterpart. RTP sequence wraps and swaps one adjacent pair in each 100-packet
// stream run. The independent ETSI sequence remains ordered and also wraps.
func calibrationProduct(ordinal uint64, calls int, x3 bool) ([]byte, int, int, error) {
	stream := ordinal % uint64(calls*2)
	call, packet := int(stream/2), ordinal/uint64(calls*2)
	mediaBytes := 160
	if ordinal%10 >= 7 {
		mediaBytes = 320
	}
	if ordinal%10 == 9 {
		mediaBytes = 1200
	}
	rtp := make([]byte, 12+mediaBytes)
	rtp[0] = 0x80
	rtpSequence := packet
	if packet%100 == 0 {
		rtpSequence++
	} else if packet%100 == 1 {
		rtpSequence--
	}
	binary.BigEndian.PutUint16(rtp[2:4], uint16(65500+rtpSequence))
	binary.BigEndian.PutUint32(rtp[4:8], uint32(packet*160))
	binary.BigEndian.PutUint32(rtp[8:12], 0x12340000+uint32(stream))
	seed := ordinal ^ 0x9e3779b97f4a7c15
	for i := 12; i < len(rtp); i++ {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		rtp[i] = byte(seed)
	}
	pdu := x2x3.NewX3RTPPDU(calibrationXID, uint64(call+1))
	if !x3 {
		pdu.Header.Type = x2x3.PDUTypeX2
		pdu.Header.PayloadFormat = x2x3.PayloadFormatSIP
	}
	pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, ^uint32(0)-50+uint32(packet*2+stream%2)))
	pdu.Payload = rtp
	data, err := pdu.MarshalBinary()
	return data, mediaBytes, call, err
}

func calibrationCPU(usage syscall.Rusage) float64 {
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}

func calibrationRSS() (int64, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, errors.New("invalid process RSS counters")
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	return pages * int64(os.Getpagesize()), err
}

// Count allocated blocks for every inode, including directory growth, stable
// lock/usage metadata and encrypted temporary files. Concurrent rename/unlink
// can disappear between enumeration and stat; samples are not atomic snapshots.
func calibrationAllocated(dir string) (_ int64, _ uint64, resultErr error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	allocated := info.Sys().(*syscall.Stat_t).Blocks * 512
	var count uint64
	for {
		names, err := f.Readdirnames(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, 0, err
		}
		for _, name := range names {
			info, err := os.Lstat(filepath.Join(dir, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return 0, 0, err
			}
			if !info.Mode().IsRegular() {
				return 0, 0, errors.New("unexpected calibration artifact")
			}
			allocated += info.Sys().(*syscall.Stat_t).Blocks * 512
			count++
		}
		if errors.Is(err, io.EOF) {
			return allocated, count, nil
		}
	}
}

func TestStorageCalibrationSyntheticProducts(t *testing.T) {
	for _, calls := range []int{1, 10, 100} {
		for _, ordinal := range []uint64{0, 1, 7, 9, 20000, 40001} {
			proxy, media, call, err := calibrationProduct(ordinal, calls, false)
			if err != nil {
				t.Fatal(err)
			}
			x3, otherMedia, otherCall, err := calibrationProduct(ordinal, calls, true)
			if err != nil || len(proxy) != len(x3) || media != otherMedia || call != otherCall {
				t.Fatalf("synthetic encoded-size mismatch: %v", err)
			}
			if _, err := x2x3.X2SequenceCheckpoint(proxy); err != nil {
				t.Fatal(err)
			}
			if _, err := x2x3.X2SequenceCheckpoint(x3); err == nil {
				t.Fatal("proxy must not disguise unsupported X3 journal validation")
			}
		}
	}
	var h calibrationHistogram
	for _, d := range []time.Duration{time.Microsecond, 100 * time.Microsecond, time.Millisecond, time.Second, time.Minute} {
		h.add(d)
		if got := h.quantile(100); got < float64(d)/float64(time.Millisecond) || got > float64(d)/float64(time.Millisecond)*1.063+0.001 {
			t.Fatalf("histogram upper bound %f for %s", got, d)
		}
	}
}
