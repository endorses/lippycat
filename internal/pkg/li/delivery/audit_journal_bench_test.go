//go:build li && linux

package delivery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
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
			pdu.SetPayload(make([]byte, 512*(i%8+1)))
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

// BenchmarkAuditProductionJournalOutage drives the production segmented client
// on an explicitly selected ext4 filesystem. The independent producer is paced
// by source time, never by persistence completion. Actual callbacks provide the
// latency timestamps; no modeled per-record arrival offsets are subtracted.
//
// Opt in with LC_LI_STORAGE_BENCH_DIR and -benchtime=1x. Parameters:
// LC_LI_PRODUCTION_CALLS=1|10|100 (default100), SECONDS=1..60 (default1),
// DESTINATIONS=1|2|4 (default2), MODE=x2|x3|dual (defaultdual), all prefixed with
// LC_LI_PRODUCTION_. Dual mode adds100 X2 source products/s on the same device.
// DRAIN=1 adds TLS MDF drain, continuing capture and control/retention probes.
// These observations do not establish the full frozen qualification matrix. Memory/CPU
// include the benchmark's bounded pending observer and original-byte hash oracle.
func BenchmarkAuditProductionJournalOutage(b *testing.B) {
	parent := os.Getenv("LC_LI_STORAGE_BENCH_DIR")
	if parent == "" {
		b.Skip("set LC_LI_STORAGE_BENCH_DIR for opt-in production storage measurement")
	}
	if b.N != 1 {
		b.Fatal("fixed workload requires -benchtime=1x")
	}
	readInt := func(name string, fallback int) int {
		text := os.Getenv("LC_LI_PRODUCTION_" + name)
		if text == "" {
			return fallback
		}
		n, err := strconv.Atoi(text)
		require.NoError(b, err)
		return n
	}
	calls, seconds, destinations := readInt("CALLS", 100), readInt("SECONDS", 1), readInt("DESTINATIONS", 2)
	require.Contains(b, []int{1, 10, 100}, calls)
	require.Contains(b, []int{1, 2, 4}, destinations)
	require.True(b, seconds >= 1 && seconds <= 60)
	mode := os.Getenv("LC_LI_PRODUCTION_MODE")
	drain := os.Getenv("LC_LI_PRODUCTION_DRAIN") == "1"
	if mode == "" {
		mode = "dual"
	}
	require.Contains(b, []string{"x2", "x3", "dual"}, mode)
	var fs syscall.Statfs_t
	require.NoError(b, syscall.Statfs(parent, &fs))
	require.EqualValues(b, 0xef53, fs.Type, "use the reviewed ext4 volume")
	require.GreaterOrEqual(b, fs.Bavail*uint64(fs.Bsize), uint64(5<<30), "allow bounded configured stores and setup scratch")
	root, err := os.MkdirTemp(parent, ".li-production-journal-bench-")
	require.NoError(b, err)
	defer func() { require.NoError(b, os.RemoveAll(root)) }()
	require.NoError(b, os.Chmod(root, 0700))
	cfg := DefaultClientConfig()
	cfg.QueueSize, cfg.X2QueueSize, cfg.X3QueueSize = 4096, 4096, 4096
	cfg.X2QueueBytes, cfg.X3QueueBytes = 64<<20, 64<<20
	cfg.StateIncarnation, cfg.X3MaxAge = uuid.New(), 10*time.Minute
	cfg.X3SpoolDir, cfg.X3SpoolKeyFile = filepath.Join(root, "x3"), filepath.Join(root, "x3.key")
	cfg.X3SpoolKeyID, cfg.X3SpoolMaxBytes = "benchmark-x3", 4<<30
	// A 100-call/two-destination/60s synthetic workload retains 1.2m
	// destination copies. Its conservative terminal-credit reserve requires
	// 24GiB of configured capacity even though actual allocation is measured
	// separately. A short probe keeps the smaller original budget.
	if seconds > 10 {
		cfg.X3SpoolMaxBytes = 24 << 30
	}
	cfg.ShutdownTimeout = time.Millisecond
	require.NoError(b, os.WriteFile(cfg.X3SpoolKeyFile, bytes.Repeat([]byte{0x83}, 32), 0600))
	if mode != "x3" {
		cfg.X2SpoolDir, cfg.X2SpoolKeyFile = filepath.Join(root, "x2"), filepath.Join(root, "x2.key")
		cfg.X2SpoolKeyID, cfg.X2SpoolMaxBytes = "benchmark-x2", 512<<20
		require.NoError(b, os.WriteFile(cfg.X2SpoolKeyFile, bytes.Repeat([]byte{0x82}, 32), 0600))
	}
	manager := &Manager{destinations: make(map[uuid.UUID]*destinationState)}
	var mdf *auditProductionMDF
	if drain {
		mdf = newAuditProductionMDF(b, root, destinations)
		defer mdf.close(b)
	}
	dids := make([]uuid.UUID, destinations)
	for i := range dids {
		dids[i] = uuid.New()
		manager.destinations[dids[i]] = &destinationState{dest: &li.Destination{DID: dids[i], ProtocolType: "X2ANDX3", DeliveryRevision: 1, CreatedAt: time.Now()}}
		if mdf != nil {
			manager.destinations[dids[i]].dest.Address = "127.0.0.1"
			manager.destinations[dids[i]].dest.Port = mdf.listeners[i].Addr().(*net.TCPAddr).Port
			mdf.dids[i] = dids[i]
		}
	}
	callIDs := make([]uuid.UUID, calls)
	for i := range callIDs {
		callIDs[i] = uuid.New()
	}
	b.StopTimer()
	setup := time.Now()
	client := NewClient(manager, cfg)
	require.NoError(b, client.Err())
	defer client.Stop()
	client.SetX3TaskAuthorization(calibrationXID, 1, time.Now().Add(cfg.X3MaxAge))
	client.Start() // offline manager exercises independent retry/expiry owners
	setupTime := time.Since(setup)
	type identity struct {
		typeID  PDUType
		did     uuid.UUID
		ordinal uint64
	}
	type expected struct {
		hash     [32]byte
		deadline time.Time
	}
	type observed struct {
		item     *deliveryItem
		admitted time.Time
		typeID   PDUType
	}
	original := make(map[identity]expected, calls*100*seconds*destinations)
	watch := make(chan observed, 16384)
	var observer sync.WaitGroup
	observer.Add(1)
	var callback [2][]time.Duration
	var failedCallbacks int
	go func() {
		defer observer.Done()
		pending := make([]observed, 0, 16384)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		input := watch
		for input != nil || len(pending) != 0 {
			select {
			case item, ok := <-input:
				if ok {
					pending = append(pending, item)
				} else {
					input = nil
				}
			case <-ticker.C:
			}
			kept := pending[:0]
			for _, p := range pending {
				if p.item.persisted.Load() {
					idx := queueIndex(p.typeID)
					callback[idx] = append(callback[idx], p.item.durableAt.Sub(p.admitted))
				} else if p.item.terminal.Load() {
					failedCallbacks++
				} else {
					kept = append(kept, p)
				}
			}
			clear(pending[len(kept):])
			pending = kept
		}
	}()
	var offered, accepted, rejected [2]int
	var firstRejection [2]string
	var admission, lateness []time.Duration
	var usageBefore [2]uint64
	for _, j := range client.journals() {
		usageBefore[queueIndex(j.cfg.Interface)] = j.usage.Stats().Invocations
	}
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	var cpuBefore, cpuAfter syscall.Rusage
	require.NoError(b, syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore))
	b.StartTimer()
	start := time.Now()
	x3Rate := calls * 100
	x3Total, x2Total := x3Rate*seconds, 0
	if mode == "x2" {
		x3Total = 0
	}
	if mode != "x3" {
		x2Total = 100 * seconds
	}
	var nextX3, nextX2 int
	maxQueue, maxPending := 0, 0
	for nextX3 < x3Total || nextX2 < x2Total {
		typeID, ordinal, rate := PDUTypeX3, nextX3, x3Rate
		if nextX2 < x2Total && (nextX3 == x3Total || time.Duration(nextX2)*time.Second/100 <= time.Duration(nextX3)*time.Second/time.Duration(x3Rate)) {
			typeID, ordinal, rate = PDUTypeX2, nextX2, 100
			nextX2++
		} else {
			nextX3++
		}
		target := start.Add(time.Duration(ordinal) * time.Second / time.Duration(rate))
		if delay := time.Until(target); delay > 0 {
			time.Sleep(delay)
		}
		lateness = append(lateness, max(time.Since(target), 0))
		var data []byte
		call := ordinal % calls
		if typeID == PDUTypeX3 {
			data, _, call, err = calibrationProduct(uint64(ordinal), calls, true)
		} else {
			pdu := x2x3.NewX2SIPPDU(calibrationXID, uint64(call+1))
			pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, uint32(ordinal/calls)))
			body := bytes.Repeat([]byte{'s'}, 512*(ordinal%8+1))
			pdu.SetPayload(append([]byte(fmt.Sprintf("INVITE sip:synthetic@example.invalid SIP/2.0\r\nCall-ID: synthetic-%d\r\nContent-Length: %d\r\n\r\n", call, len(body))), body...))
			data, err = pdu.MarshalBinary()
		}
		require.NoError(b, err)
		for _, did := range dids {
			idx := queueIndex(typeID)
			offered[idx]++
			admitted := time.Now()
			metadata := DeliveryMetadata{StateIncarnation: cfg.StateIncarnation, TaskGeneration: 1, DestinationGeneration: li.DestinationDeliveryGeneration(manager.destinations[did].dest), AdmittedAt: admitted, CapturedAt: target, CallIncarnation: callIDs[call], CallGeneration: 1, CallID: fmt.Sprintf("synthetic-call-%d", call), Provenance: li.DeliveryProvenance{Kind: "call", CallIncarnation: callIDs[call], CallGeneration: 1, CallID: fmt.Sprintf("synthetic-call-%d", call)}}
			var item *deliveryItem
			if typeID == PDUTypeX3 {
				var token *AcceptedX3
				token, err = client.PrepareX3(calibrationXID, did, data, metadata)
				if err == nil {
					item = token.item
					err = client.SendAcceptedX3(token)
					token.Release()
				}
			} else {
				// Instrument the exact detached client persistence branch used by
				// SendX2WithMetadata; retain its item only to observe the callback.
				client.admissionMu.Lock()
				q := client.getOrCreateQueue(did)
				item = &deliveryItem{journal: client.x2Journal, pduType: typeID, xid: calibrationXID, metadata: metadata, queued: admitted, data: append([]byte(nil), data...), detached: true}
				client.attachPayload(item)
				err = client.persistItem(q, item)
				if err != nil {
					client.recordTerminalDrop(did, q, item, "journal_rejected")
				}
				client.admissionMu.Unlock()
			}
			admission = append(admission, time.Since(admitted))
			if err != nil {
				rejected[idx]++
				if firstRejection[idx] == "" {
					firstRejection[idx] = err.Error()
				}
				continue
			}
			accepted[idx]++
			original[identity{typeID, did, uint64(ordinal)}] = expected{sha256.Sum256(data), item.metadata.Deadline}
			watch <- observed{item, admitted, typeID}
		}
		maxQueue = max(maxQueue, client.QueueDepth())
		maxPending = max(maxPending, client.X3JournalStats().Pending)
	}
	producerTime := time.Since(start)
	require.NoError(b, client.FlushPersistence(context.Background()))
	close(watch)
	observer.Wait()
	durableTime := time.Since(start)
	b.StopTimer()
	runtime.ReadMemStats(&memAfter)
	require.NoError(b, syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter))
	rss, err := calibrationRSS()
	require.NoError(b, err)
	var allocated int64
	var renewal [2]uint64
	for _, j := range client.journals() {
		actual, _, err := calibrationAllocated(j.cfg.Dir)
		require.NoError(b, err)
		allocated += actual
		renewal[queueIndex(j.cfg.Interface)] = j.usage.Stats().Invocations - usageBefore[queueIndex(j.cfg.Interface)]
		require.Empty(b, j.Stats().LastError)
	}
	statsX2, statsX3 := client.JournalStats(), client.X3JournalStats()
	require.NoError(b, client.CloseAllCaptures(context.Background()))
	client.Stop()
	var liveManager *Manager
	if mdf != nil {
		mdf.start()
		liveManager, err = NewManager(mdf.config)
		require.NoError(b, err)
		defer liveManager.Stop()
		for _, did := range dids {
			require.NoError(b, liveManager.AddDestination(manager.destinations[did].dest))
		}
		manager = liveManager
	}
	recoveryStart := time.Now()
	reopened := NewClient(manager, cfg)
	require.NoError(b, reopened.Err())
	defer reopened.Stop()
	recoveryTime := time.Since(recoveryStart)
	var recovered [2]int
	transportWant := make(map[auditWireIdentity]int)
	for _, j := range reopened.journals() {
		// Production retains exact bytes; the external oracle holds only hashes.
		byDestination := make(map[uuid.UUID]int)
		require.NoError(b, j.VisitHeld(func(r JournalRecord) error {
			idx := queueIndex(r.Interface)
			// Rejected admissions leave holes; identify the deterministic original
			// PDU by digest while checking each accepted identity exactly once.
			digest := sha256.Sum256(r.Data)
			transportWant[auditWireIdentity{r.Interface, r.DID, digest}]++
			ordinal := byDestination[r.DID]
			for ordinal < offered[idx]/destinations {
				key := identity{r.Interface, r.DID, uint64(ordinal)}
				want, ok := original[key]
				ordinal++
				if !ok {
					continue
				}
				if want.hash != digest || !want.deadline.Equal(r.Deadline) {
					return fmt.Errorf("recovered byte/deadline/FIFO oracle mismatch")
				}
				delete(original, key)
				byDestination[r.DID] = ordinal
				recovered[idx]++
				return nil
			}
			return fmt.Errorf("unexpected recovered product")
		}))
	}
	require.Empty(b, original)
	require.Equal(b, accepted, recovered)
	require.Zero(b, failedCallbacks)
	quantile := func(samples []time.Duration, p int) float64 {
		if len(samples) == 0 {
			return 0
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		return float64(samples[(len(samples)-1)*p/100]) / float64(time.Millisecond)
	}
	for i, name := range []string{"x2", "x3"} {
		b.ReportMetric(float64(offered[i]), name+"-offered")
		b.ReportMetric(float64(accepted[i]), name+"-accepted")
		b.ReportMetric(float64(rejected[i]), name+"-rejected")
		b.ReportMetric(float64(len(callback[i])), name+"-callbacks")
		b.ReportMetric(quantile(callback[i], 50), name+"-callback-p50-ms")
		b.ReportMetric(quantile(callback[i], 99), name+"-callback-p99-ms")
		b.ReportMetric(quantile(callback[i], 100), name+"-callback-max-ms")
		b.ReportMetric(float64(accepted[i])/durableTime.Seconds(), name+"-durable-copies/s")
	}
	b.ReportMetric(quantile(admission, 99), "admission-p99-ms")
	b.ReportMetric(quantile(lateness, 99), "scheduling-lateness-p99-ms")
	b.ReportMetric(quantile(lateness, 100), "scheduling-lateness-max-ms")
	b.ReportMetric(float64(allocated), "actual-allocated-B")
	b.ReportMetric(float64(memAfter.TotalAlloc-memBefore.TotalAlloc), "total-alloc-B")
	b.ReportMetric(float64(memAfter.Mallocs-memBefore.Mallocs), "mallocs")
	b.ReportMetric(float64(memAfter.HeapAlloc), "heap-end-B")
	b.ReportMetric(float64(rss), "rss-end-B")
	b.ReportMetric(calibrationCPU(cpuAfter)-calibrationCPU(cpuBefore), "cpu-s")
	b.ReportMetric(recoveryTime.Seconds(), "reopen-s")
	b.ReportMetric(float64(maxQueue), "transport-queue-peak")
	b.ReportMetric(float64(maxPending), "x3-pending-peak")
	b.Logf("production=%s calls=%d destinations=%d duration=%ds setup=%s producer=%s durable=%s x2=%+v x3=%+v usage_reserved_delta=%v exact_recovered=%v first_rejection=%q shared_host_no_isolation=true", mode, calls, destinations, seconds, setupTime, producerTime, durableTime, statsX2, statsX3, renewal, recovered, firstRejection)
	if x3Total > 0 {
		require.Positive(b, accepted[1], "X3 path must be exercised; first rejection=%q", firstRejection[1])
	}
	if x2Total > 0 {
		require.Positive(b, accepted[0], "X2 path must be exercised; first rejection=%q", firstRejection[0])
	}
	if mdf != nil {
		auditProductionDrain(b, reopened, mdf, cfg, dids, calls, mode, uint64(x3Total), transportWant)
	}
	b.StartTimer()
}

type auditWireIdentity struct {
	Type PDUType
	DID  uuid.UUID
	Hash [32]byte
}
type auditProductionMDF struct {
	listeners []net.Listener
	dids      []uuid.UUID
	config    DestinationConfig
	tls       *tls.Config
	mu        sync.Mutex
	conns     map[net.Conn]bool
	received  map[auditWireIdentity]int
	firstErr  error
	closed    bool
	partial   int
	wg        sync.WaitGroup
}

func newAuditProductionMDF(b *testing.B, root string, destinations int) *auditProductionMDF {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic benchmark"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(b, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(b, err)
	certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath := filepath.Join(root, "tls-cert.pem"), filepath.Join(root, "tls-key.pem")
	require.NoError(b, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(b, os.WriteFile(keyPath, keyPEM, 0600))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(b, err)
	pool := x509.NewCertPool()
	require.True(b, pool.AppendCertsFromPEM(certPEM))
	s := &auditProductionMDF{dids: make([]uuid.UUID, destinations), conns: make(map[net.Conn]bool), received: make(map[auditWireIdentity]int), tls: &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}}
	s.config = DefaultConfig()
	s.config.TLSCertFile = certPath
	s.config.TLSKeyFile = keyPath
	s.config.TLSCAFile = certPath
	s.config.DialTimeout = 100 * time.Millisecond
	s.config.InitialBackoff = 10 * time.Millisecond
	s.config.MaxBackoff = 50 * time.Millisecond
	for i := 0; i < destinations; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(b, err)
		s.listeners = append(s.listeners, listener)
	}
	return s
}
func (s *auditProductionMDF) start() {
	for i, raw := range s.listeners {
		listener, did := tls.NewListener(raw, s.tls), s.dids[i]
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						s.recordError(err)
					}
					return
				}
				s.mu.Lock()
				if s.closed {
					s.mu.Unlock()
					if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						s.recordError(err)
					}
					return
				}
				s.conns[conn] = true
				s.wg.Add(1)
				s.mu.Unlock()
				go s.read(conn, did)
			}
		}()
	}
}
func (s *auditProductionMDF) recordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && s.firstErr == nil {
		s.firstErr = err
	}
}
func (s *auditProductionMDF) read(conn net.Conn, did uuid.UUID) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.recordError(err)
		}
	}()
	for {
		header := make([]byte, x2x3.HeaderMinSize)
		if n, err := io.ReadFull(conn, header); err != nil {
			if n > 0 {
				s.mu.Lock()
				s.partial++
				s.mu.Unlock()
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrUnexpectedEOF) {
				s.recordError(err)
			}
			return
		}
		var parsed x2x3.PDUHeader
		if err := parsed.UnmarshalBinary(header); err != nil {
			s.recordError(err)
			return
		}
		n := uint64(parsed.HeaderLength) + uint64(parsed.PayloadLength)
		if n < uint64(len(header)) || n > 8192 {
			s.recordError(fmt.Errorf("benchmark frame exceeds bounded synthetic format"))
			return
		}
		data := make([]byte, n)
		copy(data, header)
		if _, err := io.ReadFull(conn, data[len(header):]); err != nil {
			s.mu.Lock()
			s.partial++
			s.mu.Unlock()
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
				s.recordError(err)
			}
			return
		}
		s.mu.Lock()
		s.received[auditWireIdentity{PDUType(parsed.Type), did, sha256.Sum256(data)}]++
		s.mu.Unlock()
	}
}
func (s *auditProductionMDF) close(b *testing.B) {
	s.mu.Lock()
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, listener := range s.listeners {
		err := listener.Close()
		if !errors.Is(err, net.ErrClosed) {
			require.NoError(b, err)
		}
	}
	for _, conn := range conns {
		err := conn.Close()
		if !errors.Is(err, net.ErrClosed) {
			require.NoError(b, err)
		}
	}
	s.wg.Wait()
}

// The optional drain is deliberately bounded: one second of unchanged-rate live
// arrivals followed by at most ten seconds to observe transport/control progress.
// Any remaining durable backlog is verified after another reopen and reported,
// never silently treated as a successful throughput qualification.
func auditProductionDrain(b *testing.B, c *Client, mdf *auditProductionMDF, cfg ClientConfig, dids []uuid.UUID, calls int, mode string, startOrdinal uint64, want map[auditWireIdentity]int) {
	b.Helper()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	var cpuBefore, cpuAfter syscall.Rusage
	require.NoError(b, syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore))
	c.SetX3TaskAuthorization(calibrationXID, 1, time.Now().Add(cfg.X3MaxAge))
	// These exact controls run against held records while the historical FIFO
	// predecessors remain unapproved and no MDF transport owner has started.
	probe := func(expiry bool) (uuid.UUID, DeliveryMetadata, []byte) {
		xid := uuid.New()
		now := time.Now()
		meta := DeliveryMetadata{StateIncarnation: cfg.StateIncarnation, TaskGeneration: 1, AdmittedAt: now, CapturedAt: now, Deadline: now.Add(time.Minute), Provenance: li.DeliveryProvenance{Kind: "non_call", SourceKind: "rtp", OriginNodeID: "benchmark", SourceID: "control", CaptureEpoch: uuid.New(), ObservationSequence: 1, Transport: 17, SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2", SourcePort: 2000, DestinationPort: 3000, SSRC: 1}}
		if expiry {
			meta.Deadline = now.Add(150 * time.Millisecond)
		}
		pdu := x2x3.NewX3RTPPDU(xid, 1)
		pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, 0))
		rtp := make([]byte, 172)
		rtp[0], rtp[11] = 0x80, 1
		pdu.SetPayload(rtp)
		data, err := pdu.MarshalBinary()
		require.NoError(b, err)
		handle, err := c.PrepareX3(xid, dids[0], data, meta)
		require.NoError(b, err)
		require.NoError(b, c.SendAcceptedX3(handle))
		handle.Release()
		require.NoError(b, c.FlushPersistence(context.Background()))
		return xid, meta, data
	}
	xid, meta, data := probe(false)
	controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, Task: &li.InterceptTask{XID: xid, ActivationGeneration: 1}})
	require.NoError(b, err)
	controlStart := time.Now()
	out, err := c.DurableRevoker().Commit(controls)
	require.NoError(b, err)
	require.Equal(b, securestore.Committed, out)
	b.ReportMetric(float64(time.Since(controlStart))/float64(time.Millisecond), "revocation-control-ms")
	_, err = c.PrepareX3(xid, dids[0], data, meta)
	require.Error(b, err, "same generation cannot enter after memory revocation")
	expiredBefore := c.X3JournalStats().Expired
	_, expiryMeta, _ := probe(true)
	limit := time.Now().Add(3 * time.Second)
	for c.X3JournalStats().Expired == expiredBefore && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	require.Greater(b, c.X3JournalStats().Expired, expiredBefore)
	b.ReportMetric(float64(time.Since(expiryMeta.Deadline))/float64(time.Millisecond), "held-expiry-notice-ms")
	drainStart := time.Now()
	c.Start()
	require.NoError(b, c.ReplayHeldX2(func(JournalRecord) bool { return true }))
	require.NoError(b, c.ReplayHeldX3(func(JournalRecord) bool { return true }))
	liveStart := time.Now()
	var offered, accepted, rejected [2]int
	var callback [2][]time.Duration
	var admission, lateness []time.Duration
	var pending []*deliveryItem
	newCalls := make([]uuid.UUID, calls)
	for i := range newCalls {
		newCalls[i] = uuid.New()
	}
	rate := calls * 100
	x3Total := rate
	if mode == "x2" {
		x3Total = 0
	}
	x2Total := 100
	if mode == "x3" {
		x2Total = 0
	}
	for x3, x2 := 0, 0; x3 < x3Total || x2 < x2Total; {
		typeID, n, r := PDUTypeX3, x3, rate
		if x2 < x2Total && (x3 == x3Total || time.Duration(x2)*time.Second/100 <= time.Duration(x3)*time.Second/time.Duration(rate)) {
			typeID, n, r = PDUTypeX2, x2, 100
			x2++
		} else {
			x3++
		}
		target := liveStart.Add(time.Duration(n) * time.Second / time.Duration(r))
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
		lateness = append(lateness, max(time.Since(target), 0))
		var data []byte
		call := n % calls
		if typeID == PDUTypeX3 {
			data, _, call, err = calibrationProduct(startOrdinal+uint64(n), calls, true)
		} else {
			pdu := x2x3.NewX2SIPPDU(calibrationXID, uint64(call+1))
			pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, uint32(100000+n/calls)))
			body := bytes.Repeat([]byte{'s'}, 512*(n%8+1))
			pdu.SetPayload(append([]byte(fmt.Sprintf("INVITE sip:synthetic@example.invalid SIP/2.0\r\nCall-ID: synthetic-live-%d\r\nContent-Length: %d\r\n\r\n", call, len(body))), body...))
			data, err = pdu.MarshalBinary()
		}
		require.NoError(b, err)
		for _, did := range dids {
			i := queueIndex(typeID)
			offered[i]++
			now := time.Now()
			dest, err := c.manager.GetDestination(did)
			require.NoError(b, err)
			m := DeliveryMetadata{StateIncarnation: cfg.StateIncarnation, TaskGeneration: 1, DestinationGeneration: li.DestinationDeliveryGeneration(dest), AdmittedAt: now, CapturedAt: target, CallIncarnation: newCalls[call], CallGeneration: 2, CallID: fmt.Sprintf("synthetic-live-%d", call), Provenance: li.DeliveryProvenance{Kind: "call", CallIncarnation: newCalls[call], CallGeneration: 2, CallID: fmt.Sprintf("synthetic-live-%d", call)}}
			var item *deliveryItem
			if typeID == PDUTypeX3 {
				var token *AcceptedX3
				token, err = c.PrepareX3(calibrationXID, did, data, m)
				if err == nil {
					item = token.item
					err = c.SendAcceptedX3(token)
					token.Release()
				}
			} else {
				c.admissionMu.Lock()
				q := c.getOrCreateQueue(did)
				item = &deliveryItem{journal: c.x2Journal, pduType: typeID, xid: calibrationXID, metadata: m, queued: now, data: append([]byte(nil), data...), detached: true}
				c.attachPayload(item)
				err = c.persistItem(q, item)
				if err != nil {
					c.recordTerminalDrop(did, q, item, "journal_rejected")
				}
				c.admissionMu.Unlock()
			}
			admission = append(admission, time.Since(now))
			if err != nil {
				rejected[i]++
				continue
			}
			accepted[i]++
			pending = append(pending, item)
			want[auditWireIdentity{typeID, did, sha256.Sum256(data)}]++
		}
	}
	require.NoError(b, c.FlushPersistence(context.Background()))
	for _, item := range pending {
		require.True(b, item.persisted.Load(), "accepted live product did not complete durability")
		i := queueIndex(item.pduType)
		callback[i] = append(callback[i], item.durableAt.Sub(item.metadata.AdmittedAt))
	}
	pending = nil
	limit = time.Now().Add(10 * time.Second)
	for c.JournalStats().Persisted+c.X3JournalStats().Persisted != 0 && time.Now().Before(limit) {
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(b, c.CloseAllCaptures(context.Background()))
	c.Stop()
	drainDuration := time.Since(drainStart)
	retained := NewClient(c.manager, cfg)
	require.NoError(b, retained.Err())
	defer retained.Stop()
	left := make(map[auditWireIdentity]int)
	for _, j := range retained.journals() {
		require.NoError(b, j.VisitHeld(func(r JournalRecord) error {
			left[auditWireIdentity{r.Interface, r.DID, sha256.Sum256(r.Data)}]++
			return nil
		}))
	}
	mdf.mu.Lock()
	received := make(map[auditWireIdentity]int, len(mdf.received))
	for k, v := range mdf.received {
		received[k] = v
	}
	receiverError := mdf.firstErr
	partial := mdf.partial
	mdf.mu.Unlock()
	require.NoError(b, receiverError)
	var delivered, held, duplicates [2]int
	for key, count := range want {
		n, l := received[key], left[key]
		require.GreaterOrEqual(b, n+l, count, "accepted copy is neither received nor durably retained")
		require.LessOrEqual(b, l, count)
		i := queueIndex(key.Type)
		delivered[i] += n
		held[i] += l
		duplicates[i] += max(0, n+l-count)
		delete(received, key)
		delete(left, key)
	}
	require.Empty(b, received, "MDF saw bytes outside the external original-byte oracle")
	require.Empty(b, left, "reopen retained an unexpected product")
	for i, name := range []string{"x2", "x3"} {
		if offered[i] > 0 {
			require.Positive(b, delivered[i], "selected interface must make real MDF progress")
		}
		b.ReportMetric(float64(offered[i]), name+"-live-offered")
		b.ReportMetric(float64(accepted[i]), name+"-live-accepted")
		b.ReportMetric(float64(rejected[i]), name+"-live-rejected")
		b.ReportMetric(float64(len(callback[i])), name+"-live-callbacks")
		sort.Slice(callback[i], func(a, z int) bool { return callback[i][a] < callback[i][z] })
		if n := len(callback[i]); n > 0 {
			b.ReportMetric(float64(callback[i][(n-1)/2])/float64(time.Millisecond), name+"-live-callback-p50-ms")
			b.ReportMetric(float64(callback[i][(n-1)*99/100])/float64(time.Millisecond), name+"-live-callback-p99-ms")
			b.ReportMetric(float64(callback[i][n-1])/float64(time.Millisecond), name+"-live-callback-max-ms")
		}
		b.ReportMetric(float64(delivered[i])/drainDuration.Seconds(), name+"-transport-copies/s")
		b.ReportMetric(float64(held[i]), name+"-drain-retained")
		b.ReportMetric(float64(duplicates[i]), name+"-received-retained-overlap")
	}
	b.ReportMetric(float64(partial), "transport-partial-frames")
	sort.Slice(admission, func(i, j int) bool { return admission[i] < admission[j] })
	sort.Slice(lateness, func(i, j int) bool { return lateness[i] < lateness[j] })
	if len(admission) > 0 {
		b.ReportMetric(float64(admission[(len(admission)-1)*99/100])/float64(time.Millisecond), "live-admission-p99-ms")
	}
	if len(lateness) > 0 {
		b.ReportMetric(float64(lateness[(len(lateness)-1)*99/100])/float64(time.Millisecond), "live-scheduling-lateness-p99-ms")
	}
	runtime.ReadMemStats(&memAfter)
	require.NoError(b, syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter))
	rss, err := calibrationRSS()
	require.NoError(b, err)
	b.ReportMetric(float64(memAfter.HeapAlloc), "drain-heap-end-B")
	b.ReportMetric(float64(rss), "drain-rss-end-B")
	b.ReportMetric(float64(memAfter.TotalAlloc-memBefore.TotalAlloc), "drain-total-alloc-B")
	b.ReportMetric(calibrationCPU(cpuAfter)-calibrationCPU(cpuBefore), "drain-cpu-s")
	b.Logf("bounded TLS drain duration=%s continuing_arrival_seconds=1 live_offered=%v accepted=%v rejected=%v wire_received=%v durable_retained=%v received_retained_overlap=%v exact_wire_or_retained_oracle=true shared_host_no_isolation=true", drainDuration, offered, accepted, rejected, delivered, held, duplicates)
}
