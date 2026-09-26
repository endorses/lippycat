//go:build li && linux

package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func x3ClientFixture(t *testing.T) (ClientConfig, *Manager, uuid.UUID, uuid.UUID, DeliveryMetadata, []byte) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	key := filepath.Join(root, "x3.key")
	require.NoError(t, os.WriteFile(key, bytes.Repeat([]byte{53}, 32), 0600))
	cfg := DefaultClientConfig()
	cfg.X3SpoolDir = filepath.Join(root, "x3")
	cfg.X3SpoolKeyFile = key
	cfg.X3SpoolKeyID = "x3-test"
	cfg.X3SpoolMaxBytes = 384 << 20
	cfg.X3MaxAge = time.Minute
	cfg.StateIncarnation = uuid.New()
	cfg.QueueSize = 8
	cfg.ShutdownTimeout = time.Millisecond
	did, xid := uuid.New(), uuid.New()
	dest := &li.Destination{DID: did, ProtocolType: "X2ANDX3", X2Enabled: true, X3Enabled: true, CreatedAt: time.Now(), DeliveryRevision: 1}
	manager := &Manager{destinations: map[uuid.UUID]*destinationState{did: {dest: dest}}}
	now := time.Now().UTC()
	meta := DeliveryMetadata{StateIncarnation: cfg.StateIncarnation, AdmittedAt: now, CapturedAt: now, Deadline: now.Add(time.Minute), TaskGeneration: 7, DestinationGeneration: li.DestinationDeliveryGeneration(dest), Provenance: li.DeliveryProvenance{Kind: "non_call", SourceKind: "rtp", OriginNodeID: "synthetic", SourceID: "test-interface", CaptureEpoch: uuid.New(), ObservationSequence: 1, Transport: 17, SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2", SourcePort: 2000, DestinationPort: 3000, SSRC: 42}}
	pdu := x2x3.NewPDU(x2x3.PDUTypeX3, xid, 42)
	pdu.AddAttribute((&x2x3.TLVEncoder{}).EncodeUint32(x2x3.AttrSequenceNumber, 0))
	pdu.SetPayload([]byte("synthetic content only"))
	data, err := pdu.MarshalBinary()
	require.NoError(t, err)
	return cfg, manager, did, xid, meta, data
}

func TestClientX3ProductionRestartManifestAndExactBytes(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta))
	require.NoError(t, c.FlushPersistence(context.Background()))
	require.Equal(t, 1, c.X3JournalStats().Persisted)
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Equal(t, 1, c.X3JournalStats().Held)
	require.Zero(t, c.QueueDepth())
	var recovered JournalRecord
	require.NoError(t, c.x3Journal.VisitHeld(func(r JournalRecord) error { recovered = r; return nil }))
	require.Equal(t, data, recovered.Data)
	require.True(t, meta.Deadline.Equal(recovered.Deadline))
	require.Equal(t, meta.Provenance, recovered.Provenance)
	require.NotEqual(t, [32]byte{}, recovered.ContentSHA256)
	path := filepath.Join(t.TempDir(), "approval.json")
	require.NoError(t, os.Chmod(filepath.Dir(path), 0700))
	require.NoError(t, c.ExportHeldX3JournalManifest(path))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	manifest, err := decodeX3Manifest(raw)
	require.NoError(t, err)
	require.Len(t, manifest.Records, 1)
	require.NoError(t, c.ReplayX3JournalManifest(path, func(JournalRecord) bool { return false }))
	require.Zero(t, c.QueueDepth())
	manifest.Records[0].Deadline.Nanos = (manifest.Records[0].Deadline.Nanos + 1) % 1_000_000_000
	altered, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, altered, 0600))
	require.NoError(t, c.ReplayX3JournalManifest(path, func(JournalRecord) bool { return true }))
	require.Zero(t, c.QueueDepth())
	require.NoError(t, os.WriteFile(path, raw, 0600))
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(time.Minute))
	require.NoError(t, c.ReplayX3JournalManifest(path, func(JournalRecord) bool { return true }))
	require.Eventually(t, func() bool { return c.QueueDepth() == 1 }, time.Second, time.Millisecond)
	q := c.getOrCreateQueue(did)
	q.mu.Lock()
	item := q.items[1].Front().Value.(*deliveryItem)
	require.Equal(t, data, item.data)
	require.True(t, meta.Deadline.Equal(item.metadata.Deadline))
	q.mu.Unlock()
}

func TestClientX3AdmissionReservationAndPureRevocation(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	cfg.X3QueueSize = 1
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	accepted, err := c.PrepareX3(xid, did, data, meta)
	require.NoError(t, err)
	_, err = c.PrepareX3(xid, did, data, meta)
	require.ErrorIs(t, err, ErrQueueFull)
	before := c.X3JournalStats()
	record, admission := c.x3Journal.Highwaters()
	controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, Kind: li.StateTaskDeactivate, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}})
	require.NoError(t, err)
	require.Equal(t, before, c.X3JournalStats())
	afterRecord, afterAdmission := c.x3Journal.Highwaters()
	require.Equal(t, record, afterRecord)
	require.Equal(t, admission, afterAdmission)
	require.True(t, c.itemEligible(did, accepted.item, true))
	outcome, err := c.DurableRevoker().Commit(controls)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, outcome)
	require.Error(t, c.SendAcceptedX3(accepted))
	accepted.Release()
	require.Zero(t, c.QueueDepth())
	require.Zero(t, c.Stats().PhysicalQueueBytes)
	_, err = c.PrepareX3(xid, did, data, meta)
	require.Error(t, err)
}

func TestClientX3CurrentTaskCutoffDoesNotRefreshRecordDeadline(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	cfg.X3SpoolDir = ""
	cfg.X3SpoolKeyFile = ""
	cfg.X3SpoolKeyID = ""
	cfg.X3SpoolMaxBytes = 0
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	accepted, err := c.PrepareX3(xid, did, data, meta)
	require.NoError(t, err)
	require.NoError(t, c.SendAcceptedX3(accepted))
	accepted.Release()
	q := c.getOrCreateQueue(did)
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(-time.Second))
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(time.Hour))
	q.mu.Lock()
	item := q.items[1].Front().Value.(*deliveryItem)
	require.True(t, item.metadata.Deadline.Equal(meta.Deadline))
	q.mu.Unlock()
	require.False(t, c.itemEligible(did, item, false))
	c.expireQueued(q)
	require.Zero(t, c.QueueDepth())
	require.Zero(t, c.Stats().PhysicalQueueBytes)
}

func TestClientDualJournalKeyIndependencePrecedesBootstrap(t *testing.T) {
	cfg, manager, _, _, _, _ := x3ClientFixture(t)
	cfg.X2SpoolDir = filepath.Join(filepath.Dir(cfg.X3SpoolDir), "x2")
	cfg.X2SpoolKeyFile = cfg.X3SpoolKeyFile
	cfg.X2SpoolKeyID = "different-label"
	cfg.X2SpoolMaxBytes = cfg.X3SpoolMaxBytes
	c := NewClient(manager, cfg)
	require.Error(t, c.Err())
	require.NoDirExists(t, cfg.X2SpoolDir)
	require.NoDirExists(t, cfg.X3SpoolDir)
	c.Stop()
}

func TestClientDualJournalAuthenticationPrecedesActivation(t *testing.T) {
	for _, existingX2 := range []bool{false, true} {
		name := "missing X2 remains absent"
		if existingX2 {
			name = "existing X2 remains unchanged"
		}
		t.Run(name, func(t *testing.T) {
			cfg, manager, _, _, _, _ := x3ClientFixture(t)
			initial := NewClient(manager, cfg)
			require.NoError(t, initial.Err())
			initial.Stop()
			catalog := filepath.Join(cfg.X3SpoolDir, ".segments")
			raw, err := os.ReadFile(catalog)
			require.NoError(t, err)
			require.NotEmpty(t, raw)
			raw[len(raw)-1] ^= 1
			require.NoError(t, os.WriteFile(catalog, raw, 0600))
			cfg.X2SpoolDir = filepath.Join(filepath.Dir(cfg.X3SpoolDir), "x2")
			cfg.X2SpoolKeyFile = filepath.Join(filepath.Dir(cfg.X3SpoolDir), "x2.key")
			cfg.X2SpoolKeyID = "independent-x2"
			cfg.X2SpoolMaxBytes = cfg.X3SpoolMaxBytes
			require.NoError(t, os.WriteFile(cfg.X2SpoolKeyFile, bytes.Repeat([]byte{61}, 32), 0600))
			if existingX2 {
				j, err := OpenJournal(JournalConfig{Interface: PDUTypeX2, Dir: cfg.X2SpoolDir, KeyFile: cfg.X2SpoolKeyFile, KeyID: cfg.X2SpoolKeyID, MaxBytes: cfg.X2SpoolMaxBytes, MaxPending: 8, MaxRecords: 16, StateIncarnation: cfg.StateIncarnation})
				require.NoError(t, err)
				require.NoError(t, j.Close())
			}
			snapshot := func(dir string) map[string][32]byte {
				t.Helper()
				entries, err := os.ReadDir(dir)
				require.NoError(t, err)
				result := make(map[string][32]byte, len(entries))
				for _, entry := range entries {
					require.True(t, entry.Type().IsRegular())
					f, err := os.Open(filepath.Join(dir, entry.Name()))
					require.NoError(t, err)
					h := sha256.New()
					_, readErr := io.Copy(h, f)
					closeErr := f.Close()
					require.NoError(t, readErr)
					require.NoError(t, closeErr)
					result[entry.Name()] = [32]byte(h.Sum(nil))
				}
				return result
			}
			x3Before := snapshot(cfg.X3SpoolDir)
			var x2Before map[string][32]byte
			if existingX2 {
				x2Before = snapshot(cfg.X2SpoolDir)
			}
			c := NewClient(manager, cfg)
			require.Error(t, c.Err())
			c.Stop()
			require.Equal(t, x3Before, snapshot(cfg.X3SpoolDir))
			if existingX2 {
				require.Equal(t, x2Before, snapshot(cfg.X2SpoolDir), "authentication failure cannot advance X2 leases or recover its files")
			} else {
				require.NoDirExists(t, cfg.X2SpoolDir, "fresh X2 initialization must wait for existing X3 authentication")
			}
		})
	}
}

func TestX3ManifestRejectsAmbiguousIdentityBeforeApproval(t *testing.T) {
	_, _, did, xid, meta, _ := x3ClientFixture(t)
	r := JournalRecord{JournalUUID: uuid.New(), ID: 1, StateIncarnation: meta.StateIncarnation, XID: xid, DID: did, TaskGeneration: 7, DestinationGeneration: 9, AdmittedAt: meta.AdmittedAt, CapturedAt: meta.CapturedAt, Deadline: meta.Deadline, Provenance: meta.Provenance, ContentSHA256: [32]byte{1}}
	m := X3ReplayManifest{Version: 2, Records: []X3ReplayAuthorization{x3Authorization(r)}}
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	_, err = decodeX3Manifest(raw)
	require.NoError(t, err)
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"interface":"x3"`), []byte(`"interface":"x2"`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"origin_node_id":"synthetic"`), []byte(`"origin_node_id":"\ud800"`), 1)
		},
		func(b []byte) []byte { return append(b, []byte(`{}`)...) },
	} {
		_, err := decodeX3Manifest(mutate(raw))
		require.Error(t, err)
	}
	m.Records = append(m.Records, m.Records[0])
	raw, err = json.Marshal(m)
	require.NoError(t, err)
	_, err = decodeX3Manifest(raw)
	require.Error(t, err)
}

func TestClientX3ReplayOverRealMDFPreservesFIFOAndCompletion(t *testing.T) {
	cfg, _, did, xid, meta, data := x3ClientFixture(t)
	certPEM, keyPEM := generateTestCert(t)
	mdf := newRestartableMDF(t, certPEM, keyPEM, len(data))
	mdf.Start(t)
	defer mdf.Close()
	port := mdf.Port()
	mdf.Stop()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	managerCfg := testConfigWithCerts(t)
	managerCfg.InitialBackoff = 10 * time.Millisecond
	managerCfg.MaxBackoff = 30 * time.Millisecond
	managerCfg.DialTimeout = 50 * time.Millisecond
	manager, err := NewManager(managerCfg)
	require.NoError(t, err)
	defer manager.Stop()
	destination := &li.Destination{DID: did, Address: "127.0.0.1", Port: port, ProtocolType: "X3", X3Enabled: true, CreatedAt: time.Now(), DeliveryRevision: 1, TLSConfig: &tls.Config{RootCAs: pool, Certificates: manager.tlsConfig.Certificates, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	require.NoError(t, manager.AddDestination(destination))
	meta.DestinationGeneration = li.DestinationDeliveryGeneration(destination)
	cfg.RetryInitialBackoff = 10 * time.Millisecond
	cfg.RetryMaxBackoff = 30 * time.Millisecond
	cfg.SendTimeout = 100 * time.Millisecond
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	second := append([]byte(nil), data...)
	second[len(second)-1] = '2'
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta))
	meta.Provenance.ObservationSequence++
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, second, meta))
	require.NoError(t, c.FlushPersistence(context.Background()))
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	c.Start()
	require.Equal(t, 2, c.X3JournalStats().Held)
	// The held predecessor, rather than RAM capacity, is the replay barrier.
	manifest := filepath.Join(t.TempDir(), "approval.json")
	require.NoError(t, os.Chmod(filepath.Dir(manifest), 0700))
	require.NoError(t, c.ExportHeldX3JournalManifest(manifest))
	var firstID uint64
	require.NoError(t, c.x3Journal.VisitHeld(func(r JournalRecord) error {
		if firstID == 0 {
			firstID = r.ID
		}
		return nil
	}))
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(time.Minute))
	require.NoError(t, c.ReplayX3JournalManifest(manifest, func(r JournalRecord) bool { return r.ID == firstID }))
	mdf.Start(t)
	require.Equal(t, string(data), mdf.Receive(t, 3*time.Second))
	require.Eventually(t, func() bool { return c.Stats().X3Sent == 1 }, time.Second, time.Millisecond)
	select {
	case unexpected := <-mdf.received:
		t.Fatalf("unapproved successor delivered: %d bytes", len(unexpected))
	case <-time.After(30 * time.Millisecond):
	}
	require.NoError(t, c.ReplayX3JournalManifest(manifest, func(JournalRecord) bool { return true }))
	require.Equal(t, string(second), mdf.Receive(t, 3*time.Second))
	require.Eventually(t, func() bool { return c.Stats().X3Sent == 2 }, time.Second, time.Millisecond)
	require.NoError(t, c.FlushPersistence(context.Background()))
	require.Zero(t, c.X3JournalStats().Persisted)
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Zero(t, c.X3JournalStats().Held)
}

func TestClientX3TaskCutoffRacingCompletedTransportKeepsOneOutcome(t *testing.T) {
	transport := &failDeadlineClearConn{}
	conn, peer := writeCleanupTLSPipe(t, transport)
	written, release := make(chan struct{}), make(chan struct{})
	var entered, unblock sync.Once
	transport.beforeClear = func() { entered.Do(func() { close(written) }); <-release }
	releaseWrite := func() { unblock.Do(func() { close(release) }) }
	defer releaseWrite()
	did, xid := uuid.New(), uuid.New()
	manager, state := testKeepaliveManager(did)
	manager.registerConnection(state, conn, PDUTypeX3)
	manager.ReleaseConnection(did, conn)
	cfg := DefaultClientConfig()
	cfg.ShutdownTimeout = time.Millisecond
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	c.Start()
	defer func() { releaseWrite(); c.Stop(); manager.Stop() }()
	payload := []byte("synthetic accepted transport before task cutoff")
	got := make([]byte, len(payload))
	read := make(chan error, 1)
	go func() { _, err := io.ReadFull(peer, got); read <- err }()
	originalDeadline := time.Now().Add(time.Minute)
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, payload, DeliveryMetadata{TaskGeneration: 4, Deadline: originalDeadline}))
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("transport did not reach completed-write boundary")
	}
	require.NoError(t, <-read)
	require.Equal(t, payload, got)
	c.SetX3TaskAuthorization(xid, 4, time.Now().Add(-time.Second))
	require.Equal(t, 1, c.QueueDepth(), "cancellation request cannot release an active transport owner")
	releaseWrite()
	require.Eventually(t, func() bool { return c.QueueDepth() == 0 }, time.Second, time.Millisecond)
	stats := c.Stats()
	require.Equal(t, uint64(1), stats.X3Sent+stats.X3Dropped)
	require.Zero(t, stats.PhysicalQueueBytes)
	require.False(t, c.itemEligible(did, &deliveryItem{pduType: PDUTypeX3, xid: xid, metadata: DeliveryMetadata{TaskGeneration: 4, Deadline: originalDeadline}}, false))
}

func TestClientX3RevocationJoinsTransportOwner(t *testing.T) {
	for _, tc := range []struct {
		name        string
		destination bool
		call        bool
		timeout     bool
	}{
		{name: "task"},
		{name: "destination", destination: true},
		{name: "call", call: true},
		{name: "timeout preserves committed control", timeout: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, manager, did, xid, meta, data := x3ClientFixture(t)
			if tc.call {
				meta.CallIncarnation, meta.CallGeneration, meta.CallID = uuid.New(), 3, "synthetic-revoked-call"
				meta.Provenance = li.DeliveryProvenance{Kind: "call", CallIncarnation: meta.CallIncarnation, CallGeneration: meta.CallGeneration, CallID: meta.CallID}
			}
			if tc.timeout {
				cfg.SendTimeout = 50 * time.Millisecond
			}
			c := NewClient(manager, cfg)
			require.NoError(t, c.Err())
			defer c.Stop()
			require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta))
			require.NoError(t, c.FlushPersistence(context.Background()))
			require.Eventually(t, func() bool { return c.QueueDepth() == 1 }, time.Second, time.Millisecond)
			request := li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}}
			if tc.destination {
				request.Task = nil
				request.Destination = &li.StateDestination{DID: did}
				request.DestinationGeneration = meta.DestinationGeneration
			}
			controls, err := c.DurableRevoker().Prepare(request)
			require.NoError(t, err)
			if tc.call {
				control := controls[0]
				control.Scope = li.StateRevokeCall
				control.DID, control.DestinationGeneration = &did, &meta.DestinationGeneration
				control.CallIncarnation, control.CallGeneration = &meta.CallIncarnation, &meta.CallGeneration
			}
			q := c.getOrCreateQueue(did)
			// Stall the actual dispatcher inside connection acquisition. Context
			// cancellation alone cannot release this retained transport owner.
			manager.mu.Lock()
			locked := true
			defer func() {
				if locked {
					manager.mu.Unlock()
				}
			}()
			c.Start()
			var item *deliveryItem
			require.Eventually(t, func() bool {
				q.mu.Lock()
				defer q.mu.Unlock()
				claim := q.claims[1]
				if claim == nil || claim.item.cancel == nil {
					return false
				}
				item = claim.item
				return true
			}, time.Second, time.Millisecond)
			type result struct {
				out securestore.Outcome
				err error
			}
			done := make(chan result, 1)
			go func() {
				out, err := c.DurableRevoker().Commit(controls)
				done <- result{out, err}
			}()
			if tc.timeout {
				select {
				case got := <-done:
					require.Equal(t, securestore.Committed, got.out, "join failure cannot undo the durable control")
					require.ErrorIs(t, got.err, context.DeadlineExceeded)
					require.False(t, c.itemEligible(did, item, false), "timeout must leave the gate blocked")
				case <-time.After(time.Second):
					t.Fatal("revocation join exceeded its configured bound")
				}
			} else {
				select {
				case got := <-done:
					t.Fatalf("revocation returned before the transport owner resolved: outcome=%v error=%v", got.out, got.err)
				case <-time.After(40 * time.Millisecond):
				}
			}
			manager.mu.Unlock()
			locked = false
			if !tc.timeout {
				select {
				case got := <-done:
					require.Equal(t, securestore.Committed, got.out)
					require.NoError(t, got.err)
				case <-time.After(time.Second):
					t.Fatal("revocation did not join the released transport owner")
				}
			}
			require.Eventually(t, func() bool {
				q.mu.Lock()
				defer q.mu.Unlock()
				return q.claims[1] == nil && q.items[1].Len() == 0
			}, time.Second, time.Millisecond)
			require.Equal(t, uint64(1), c.Stats().X3Dropped)
			require.Zero(t, c.Stats().PhysicalQueueBytes)
			out, err := c.DurableRevoker().Commit(controls)
			require.Equal(t, securestore.Committed, out)
			require.NoError(t, err, "retry joins the resolved owner and keeps the control idempotent")
		})
	}
}

func TestClientX3DurableBacklogExceedsTransportQueue(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	cfg.X3QueueSize = 1
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	const count = 8
	for i := 0; i < count; i++ {
		meta.Provenance.ObservationSequence = uint64(i + 1)
		accepted, err := c.PrepareX3(xid, did, data, meta)
		require.NoError(t, err)
		require.NoError(t, c.SendAcceptedX3(accepted))
		accepted.Release()
		require.NoError(t, c.FlushPersistence(context.Background()))
		require.LessOrEqual(t, c.QueueDepth(), 1)
	}
	require.Equal(t, count, c.X3JournalStats().Persisted)
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Equal(t, count, c.X3JournalStats().Held)
	require.Zero(t, c.QueueDepth())
	var visited int
	require.NoError(t, c.x3Journal.VisitHeld(func(r JournalRecord) error {
		visited++
		require.Equal(t, uint64(visited), r.Provenance.ObservationSequence)
		require.Equal(t, data, r.Data)
		return nil
	}))
	require.Equal(t, count, visited)
}

func TestClientX3TaskCutoffSweepsUnapprovedHeldBacklog(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta))
	require.NoError(t, c.FlushPersistence(context.Background()))
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Equal(t, 1, c.X3JournalStats().Held)
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(-time.Second))
	c.SetX3TaskAuthorization(xid, meta.TaskGeneration, time.Now().Add(time.Hour))
	c.Start()
	require.Eventually(t, func() bool { return c.X3JournalStats().Persisted == 0 }, 3*time.Second, time.Millisecond)
	require.Equal(t, uint64(1), c.X3JournalStats().Revoked)
	require.Empty(t, c.X3JournalStats().LastError)
	c.Stop()
	c = NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	require.Zero(t, c.X3JournalStats().Held)
}

func TestClientX3RemoveDestinationJoinsPendingCallbackWithoutReauthorizing(t *testing.T) {
	cfg, manager, did, xid, meta, data := x3ClientFixture(t)
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	c.x3Journal.segments.(*journalSegments).callbacks <- journalCallback{fn: func(uint64, error) { close(entered); <-release }}
	<-entered
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta))
	q := c.getOrCreateQueue(did)
	removed := make(chan struct{})
	go func() { c.RemoveDestination(did); close(removed) }()
	require.Eventually(t, func() bool { q.mu.Lock(); defer q.mu.Unlock(); return q.stopped }, time.Second, time.Millisecond)
	unblock()
	select {
	case <-removed:
	case <-time.After(3 * time.Second):
		t.Fatal("destination removal retained a lock needed by its pending callback")
	}
	require.Equal(t, 1, c.X3JournalStats().Held)
	require.Zero(t, c.X3JournalStats().ReplayPending)
	require.Zero(t, c.QueueDepth())
	require.Zero(t, c.Stats().PhysicalQueueBytes)
}

func TestClientX3RevocationCannotReplaceBoundControl(t *testing.T) {
	cfg, manager, did, xid, meta, _ := x3ClientFixture(t)
	c := NewClient(manager, cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), StateIncarnation: cfg.StateIncarnation, Task: &li.InterceptTask{XID: xid, ActivationGeneration: meta.TaskGeneration}})
	require.NoError(t, err)
	outcome, err := c.DurableRevoker().Commit(controls)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, outcome)
	changed := copyDeliveryControl(controls[0])
	otherXID := uuid.New()
	changed.XID = &otherXID
	outcome, err = c.DurableRevoker().Commit([]*li.StateRevocation{changed})
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, outcome)
	item := &deliveryItem{pduType: PDUTypeX3, xid: xid, metadata: meta}
	require.False(t, c.itemEligible(did, item, false))
	item.xid = otherXID
	require.True(t, c.itemEligible(did, item, false))
}

func TestDeliveryCallRevocationIncludesDestinationIncarnation(t *testing.T) {
	xid, did, state, call := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	taskGeneration, destinationGeneration, callGeneration := uint64(2), uint64(3), uint64(4)
	control := &li.StateRevocation{Version: 1, Scope: li.StateRevokeCall, StateIncarnation: state, XID: &xid, DID: &did, TaskGeneration: &taskGeneration, DestinationGeneration: &destinationGeneration, CallIncarnation: &call, CallGeneration: &callGeneration}
	item := &deliveryItem{pduType: PDUTypeX3, xid: xid, metadata: DeliveryMetadata{StateIncarnation: state, TaskGeneration: taskGeneration, DestinationGeneration: destinationGeneration, CallIncarnation: call, CallGeneration: callGeneration}}
	require.True(t, validDeliveryControl(control))
	require.True(t, controlMatches(control, did, item))
	require.False(t, controlMatches(control, uuid.New(), item))
	item.metadata.DestinationGeneration++
	require.False(t, controlMatches(control, did, item))
	control.DID = nil
	require.False(t, validDeliveryControl(control))
}
