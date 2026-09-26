//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This fixture uses the actual Processor startup, encrypted owners, ADMF XML,
// packet encoder, reorder callbacks, journal and restart approval path.
type persistentProcessorFixture struct {
	config               Config
	xid, did             uuid.UUID
	address              string
	mu                   sync.Mutex
	target               string
	port                 int
	includeTask          bool
	endTime              time.Time
	explicitDeactivation bool
}

func TestProcessorX3ReplayPolicyWiring(t *testing.T) {
	for _, policy := range []string{"", "hold", "purge"} {
		p := &Processor{config: Config{LIDeliveryX3SpoolReplayPolicy: policy}}
		require.Equal(t, policy, p.liDeliveryConfig().X3SpoolReplayPolicy)
		err := validateIndependentStorageKeys(p.config, nil)
		if policy == "purge" {
			require.Error(t, err, "an explicit persistent operation requires LI")
		} else {
			require.NoError(t, err, "default hold without a spool preserves disabled-LI compatibility")
		}
	}
}

func TestProcessorPersistentRTPObservationIdentity(t *testing.T) {
	p := &Processor{liStorage: &liStoragePreparation{captureEpoch: uuid.New()}}
	packet := dirRTPPacket(42, "::ffff:192.0.2.1", "1000", "192.0.2.2", "2000")
	packet.NodeID, packet.Interface, packet.Transport = "sensor", "capture-source", 17
	first, err := p.newRTPProvenance(packet)
	require.NoError(t, err)
	second, err := p.newRTPProvenance(packet)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", first.SourceAddress)
	require.Equal(t, "non_call", first.Kind)
	require.Equal(t, "rtp", first.SourceKind)
	require.Equal(t, first.CaptureEpoch, second.CaptureEpoch)
	require.EqualValues(t, 1, first.ObservationSequence)
	require.EqualValues(t, 2, second.ObservationSequence)
	p.liStorage.observationSequence.Store(^uint64(0))
	_, err = p.newRTPProvenance(packet)
	require.Error(t, err, "an exhausted capture sequence cannot wrap or invent another epoch")
	p.liStorage.observationSequence.Store(0)
	packet.Interface = ""
	_, err = p.newRTPProvenance(packet)
	require.Error(t, err, "non-call capture never invents a source identity")
	require.Zero(t, p.liStorage.observationSequence.Load())
}

func newPersistentProcessorFixture(t *testing.T) *persistentProcessorFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close()) // MDF is deliberately unavailable during capture.
	f := &persistentProcessorFixture{config: storageKeyStartupConfig(t), xid: uuid.New(), did: uuid.New(), address: address, port: port, target: "sip:alice@example.invalid", includeTask: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		xid, did, target, ip := schema.UUID(f.xid.String()), schema.UUID(f.did.String()), schema.SIPURI(f.target), "127.0.0.1"
		implicit := true
		if f.explicitDeactivation {
			implicit = false
		}
		response := schema.GetAllDetailsResponse{
			ListOfTaskResponseDetails: &schema.ListOfTaskResponseDetails{},
			ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{DestinationResponseDetails: []*schema.DestinationResponseDetails{{DestinationDetails: &schema.DestinationDetails{
				DId: &did, DeliveryType: "X3Only", DeliveryAddress: &schema.DeliveryAddress{IpAddressAndPort: &schema.IPAddressPort{Address: &schema.IPAddress{IPv4Address: &ip}, Port: &schema.Port{TCPPort: &f.port}}},
			}}}},
		}
		if f.includeTask {
			var end *schema.QualifiedMicrosecondDateTime
			var mediation *schema.ListOfMediationDetails
			if !f.endTime.IsZero() {
				value := schema.QualifiedMicrosecondDateTime(f.endTime.Format(time.RFC3339Nano))
				end = &value
				mediation = &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{DeliveryType: "HI3Only", EndTime: end}}}
			}
			response.ListOfTaskResponseDetails.TaskResponseDetails = []*schema.TaskResponseDetails{{TaskDetails: &schema.TaskDetails{
				XId: &xid, DeliveryType: "X3Only", ImplicitDeactivationAllowed: &implicit, ListOfMediationDetails: mediation,
				TargetIdentifiers: &schema.ListOfTargetIdentifiers{TargetIdentifier: []*schema.TargetIdentifier{{SipUri: &target}}}, ListOfDIDs: &schema.ListOfDids{DId: []*schema.UUID{&did}},
			}, TaskStatus: &schema.TaskStatus{ProvisioningStatus: "active"}}}
		}
		body, err := xml.Marshal(response)
		f.mu.Unlock()
		if err != nil {
			t.Errorf("marshal ADMF response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if _, err := w.Write(body); err != nil {
			t.Logf("ADMF response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	f.config.ProcessorID = "persistent-processor-test"
	f.config.LIADMFEndpoint, f.config.LIADMFSyncOnStartup, f.config.LIADMFSyncTimeout = server.URL, true, 3*time.Second
	f.config.LIDeliveryX3SpoolDir = filepath.Join(t.TempDir(), "x3")
	f.config.LIDeliveryX3SpoolMaxBytes = 384 << 20
	// Persistent X3 also upgrades the shared control/sequence owner to the
	// bounded segmented workspace; keep both independent journals provisioned.
	f.config.LIDeliveryX2SpoolMaxBytes = 384 << 20
	key := storageKeyRef(t, "x3-active", 7)
	f.config.LIDeliveryX3SpoolKeyFile, f.config.LIDeliveryX3SpoolKeyID = key.File, key.ID
	f.config.LIDeliveryX3MaxAge = time.Minute
	f.config.LIDeliveryX3SpoolReplayPolicy = "hold"
	f.config.LIDeliveryShutdownTimeout = time.Millisecond
	return f
}

func (f *persistentProcessorFixture) open(t *testing.T) *Processor {
	t.Helper()
	p, err := New(f.config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p
}

func (f *persistentProcessorFixture) captureAndClose(t *testing.T, p *Processor) uuid.UUID {
	t.Helper()
	require.NoError(t, p.startLIManager())
	task, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	require.Equal(t, li.TaskStatusActive, task.Status)
	for _, sequence := range []uint16{1, 3} {
		packet := dirRTPPacket(42, dirUEAddr, dirUEPort, dirCoreAddr, dirCorePort)
		packet.Timestamp = time.Now().UTC()
		packet.VoIPData.SequenceNum = sequence
		packet.RawData[0], packet.RawData[1] = byte(sequence), 0x55
		// SIP identity filters reach RTP through the authoritative call match,
		// never as a fabricated packet-level direct IP match.
		p.processLIPacketWithProvenance(packet, nil, []string{"li-" + f.xid.String() + "-0"})
	}
	result := p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete)
	require.True(t, result.Finalized)
	require.NoError(t, result.Err, "normal completion must drain accepted reorder work before durable call closure")
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Equal(t, 2, liDeliveryClient.X3JournalStats().Persisted)
	require.True(t, p.callLifecycle.IsFinalized(dirCallID))
	return p.liManager.StateIncarnation()
}

func exportProcessorX3Approval(t *testing.T) (string, delivery.X3ReplayManifest) {
	t.Helper()
	path := newTestFilterFile(t)
	require.NoError(t, liDeliveryClient.ExportHeldX3JournalManifest(path))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var manifest delivery.X3ReplayManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	return path, manifest
}

func (f *persistentProcessorFixture) listenMDF(t *testing.T) <-chan *x2x3.PDU {
	t.Helper()
	certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
	certificate, err := tls.LoadX509KeyPair(filepath.Join(certDir, "mdf-server-cert.pem"), filepath.Join(certDir, "mdf-server-key.pem"))
	require.NoError(t, err)
	caBytes, err := os.ReadFile(filepath.Join(certDir, "ca-cert.pem"))
	require.NoError(t, err)
	ca := x509.NewCertPool()
	require.True(t, ca.AppendCertsFromPEM(caBytes))
	listener, err := tls.Listen("tcp", f.address, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca})
	require.NoError(t, err)
	products := make(chan *x2x3.PDU, 8)
	var mu sync.Mutex
	var workers sync.WaitGroup
	connections := make(map[net.Conn]struct{})
	closed := false
	workers.Add(1)
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		for connection := range connections {
			_ = connection.Close()
		}
		mu.Unlock()
		require.NoError(t, listener.Close())
		workers.Wait()
	})
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = connection.Close()
				return
			}
			connections[connection] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			// Destination health and X3 transport use distinct connections. Read
			// every accepted stream instead of waiting on the health connection.
			go func() {
				defer workers.Done()
				defer func() { _ = connection.Close(); mu.Lock(); delete(connections, connection); mu.Unlock() }()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					pdu, err := x2x3.ReadPDU(connection)
					if err != nil {
						return
					}
					products <- pdu
				}
			}()
		}
	}()
	return products
}

func TestProcessorPersistentX3NormalCloseRestartApprovalMDF(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	p := f.open(t)
	incarnation := f.captureAndClose(t, p)
	require.NoError(t, p.Shutdown())
	journal, err := delivery.OpenJournal(delivery.JournalConfig{Interface: delivery.PDUTypeX3,
		Dir: f.config.LIDeliveryX3SpoolDir, KeyFile: f.config.LIDeliveryX3SpoolKeyFile, KeyID: f.config.LIDeliveryX3SpoolKeyID,
		MaxBytes: f.config.LIDeliveryX3SpoolMaxBytes, MaxPending: 10000, MaxRecords: 2_000_000,
		StateIncarnation: incarnation, MaxAge: f.config.LIDeliveryX3MaxAge, PreserveSequences: true})
	require.NoError(t, err)
	var original [][]byte
	require.NoError(t, journal.VisitHeld(func(record delivery.JournalRecord) error {
		original = append(original, append([]byte(nil), record.Data...))
		return nil
	}))
	require.NoError(t, journal.Close())
	require.Len(t, original, 2)
	restarted := f.open(t)
	require.Equal(t, 2, liDeliveryClient.X3JournalStats().Held)
	require.Zero(t, liDeliveryClient.QueueDepth(), "recovery alone never authorizes transport")
	path, manifest := exportProcessorX3Approval(t)
	require.Len(t, manifest.Records, 2)
	for _, record := range manifest.Records {
		require.Equal(t, incarnation, record.StateIncarnation)
		require.Equal(t, dirCallID, record.Provenance.CallID)
		require.NotEqual(t, uuid.Nil, record.Provenance.CallIncarnation)
	}
	require.Equal(t, manifest.Records[0].Provenance.CallIncarnation, manifest.Records[1].Provenance.CallIncarnation)
	products := f.listenMDF(t)
	restarted.config.LIDeliveryX3SpoolReplayManifest = path
	require.NoError(t, restarted.startLIManager())
	require.Equal(t, incarnation, restarted.liManager.StateIncarnation())
	for index := range 2 {
		select {
		case product := <-products:
			require.Equal(t, x2x3.PDUTypeX3, product.Header.Type)
			require.Equal(t, f.xid, product.Header.XID)
			encoded, err := product.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, original[index], encoded, "MDF receives the original accepted encoded bytes after restart")
		case <-time.After(5 * time.Second):
			t.Fatalf("approved historical product did not reach TLS MDF: journal=%+v client=%+v", liDeliveryClient.X3JournalStats(), liDeliveryClient.Stats())
		}
	}
	// Reused protocol Call-ID after restart gets a fresh incarnation while the
	// durable X3 sequence context continues above both replayed products.
	packet := dirRTPPacket(42, dirUEAddr, dirUEPort, dirCoreAddr, dirCorePort)
	packet.Timestamp, packet.VoIPData.SequenceNum = time.Now().UTC(), 5
	restarted.processLIPacketWithProvenance(packet, nil, []string{"li-" + f.xid.String() + "-0"})
	grant, err := restarted.callLifecycle.Admit(dirCallID)
	require.NoError(t, err)
	require.NotEqual(t, manifest.Records[0].Provenance.CallIncarnation, grant.Incarnation())
	grant.Release()
	select {
	case product := <-products:
		encoded, err := product.MarshalBinary()
		require.NoError(t, err)
		checkpoint, err := x2x3.ProductSequenceCheckpoint(encoded)
		require.NoError(t, err)
		require.EqualValues(t, 3, checkpoint.Next, "restored sequence emits 2 after historical 0 and 1")
	case <-time.After(5 * time.Second):
		t.Fatal("fresh call incarnation did not reach the MDF after historical replay")
	}
	require.NoError(t, restarted.Shutdown())
}

func TestProcessorPersistentX3ReplayRequiresCurrentAuthority(t *testing.T) {
	for _, scenario := range []string{"no_approval", "task_changed", "destination_changed", "withdrawal", "expired", "state_changed"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPersistentProcessorFixture(t)
			if scenario == "expired" {
				f.config.LIDeliveryX3MaxAge = 200 * time.Millisecond
			}
			p := f.open(t)
			f.captureAndClose(t, p)
			if scenario == "withdrawal" {
				require.NoError(t, p.liManager.DeactivateTask(f.xid))
				f.mu.Lock()
				f.includeTask = false
				f.mu.Unlock()
			}
			require.NoError(t, p.Shutdown())
			if scenario == "state_changed" {
				f.config.LIStateFile = newTestFilterFile(t)
				_, err := li.InitializeEncryptedStateStore(f.config.LIStateFile, f.config.LIStateKeys, li.StateOfflineOptions{})
				require.NoError(t, err)
				other, err := New(f.config)
				require.Error(t, err, "an unrelated authenticated state incarnation cannot adopt retained X3")
				require.Nil(t, other)
				return
			}
			if scenario == "expired" {
				time.Sleep(220 * time.Millisecond)
			}
			restarted := f.open(t)
			path, manifest := exportProcessorX3Approval(t)
			if scenario == "withdrawal" {
				require.Empty(t, manifest.Records)
			} else {
				require.Len(t, manifest.Records, 2)
			}
			if scenario == "expired" {
				for _, record := range manifest.Records {
					require.True(t, time.Unix(record.Deadline.Seconds, int64(record.Deadline.Nanos)).Before(time.Now()), "deadline is the original admission cutoff")
				}
			}
			f.mu.Lock()
			if scenario == "task_changed" {
				f.target = "sip:changed@example.invalid"
			}
			if scenario == "destination_changed" {
				f.port++
			}
			f.mu.Unlock()
			products := f.listenMDF(t)
			if scenario != "no_approval" {
				restarted.config.LIDeliveryX3SpoolReplayManifest = path
			}
			require.NoError(t, restarted.startLIManager())
			require.Zero(t, liDeliveryClient.QueueDepth())
			select {
			case <-products:
				t.Fatal("unapproved or ineligible historical product reached the MDF")
			case <-time.After(30 * time.Millisecond):
			}
			require.NoError(t, restarted.Shutdown())
		})
	}
}

func TestProcessorPersistentX3TimingCommitWithoutNewPacket(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	p := f.open(t)
	f.captureAndClose(t, p)
	before, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	end := time.Now().Add(80 * time.Millisecond).UTC()
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &end}))
	current, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	require.Equal(t, before.ActivationGeneration, current.ActivationGeneration)
	// No new packet is needed to propagate the committed shortened cutoff.
	require.Eventually(t, func() bool { return liDeliveryClient.X3JournalStats().Persisted == 0 }, time.Second, 5*time.Millisecond)
	extended := time.Now().Add(time.Minute).UTC()
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{EndTime: &extended}))
	encodedBefore := p.getLIEncodingStats().X3Encoded
	packet := dirRTPPacket(52, dirUEAddr, dirUEPort, dirCoreAddr, dirCorePort)
	packet.Timestamp, packet.VoIPData.CallID = time.Now().UTC(), "new-call-after-cutoff"
	p.processLIPacketWithProvenance(packet, nil, []string{"li-" + f.xid.String() + "-0"})
	require.Equal(t, encodedBefore+1, p.getLIEncodingStats().X3Encoded, "fresh capture reaches the immutable client gate after the metadata extension")
	require.NoError(t, liDeliveryClient.FlushPersistence(context.Background()))
	require.Zero(t, liDeliveryClient.X3JournalStats().Persisted, "extension cannot resurrect the already expired task generation")
	require.NoError(t, p.Shutdown())
}
