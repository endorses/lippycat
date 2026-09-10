//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	packetpcap "github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type radiusPOIMatcher struct{ group *radius.Group }

func (m radiusPOIMatcher) MatchRADIUSObservation(o *radius.Observation) (bool, []string, []radius.AttributionReference) {
	ref, ok, err := m.group.Match(o)
	if err != nil || !ok {
		return false, nil, nil
	}
	return true, nil, []radius.AttributionReference{ref}
}
func (m radiusPOIMatcher) RADIUSEvidenceCurrent(ref radius.AttributionReference) bool {
	return m.group.CurrentReference(ref)
}

func radiusPOIBatch(t *testing.T, p *Processor, task *li.InterceptTask) (*source.PacketBatch, []*radius.Observation) {
	t.Helper()
	fm := li.NewFilterManager(nil)
	ids, err := fm.CreateFiltersForTask(task)
	require.NoError(t, err)
	group, ok := fm.LookupRADIUSGroup(ids[0])
	require.True(t, ok)
	capture, err := radius.NewCaptureProcessor(radius.CaptureScope{OriginNodeID: "tap-fixture", SourceID: "eth0", OperatorScope: "operator", ProfileRevision: "v1"})
	require.NoError(t, err)
	defer capture.Close()
	packets := radiusOutputFixtures(t)
	observations := make([]*radius.Observation, 0, len(packets))
	for i, packet := range packets {
		packet.TimestampNs = time.Now().Add(time.Duration(i) * time.Millisecond).UnixNano()
		decoded := gopacket.NewPacket(packet.Data, layers.LinkType(packet.LinkType), gopacket.Default)
		decoded.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, packet.TimestampNs), CaptureLength: int(packet.CaptureLength), Length: int(packet.OriginalLength)}
		o := capture.Process(decoded, layers.LinkType(packet.LinkType), "eth0", radiusPOIMatcher{group})
		require.NotNil(t, o)
		packet.Radius = grpcadapter.RADIUSToProto(o)
		observations = append(observations, o)
	}
	require.Len(t, observations[0].Direct, 1)
	require.Len(t, observations[1].Inherited, 1)
	batch := source.FromProtoBatch(&data.PacketBatch{HunterId: "tap-fixture", Packets: packets})
	batch.RADIUSSourceTrusted = true
	return batch, observations
}

func radiusPOIProcessor(t *testing.T, queueSize int) (*Processor, *li.InterceptTask, string) {
	t.Helper()
	dir := t.TempDir()
	p, err := New(Config{ProcessorID: "tap-poi", ListenAddr: "127.0.0.1:0", MaxHunters: 1, LIEnabled: true, LIRADIUSCorrelationStateFile: filepath.Join(dir, "correlation.json"), FilterFile: filepath.Join(dir, "filters.yaml"), WriteFile: filepath.Join(dir, "ordinary.pcap"), LogConfig: &StructuredLogConfig{Enabled: true, Directory: dir, Format: "json", Streams: []string{"radius"}, QueueSize: 32, EmitStage: "all"}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	p.pcapWriter, err = packetpcap.NewWriter(p.config.WriteFile)
	require.NoError(t, err)
	p.pcapWriter.Start(context.Background())
	require.NoError(t, p.logSink.Start(context.Background()))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	cfg := delivery.DefaultConfig()
	certDir := "../../../test/testcerts/li"
	cfg.TLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
	cfg.TLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
	cfg.TLSCAFile = filepath.Join(certDir, "ca-cert.pem")
	cfg.DialTimeout = 50 * time.Millisecond
	liDeliveryMgr, err = delivery.NewManager(cfg)
	require.NoError(t, err)
	clientCfg := delivery.DefaultClientConfig()
	clientCfg.QueueSize = queueSize
	clientCfg.ShutdownTimeout = time.Second
	clientCfg.SendTimeout = 100 * time.Millisecond
	liDeliveryClient = delivery.NewClient(liDeliveryMgr, clientCfg)
	require.NoError(t, liDeliveryClient.Err())
	dest := &li.Destination{DID: uuid.New(), Address: "127.0.0.1", Port: 1, X2Enabled: true, ProtocolType: "X2Only"}
	require.NoError(t, p.liManager.CreateDestination(dest))
	require.NoError(t, replaceLIDeliveryDestination(liDeliveryMgr, liDeliveryClient, dest))
	task := &li.InterceptTask{XID: uuid.New(), Targets: []li.TargetIdentity{{Type: li.TargetTypeNAI, Value: "alice@example.test"}}, DeliveryType: li.DeliveryX2Only, DestinationIDs: []uuid.UUID{dest.DID}, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}
	require.NoError(t, p.liManager.ActivateTask(task))
	task, err = p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	return p, task, dir
}

func radiusPOIMDF(t *testing.T) (int, <-chan *x2x3.PDU) {
	t.Helper()
	certDir := "../../../test/testcerts/li"
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "mdf-server-cert.pem"), filepath.Join(certDir, "mdf-server-key.pem"))
	require.NoError(t, err)
	ca, err := os.ReadFile(filepath.Join(certDir, "ca-cert.pem"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	out := make(chan *x2x3.PDU, 16)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("close MDF connection: %v", err)
			}
		}()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		for {
			pdu, err := x2x3.ReadPDU(conn)
			if err != nil {
				return
			}
			out <- pdu
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, out
}

func assertRadiusPOIOrdinary(t *testing.T, p *Processor, dir string, want int) {
	t.Helper()
	require.NoError(t, p.Shutdown())
	log, err := os.ReadFile(filepath.Join(dir, "radius.log"))
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(log)), "\n"), want)
	f, err := os.Open(filepath.Join(dir, "ordinary.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	fixtures := radiusOutputFixtures(t)
	for i := 0; i < want; i++ {
		got, _, err := r.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, fixtures[i%2].Data, got)
	}
}

func TestRADIUSTapPOITLSFixtureAndShutdown(t *testing.T) {
	p, task, dir := radiusPOIProcessor(t, 16)
	p.config.LIRADIUSCorrelationLifetime = 60 * time.Second
	port, received := radiusPOIMDF(t)
	require.NoError(t, replaceLIDeliveryDestination(liDeliveryMgr, liDeliveryClient, &li.Destination{DID: task.DestinationIDs[0], Address: "127.0.0.1", Port: port, X2Enabled: true, ProtocolType: "X2Only"}))
	liDeliveryClient.Start()
	out := p.subscriberManager.Add("ordinary")
	batch, observations := radiusPOIBatch(t, p, task)
	p.processBatch(batch)
	requireRadiusPOIBroadcast(t, out)
	// Shutdown drains already admitted RADIUS product while closing ordinary sinks.
	assertRadiusPOIOrdinary(t, p, dir, 2)
	require.EqualValues(t, 2, p.radiusLIStats.Encoded)
	require.EqualValues(t, 2, p.radiusLIStats.QueueAccepted)
	require.Zero(t, p.radiusLIStats.QueueErrors)
	var correlation uint64
	for i, o := range observations {
		select {
		case got := <-received:
			require.Equal(t, x2x3.PayloadFormatRADIUS, got.Header.PayloadFormat)
			require.Equal(t, task.XID, got.Header.XID)
			require.Equal(t, o.Message.Raw, got.Payload)
			require.Equal(t, x2x3.PayloadDirectionUnknown, got.Header.PayloadDirection)
			if i == 0 {
				correlation = got.Header.CorrelationID
			}
			require.Equal(t, correlation, got.Header.CorrelationID)
			found := false
			for _, a := range got.Attributes {
				if a.Type == x2x3.AttrSequenceNumber {
					require.Equal(t, uint32(i), binary.BigEndian.Uint32(a.Value))
					found = true
				}
			}
			require.True(t, found)
		case <-time.After(3 * time.Second):
			t.Fatal("MDF did not receive queued RADIUS PDU")
		}
	}
}

func TestRADIUSTapPOIPressureAndDestinationRemovalPreserveOrdinarySinks(t *testing.T) {
	p, task, dir := radiusPOIProcessor(t, 1)
	out := p.subscriberManager.Add("ordinary")
	batch, _ := radiusPOIBatch(t, p, task)
	p.processBatch(batch)
	requireRadiusPOIBroadcast(t, out)
	require.Equal(t, uint64(1), liDeliveryClient.Stats().X2Dropped)
	require.Equal(t, int64(1), liDeliveryClient.Stats().QueueDepth)
	liDeliveryClient.RemoveDestination(task.DestinationIDs[0])
	require.NoError(t, liDeliveryMgr.RemoveDestination(task.DestinationIDs[0]))
	require.Equal(t, uint64(2), liDeliveryClient.Stats().X2Dropped)
	require.Zero(t, liDeliveryClient.Stats().QueueDepth)
	// Continued capture after the MDF disappears must keep producing ordinary output.
	batch, _ = radiusPOIBatch(t, p, task)
	p.processBatch(batch)
	requireRadiusPOIBroadcast(t, out)
	assertRadiusPOIOrdinary(t, p, dir, 4)
}

func TestRADIUSTapPOIEncoderFailurePreservesOrdinarySinks(t *testing.T) {
	p, task, dir := radiusPOIProcessor(t, 16)
	// Exhaust the shared sequencer to induce a real encoder error after admission.
	sequencer := x2x3.NewSequencer(1)
	_, err := sequencer.Next(x2x3.SequenceContext{PDUType: x2x3.PDUTypeX2, XID: uuid.New(), CorrelationID: 1})
	require.NoError(t, err)
	old := liRADIUSEncoder
	liRADIUSEncoder = x2x3.NewRADIUSEncoder(sequencer, "", "tap-poi", "tap-poi")
	t.Cleanup(func() { liRADIUSEncoder = old })
	before := liX2Errors.Load()
	out := p.subscriberManager.Add("ordinary")
	batch, _ := radiusPOIBatch(t, p, task)
	p.processBatch(batch)
	requireRadiusPOIBroadcast(t, out)
	require.Equal(t, before+2, liX2Errors.Load())
	require.EqualValues(t, 2, p.radiusLIStats.EncodingErrors)
	require.Zero(t, p.radiusLIStats.QueueAccepted)
	require.Zero(t, liDeliveryClient.Stats().QueueDepth)
	assertRadiusPOIOrdinary(t, p, dir, 2)
}

func TestRADIUSTapPOIExpiredTaskPreservesOrdinarySinks(t *testing.T) {
	p, task, dir := radiusPOIProcessor(t, 16)
	end := time.Now().Add(100 * time.Millisecond)
	implicit := true
	require.NoError(t, p.liManager.ModifyTask(task.XID, &li.TaskModification{EndTime: &end, ImplicitDeactivationAllowed: &implicit}))
	task, err := p.liManager.GetTaskDetails(task.XID)
	require.NoError(t, err)
	out := p.subscriberManager.Add("ordinary")
	batch, _ := radiusPOIBatch(t, p, task)
	// Admission must enforce the deadline even between registry expiry sweeps.
	time.Sleep(time.Until(end) + time.Millisecond)
	p.processBatch(batch)
	requireRadiusPOIBroadcast(t, out)
	require.Zero(t, liDeliveryClient.Stats().QueueDepth, "expired RADIUS authorization must not enqueue X2")
	assertRadiusPOIOrdinary(t, p, dir, 2)
}

type radiusLifecycleAllocator struct{ allocate func() }

func (a radiusLifecycleAllocator) Allocate(*radius.Observation) (uint64, error) {
	a.allocate()
	return 1, nil
}

func (radiusLifecycleAllocator) Close() error { return nil }

func TestRADIUSTapPOITaskChangesDuringEncodingPreserveOrdinarySinks(t *testing.T) {
	for _, change := range []string{"expire", "deactivate", "modify"} {
		t.Run(change, func(t *testing.T) {
			p, task, dir := radiusPOIProcessor(t, 16)
			end := time.Now().Add(100 * time.Millisecond)
			if change == "expire" {
				implicit := true
				require.NoError(t, p.liManager.ModifyTask(task.XID, &li.TaskModification{EndTime: &end, ImplicitDeactivationAllowed: &implicit}))
				var err error
				task, err = p.liManager.GetTaskDetails(task.XID)
				require.NoError(t, err)
			}
			allocated := false
			p.radiusLIAllocator = radiusLifecycleAllocator{allocate: func() {
				allocated = true
				switch change {
				case "expire":
					time.Sleep(time.Until(end) + time.Millisecond)
				case "deactivate":
					require.NoError(t, p.liManager.DeactivateTask(task.XID))
				case "modify":
					newEnd := time.Now().Add(time.Hour)
					require.NoError(t, p.liManager.ModifyTask(task.XID, &li.TaskModification{EndTime: &newEnd}))
				}
			}}
			out := p.subscriberManager.Add("ordinary")
			batch, _ := radiusPOIBatch(t, p, task)
			p.processBatch(batch)
			p.radiusLIAllocator = nil
			require.True(t, allocated, "task change must occur after preliminary admission")
			requireRadiusPOIBroadcast(t, out)
			require.Zero(t, liDeliveryClient.Stats().QueueDepth, "task changes before final admission must suppress X2")
			assertRadiusPOIOrdinary(t, p, dir, 2)
		})
	}
}

func requireRadiusPOIBroadcast(t *testing.T, out <-chan *data.PacketBatch) {
	t.Helper()
	select {
	case batch := <-out:
		require.NotNil(t, batch)
		require.Len(t, batch.Packets, 2)
	case <-time.After(time.Second):
		t.Fatal("ordinary subscriber did not receive RADIUS batch")
	}
}
