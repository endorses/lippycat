//go:build all && li

package processor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	hunterstats "github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

type radiusParityBuffer struct{ buffer *capture.PacketBuffer }

func (b radiusParityBuffer) GetPacketBuffer() *capture.PacketBuffer { return b.buffer }

// A real TLS handshake and protobuf/gRPC stream exercise the source identity
// gate, including verified certificate chains, without binding a capture device.
func radiusParityStream(t *testing.T, p *Processor, origin string, ctx context.Context) data.DataService_StreamPacketsClient {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{origin}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})))
	data.RegisterDataServiceServer(server, p)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done); require.NoError(t, listener.Close()) })
	conn, err := grpc.NewClient("passthrough:///radius-parity", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: origin, MinVersion: tls.VersionTLS12})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	stream, err := data.NewDataServiceClient(conn).StreamPackets(ctx)
	require.NoError(t, err)
	return stream
}

// Both topologies consume identical packet bytes/times and compiled task policy.
// Tap enters through local envelopes; hunt runs the production capture buffer,
// ForwardPackets, asynchronous sender, TLS gRPC ingress and processor pipeline.
func TestRADIUSPhase7TapHunterDecodedDeliveryParity(t *testing.T) {
	f, err := os.Open("../../../testdata/radius/acceptance.pcap")
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for _, name := range []string{"accept_ipv4", "reject_ipv6", "challenge_custom_ipv6", "accounting_ipv4", "accounting_ipv6", "accept_ipv6", "reject_ipv4", "challenge_custom_ipv4"} {
		var packets []*data.CapturedPacket
		for range 2 {
			raw, ci, err := reader.ReadPacketData()
			require.NoError(t, err)
			packets = append(packets, &data.CapturedPacket{Data: raw, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(reader.LinkType()), InterfaceName: "eth0", InterfaceIndex: 1})
		}
		t.Run(name, func(t *testing.T) { radiusParityExchange(t, packets) })
	}
}

func radiusParityExchange(t *testing.T, packets []*data.CapturedPacket) {
	var baselinePDUs []*x2x3.PDU
	var baselineLogs []map[string]any
	var baselineObservations []*radius.Observation
	now := time.Now()
	for i, p := range packets {
		p.TimestampNs = now.Add(time.Duration(i) * time.Millisecond).UnixNano()
	}
	for _, topology := range []string{"tap", "hunter"} {
		t.Run(topology, func(t *testing.T) {
			p, task, dir := radiusPOIProcessor(t, 16)
			port, received := radiusPOIMDF(t)
			require.NoError(t, replaceLIDeliveryDestination(liDeliveryMgr, liDeliveryClient, &li.Destination{DID: task.DestinationIDs[0], Address: "127.0.0.1", Port: port, X2Enabled: true, ProtocolType: "X2Only"}))
			liDeliveryClient.Start()
			fm := li.NewFilterManager(nil)
			ids, err := fm.CreateFiltersForTask(task)
			require.NoError(t, err)
			group, ok := fm.LookupRADIUSGroup(ids[0])
			require.True(t, ok)
			matcher := radiusPOIMatcher{group}
			origin := "tap-poi-local"
			if topology == "hunter" {
				origin = "radius-hunter.test"
			}
			scope := radius.CaptureScope{OriginNodeID: origin, OperatorScope: "operator", ProfileRevision: "v1"}
			out := p.subscriberManager.Add("parity")
			if topology == "tap" {
				processor, err := radius.NewCaptureProcessor(scope, 1812, 1813, 19120)
				require.NoError(t, err)
				defer processor.Close()
				batch := &source.PacketBatch{SourceID: origin, RADIUSSourceTrusted: true}
				for _, raw := range packets {
					packet := radiusParityPacket(raw)
					observation := processor.Process(packet, layers.LinkType(raw.LinkType), "eth0", matcher)
					require.NotNil(t, observation)
					batch.Envelopes = append(batch.Envelopes, &pipeline.PacketEnvelope{Data: raw.Data, LinkType: layers.LinkType(raw.LinkType), CaptureTime: packet.Metadata().Timestamp, CaptureLength: int(raw.CaptureLength), OriginalLength: int(raw.OriginalLength), Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, NodeID: origin, InterfaceName: "eth0", InterfaceIndex: 1}, RADIUS: observation})
				}
				p.processBatch(batch)
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				stream := radiusParityStream(t, p, origin, ctx)
				buffer := capture.NewPacketBuffer(ctx, 8)
				defer buffer.Close()
				forwarder := forwarding.New(forwarding.Config{HunterID: origin, BatchSize: 2, BatchTimeout: time.Second, RADIUSScope: scope, RADIUSMatcher: matcher, RADIUSOnly: true, RADIUSPorts: []uint16{1812, 1813, 19120}}, hunterstats.New(), radiusParityBuffer{buffer}, ctx, make(chan *pipeline.PacketBatch, 2))
				forwarder.SetStream(stream)
				var wg sync.WaitGroup
				wg.Add(1)
				go forwarder.ForwardPackets(&wg)
				defer func() { cancel(); wg.Wait(); forwarder.Wait(); require.NoError(t, forwarder.Close()) }()
				for _, raw := range packets {
					buffer.Send(capture.PacketInfo{Packet: radiusParityPacket(raw), LinkType: layers.LinkType(raw.LinkType), Interface: "eth0"})
				}
				ack, err := stream.Recv()
				require.NoError(t, err)
				require.NotNil(t, ack)
			}
			var broadcast *data.PacketBatch
			select {
			case broadcast = <-out:
			case <-time.After(3 * time.Second):
				t.Fatal("missing ordinary broadcast")
			}
			require.Len(t, broadcast.Packets, 2)
			observations := make([]*radius.Observation, 2)
			for i, raw := range broadcast.Packets {
				observation, err := grpcadapter.RADIUSFromProto(raw)
				require.NoError(t, err)
				require.NotNil(t, observation)
				observations[i] = observation
				require.Equal(t, packets[i].Data, raw.Data)
				require.Equal(t, packets[i].TimestampNs, raw.TimestampNs)
				require.Equal(t, packets[i].LinkType, raw.LinkType)
				require.Equal(t, origin, observation.Scope.OriginNodeID)
				require.Equal(t, "eth0", observation.Scope.SourceID)
				require.Empty(t, raw.MatchedFilterIds)
			}
			require.Len(t, observations[0].Direct, 1)
			require.Equal(t, task.XID.String(), observations[0].Direct[0].TaskID)
			require.Equal(t, task.ActivationGeneration, observations[0].Direct[0].TaskGeneration)
			require.Len(t, observations[0].Direct[0].Criteria, 1)
			require.Equal(t, []byte("alice@example.test"), observations[0].Direct[0].Criteria[0].Value)
			require.Len(t, observations[1].Inherited, 1)
			require.Equal(t, observations[0].Direct, observations[1].Inherited)
			require.Equal(t, radius.AssociationUnique, observations[1].Association.Status)
			require.Equal(t, observations[0].Association.RequestInstanceID, observations[1].Association.RequestInstanceID)
			radiusParityOrdinary(t, p, dir, packets)
			require.EqualValues(t, 2, p.radiusLIStats.QueueAccepted)
			pdus := make([]*x2x3.PDU, 2)
			for i := range pdus {
				select {
				case pdus[i] = <-received:
				case <-time.After(3 * time.Second):
					t.Fatal("missing decoded MDF PDU")
				}
				require.Equal(t, task.XID, pdus[i].Header.XID)
				require.Equal(t, observations[i].Message.Raw, pdus[i].Payload)
			}
			require.NotZero(t, pdus[0].Header.CorrelationID)
			require.Equal(t, pdus[0].Header.CorrelationID, pdus[1].Header.CorrelationID)
			// Independent POIs allocate their own XIDs/correlation IDs. NFID/IPID are
			// deliberately identical here; every decoded attribute must otherwise match.
			for _, pdu := range pdus {
				pdu.Header.XID = uuid.Nil
				pdu.Header.CorrelationID = 0
			}
			logs, err := os.ReadFile(filepath.Join(dir, "radius.log"))
			require.NoError(t, err)
			var records []map[string]any
			for _, line := range strings.Split(strings.TrimSpace(string(logs)), "\n") {
				var record map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				require.Equal(t, origin, record["origin_node_id"])
				for _, key := range []string{"uid", "node_id", "origin_node_id", "capture_epoch", "observation_id", "request_instance_id"} {
					delete(record, key)
				}
				records = append(records, record)
			}
			if topology == "tap" {
				baselinePDUs = pdus
				baselineLogs = records
				baselineObservations = observations
			} else {
				require.Equal(t, baselinePDUs, pdus)
				require.Equal(t, baselineLogs, records)
				for i, o := range observations {
					require.Equal(t, baselineObservations[i].Message, o.Message)
					require.Equal(t, baselineObservations[i].Association.Status, o.Association.Status)
					require.Equal(t, baselineObservations[i].Endpoints, o.Endpoints)
				}
			}
		})
	}
}

func radiusParityPacket(raw *data.CapturedPacket) gopacket.Packet {
	packet := gopacket.NewPacket(raw.Data, layers.LinkType(raw.LinkType), gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, raw.TimestampNs), CaptureLength: int(raw.CaptureLength), Length: int(raw.OriginalLength)}
	return packet
}

// Upstream forwarding preserves original provenance but the relay certificate
// proves only the relay's identity. It must not authorize another origin's X2.
func TestRADIUSPhase7RelayPreservesOrdinaryWithoutOriginAuthority(t *testing.T) {
	p, task, dir := radiusPOIProcessor(t, 16)
	batch, observations := radiusPOIBatch(t, p, task)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := radiusParityStream(t, p, "relay.test", ctx)
	out := p.subscriberManager.Add("upstream-ordinary")
	// The upstream manager forwards this same protobuf contract unchanged (see
	// upstream.TestRADIUSUpstreamPreservesCaptureOrigin). Exercise its receiving
	// side with the real TLS peer identity and protobuf serialization here.
	wire, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	require.NoError(t, stream.Send(wire))
	_, err = stream.Recv()
	require.NoError(t, err)
	select {
	case broadcast := <-out:
		require.Equal(t, batch.SourceID, broadcast.HunterId)
		require.Len(t, broadcast.Packets, 2)
		for i, packet := range broadcast.Packets {
			got, err := grpcadapter.RADIUSFromProto(packet)
			require.NoError(t, err)
			observations[i].Association.RequestFirstSeen = observations[i].Association.RequestFirstSeen.UTC()
			require.Equal(t, observations[i], got)
			require.Equal(t, wire.Packets[i].Data, packet.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relayed ordinary packets missing")
	}
	require.Zero(t, liDeliveryClient.Stats().QueueDepth)
	require.Zero(t, p.radiusLIStats.QueueAccepted)
	assertRadiusPOIOrdinary(t, p, dir, 2)
}

func radiusParityOrdinary(t *testing.T, p *Processor, dir string, packets []*data.CapturedPacket) {
	t.Helper()
	require.NoError(t, p.Shutdown())
	log, err := os.ReadFile(filepath.Join(dir, "radius.log"))
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(log)), "\n"), len(packets))
	f, err := os.Open(filepath.Join(dir, "ordinary.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for _, packet := range packets {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, packet.Data, raw)
		require.Equal(t, layers.LinkType(packet.LinkType), reader.LinkType())
		require.Equal(t, time.Unix(0, packet.TimestampNs).UTC().Truncate(time.Microsecond), ci.Timestamp)
	}
}
