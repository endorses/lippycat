//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	packetpcap "github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type rawCustodyReceiptDropStream struct {
	grpc.ServerStream
	drop    *atomic.Bool
	receipt chan<- *data.RawPacketReceipt
}

func (s *rawCustodyReceiptDropStream) SendMsg(message any) error {
	control, ok := message.(*data.ReliablePacketControl)
	if ok && control.GetReceipt().GetSequence() > 0 && s.drop.CompareAndSwap(false, true) {
		// This production response is constructed only after durable Accept.
		// The client sees a transport failure instead of the signed receipt.
		s.receipt <- proto.Clone(control.Receipt).(*data.RawPacketReceipt)
		return status.Error(codes.Unavailable, "injected receipt loss after receiver commit")
	}
	return s.ServerStream.SendMsg(message)
}

func serveRawCustodyWithLostReceipt(t *testing.T, p *Processor, pair tls.Certificate, roots *x509.CertPool, receipt chan<- *data.RawPacketReceipt) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var drop atomic.Bool
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})),
		grpc.StreamInterceptor(func(service any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			return handler(service, &rawCustodyReceiptDropStream{ServerStream: stream, drop: &drop, receipt: receipt})
		}),
	)
	p.registerGRPCServices(server)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	stop := sync.OnceFunc(func() {
		server.Stop()
		if err := <-done; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func rawCustodyRestartBatch(t *testing.T, id *data.RawPacketIdentity) *data.PacketBatch {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 41000, DstPort: 41001}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, gopacket.Payload("retained original capture")))
	raw := buffer.Bytes()
	at := time.Unix(1700000000, 123456000).UnixNano()
	return &data.PacketBatch{HunterId: id.SourceId, ProducerSessionId: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: 1, TimestampNs: at,
		Packets: []*data.CapturedPacket{{Data: raw, TimestampNs: at, CaptureLength: uint32(len(raw)), OriginalLength: uint32(len(raw)), LinkType: uint32(layers.LinkTypeEthernet), InterfaceName: "private-network0", ObservationDomain: 7, ObservationDomainKnown: true}},
	}
}

func requireRawCustodyOutput(t *testing.T, got, original *data.PacketBatch) {
	t.Helper()
	require.Equal(t, original.HunterId, got.HunterId)
	require.Equal(t, original.ProducerSessionId, got.ProducerSessionId)
	require.Equal(t, original.CaptureEpoch, got.CaptureEpoch)
	require.Equal(t, original.Sequence, got.Sequence)
	require.Len(t, got.Packets, 1)
	want, packet := original.Packets[0], got.Packets[0]
	require.Equal(t, want.Data, packet.Data)
	require.Equal(t, want.TimestampNs, packet.TimestampNs)
	require.Equal(t, want.InterfaceName, packet.InterfaceName)
	require.Equal(t, want.ObservationDomain, packet.ObservationDomain)
	require.Equal(t, want.ObservationDomainKnown, packet.ObservationDomainKnown)
}

func requireRawCustodyPCAP(t *testing.T, path string, original *data.PacketBatch) {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	got, info, err := reader.ReadPacketData()
	require.NoError(t, err)
	packet := original.Packets[0]
	require.Equal(t, packet.Data, got)
	require.Equal(t, packet.TimestampNs, info.Timestamp.UnixNano())
	require.EqualValues(t, packet.CaptureLength, info.CaptureLength)
	require.EqualValues(t, packet.OriginalLength, info.Length)
	require.Equal(t, layers.LinkType(packet.LinkType), reader.LinkType())
	_, _, err = reader.ReadPacketData()
	require.ErrorIs(t, err, io.EOF, "each processing attempt writes exactly one packet")
}

func TestRawCustodyRestartAfterOutputBeforeCompletionCheckpoint(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	store := packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "central", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxRecords: 8, MaxSessions: 4, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(store))
	config := Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t), TLSEnabled: true, TLSClientAuth: true, TLSCAFile: pki.caFile, TLSCertFile: certificate, TLSKeyFile: key,
		PacketCustody: PacketCustodyConfig{Enabled: true, Store: store, AuthorityID: "central", SigningCertificate: certificate, SigningKey: key},
	}
	original, err := newTestProcessor(t, config)
	require.NoError(t, err)
	address := serveRelayTestProcessor(t, original, pair, pki.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "original-session", CaptureEpoch: "original-epoch", DestinationId: "central", AckScope: "receiver"}
	batch := rawCustodyRestartBatch(t, id)
	stream := openReliableMediaStream(t, ctx, address, pki, id)
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	sendReliableMediaBatch(t, stream, verifier, id, batch, true)
	require.NoError(t, stream.CloseSend())
	_, err = stream.Recv()
	require.ErrorIs(t, err, io.EOF)

	pending, err := original.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(id, pending[0].Identity))
	require.True(t, proto.Equal(batch, pending[0].Batch))

	// Select the crash boundary by dispatching the real pending record through
	// production processing without starting its checkpointing worker. This
	// composes the existing custody/processing APIs without a public fault hook.
	firstPath := filepath.Join(t.TempDir(), "before-restart.pcap")
	original.pcapWriter, err = packetpcap.NewWriter(firstPath)
	require.NoError(t, err)
	original.pcapWriter.Start(ctx)
	firstOutput := original.subscriberManager.Add("before-restart")
	dispatch, err := source.FromProtoBatchE(pending[0].Batch)
	require.NoError(t, err)
	dispatch.HistoricalReplay = true
	original.processBatch(dispatch)
	select {
	case output := <-firstOutput:
		requireRawCustodyOutput(t, output, batch)
	case <-ctx.Done():
		t.Fatal("first processing attempt did not produce external output")
	}
	original.pcapWriter.Stop()
	requireRawCustodyPCAP(t, firstPath, batch)
	require.Zero(t, original.packetCustody.replayed.Load())
	require.Equal(t, 1, original.packetCustody.store.Stats().PendingRecords, "output has happened, but no processing checkpoint was committed")
	require.NoError(t, original.Shutdown())

	restarted, err := newTestProcessor(t, config)
	require.NoError(t, err)
	require.Empty(t, restarted.packetCustody.current, "restart restores captured evidence without current capture authority")
	pending, err = restarted.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(id, pending[0].Identity))
	require.True(t, proto.Equal(batch, pending[0].Batch))
	secondPath := filepath.Join(t.TempDir(), "after-restart.pcap")
	restarted.pcapWriter, err = packetpcap.NewWriter(secondPath)
	require.NoError(t, err)
	restarted.pcapWriter.Start(ctx)
	secondOutput := restarted.subscriberManager.Add("after-restart")
	restarted.startPacketCustody(ctx)
	select {
	case output := <-secondOutput:
		requireRawCustodyOutput(t, output, batch)
	case <-ctx.Done():
		t.Fatal("recovered custody did not repeat its uncheckpointed output")
	}
	require.Eventually(t, func() bool { return restarted.packetCustody.replayed.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.Zero(t, restarted.packetCustody.store.Stats().PendingRecords)
	require.Equal(t, 1, restarted.packetCustody.store.Stats().HistoryRecords)
	restarted.pcapWriter.Stop()
	requireRawCustodyPCAP(t, secondPath, batch)
	requireRawCustodyPCAP(t, firstPath, batch)
	require.NoError(t, restarted.Shutdown())

	// Once completion is durably checkpointed, restart preserves the receipt
	// history: an ingress retry is acknowledged without a third processing attempt.
	completed, err := packetreceipt.Open(store)
	require.NoError(t, err)
	defer func() { require.NoError(t, completed.Close()) }()
	_, duplicate, err := completed.Accept(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch})
	require.NoError(t, err)
	require.True(t, duplicate)
	pending, err = completed.Pending(1)
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestRawCustodyCommitBeforeLostReceiptRecoversAndDeduplicates(t *testing.T) {
	pki := newRelayTestPKI(t)
	pair, certificate, key := pki.identity(t, "central")
	store := packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "custody"), DestinationID: "central", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxRecords: 8, MaxSessions: 4, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(store))
	config := Config{ProcessorID: "central", ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t), TLSEnabled: true, TLSClientAuth: true, TLSCAFile: pki.caFile, TLSCertFile: certificate, TLSKeyFile: key,
		PacketCustody: PacketCustodyConfig{Enabled: true, Store: store, AuthorityID: "central", SigningCertificate: certificate, SigningKey: key},
	}
	original, err := newTestProcessor(t, config)
	require.NoError(t, err)
	lostReceipts := make(chan *data.RawPacketReceipt, 1)
	address, stopOriginal := serveRawCustodyWithLostReceipt(t, original, pair, pki.pool, lostReceipts)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id := &data.RawPacketIdentity{SourceId: "hunter-a", ProducerSessionId: "retained-session", CaptureEpoch: "retained-epoch", DestinationId: "central", AckScope: "receiver"}
	batch := rawCustodyRestartBatch(t, id)
	stream := openReliableMediaStream(t, ctx, address, pki, id)
	require.NoError(t, stream.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch, CurrentCapture: true}))
	_, err = stream.Recv()
	require.Equal(t, codes.Unavailable, status.Code(err), "the committed receipt must not reach the client")
	var lost *data.RawPacketReceipt
	select {
	case lost = <-lostReceipts:
	case <-ctx.Done():
		t.Fatal("the receiver did not reach the commit-before-receipt boundary")
	}
	verifier, err := packetreceipt.LoadVerifier("central", certificate)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(lost, id, batch))
	pending, err := original.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(id, pending[0].Identity))
	require.True(t, proto.Equal(batch, pending[0].Batch))
	require.Zero(t, original.packetsReceived.Load(), "the receiver has custody without having dispatched the capture")
	stopOriginal()
	require.NoError(t, original.Shutdown())

	restarted, err := newTestProcessor(t, config)
	require.NoError(t, err)
	pending, err = restarted.packetCustody.store.Pending(1)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(id, pending[0].Identity))
	require.True(t, proto.Equal(batch, pending[0].Batch))
	address = serveRelayTestProcessor(t, restarted, pair, pki.pool)
	retry := openReliableMediaStream(t, ctx, address, pki, id)
	require.NoError(t, retry.Send(&data.ReliablePacketMessage{ProtocolVersion: 1, Identity: id, Batch: batch, CurrentCapture: true}))
	replayed, err := retry.Recv()
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(replayed.Receipt, id, batch))
	require.True(t, proto.Equal(lost, replayed.Receipt), "the Ed25519 fixture reproduces the same signed selective receipt after recovery")
	require.EqualValues(t, 1, restarted.packetCustody.duplicates.Load())
	require.Equal(t, 1, restarted.packetCustody.store.Stats().PendingRecords, "receipt retry must not create another pending dispatch")
	require.Equal(t, 1, restarted.packetCustody.store.Stats().HistoryRecords)
	require.Empty(t, restarted.packetCustody.current, "retry cannot upgrade recovered capture into current authority")
	require.NoError(t, retry.CloseSend())
	_, err = retry.Recv()
	require.ErrorIs(t, err, io.EOF)

	outputPath := filepath.Join(t.TempDir(), "recovered-once.pcap")
	restarted.pcapWriter, err = packetpcap.NewWriter(outputPath)
	require.NoError(t, err)
	restarted.pcapWriter.Start(ctx)
	output := restarted.subscriberManager.Add("recovered-once")
	restarted.startPacketCustody(ctx)
	select {
	case got := <-output:
		requireRawCustodyOutput(t, got, batch)
	case <-ctx.Done():
		t.Fatal("recovered capture did not reach the output")
	}
	require.Eventually(t, func() bool { return restarted.packetCustody.replayed.Load() == 1 }, 5*time.Second, time.Millisecond)
	require.EqualValues(t, 1, restarted.packetsReceived.Load())
	require.Zero(t, restarted.packetCustody.store.Stats().PendingRecords)
	require.Empty(t, output, "the retry must not create another subscriber effect")
	restarted.pcapWriter.Stop()
	requireRawCustodyPCAP(t, outputPath, batch)
}
