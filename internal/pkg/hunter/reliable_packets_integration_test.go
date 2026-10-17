//go:build all

package hunter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/hunter/packetforwarding"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/endorses/lippycat/internal/pkg/packetspool"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestReliableRawRejectsUnwiredHTTPKeylog(t *testing.T) {
	for _, key := range []string{"hunter.http.tls_keylog", "hunter.http.tls_keylog_pipe", "http.tls_keylog", "http.tls_decryption_enabled"} {
		t.Run(key, func(t *testing.T) {
			previous := viper.Get(key)
			t.Cleanup(func() { viper.Set(key, previous) })
			if key == "http.tls_decryption_enabled" {
				viper.Set(key, true)
			} else {
				viper.Set(key, "keylog")
			}
			h := &Hunter{config: Config{Packets: packetforwarding.Config{DeliveryProfile: "reliable", DestinationID: "receiver", TrustedCert: "receipt.pem", Spool: packetforwarding.SpoolConfig{Directory: "spool", Protection: "private"}}}}
			require.ErrorContains(t, h.configureReliablePackets(), "matched-session key attachment")
		})
	}
}

type legacyRawReceiver struct {
	management.UnimplementedManagementServiceServer
}

func (*legacyRawReceiver) RegisterHunter(_ context.Context, request *management.HunterRegistration) (*management.RegistrationResponse, error) {
	return &management.RegistrationResponse{Accepted: true, AssignedId: request.HunterId, AcceptedForwardingMode: management.ForwardingMode_FORWARDING_MODE_PACKETS}, nil
}

func rawIntegrationCertificate(t *testing.T) (tls.Certificate, string, string, *x509.CertPool) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"edge", "receiver"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certFile, keyFile := filepath.Join(t.TempDir(), "certificate.pem"), filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certFile, keyFile, pool
}

func offlineRawPacket(t *testing.T, sequence byte) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 23456}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload{sequence}))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(sequence)*1000000), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return capture.PacketInfo{Packet: packet, Interface: "eth0", LinkType: layers.LinkTypeEthernet}
}

func TestReliableRawOfflineProductionRestartAndReceiverReceipt(t *testing.T) {
	pair, certificate, key, roots := rawIntegrationCertificate(t)
	legacyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	legacy := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})))
	management.RegisterManagementServiceServer(legacy, &legacyRawReceiver{})
	legacyDone := make(chan error, 1)
	go func() { legacyDone <- legacy.Serve(legacyListener) }()
	t.Cleanup(func() {
		legacy.Stop()
		if err := <-legacyDone; !errors.Is(err, grpc.ErrServerStopped) {
			require.NoError(t, err)
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	delivery := packetforwarding.Config{DeliveryProfile: "reliable", AckScope: "receiver", DestinationID: "receiver", TrustedCert: certificate, Spool: packetforwarding.SpoolConfig{Directory: filepath.Join(t.TempDir(), "origin"), Protection: "private", MaxBytes: 1 << 20, MaxRecords: 16}}
	spoolConfig, err := delivery.SpoolConfig("edge")
	require.NoError(t, err)
	require.NoError(t, packetspool.Initialize(spoolConfig))
	config := Config{HunterID: "edge", Processors: []failover.Endpoint{{Address: address}}, Failover: failover.Config{AttemptTimeout: 100 * time.Millisecond, ReconnectAttempts: 0, RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}, BufferSize: 16, BatchSize: 1, BatchTimeout: 10 * time.Millisecond, TLSEnabled: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, NoFilterPolicy: "allow", Packets: delivery}
	config.Processors = append([]failover.Endpoint{{Address: legacyListener.Addr().String()}}, config.Processors...)
	h, err := New(config)
	require.NoError(t, err)
	// An empty interface list opens no capture device. Feed the production
	// capture queue with synthetic packets; no external test PCAP is required.
	require.NoError(t, h.captureManager.PrepareBuffer())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Start(ctx) }()
	var expected [][]byte
	for i := byte(1); i <= 3; i++ {
		packet := offlineRawPacket(t, i)
		expected = append(expected, append([]byte(nil), packet.Packet.Data()...))
		require.True(t, h.captureManager.GetPacketBuffer().Send(packet))
	}
	require.Eventually(t, func() bool { return h.packetSpool.Status().PendingRecords == 3 }, 5*time.Second, 5*time.Millisecond, "disconnected capture must keep producing durable raw records")
	identity := h.packetSpool.Identity()
	cancel()
	require.NoError(t, <-done)
	require.NoError(t, h.Close())
	// Reopening preserves the original producer session and unacknowledged work.
	h, err = New(config)
	require.NoError(t, err)
	require.Equal(t, identity, h.packetSpool.Identity())
	store := packetreceipt.StoreConfig{Directory: filepath.Join(t.TempDir(), "receiver"), DestinationID: "receiver", Protection: "private", MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxSessions: 4, MaxRecords: 16, MaxLossRanges: 4}
	require.NoError(t, packetreceipt.Initialize(store))
	output := filepath.Join(t.TempDir(), "received.pcap")
	p, err := processor.New(processor.Config{ProcessorID: "receiver", ListenAddr: address, FilterFile: filepath.Join(t.TempDir(), "filters", "filters.yaml"), WriteFile: output, TLSEnabled: true, TLSClientAuth: true, TLSCAFile: certificate, TLSCertFile: certificate, TLSKeyFile: key, PacketCustody: processor.PacketCustodyConfig{Enabled: true, Store: store, AuthorityID: "receiver", SigningCertificate: certificate, SigningKey: key}})
	require.NoError(t, err)
	processorCtx, stopProcessor := context.WithCancel(context.Background())
	processorDone := make(chan error, 1)
	go func() { processorDone <- p.Start(processorCtx) }()
	t.Cleanup(func() { stopProcessor(); require.NoError(t, <-processorDone) })
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- h.Start(ctx) }()
	hunterStopped := false
	t.Cleanup(func() {
		if !hunterStopped {
			cancel()
			require.NoError(t, <-done)
		}
		require.NoError(t, h.Close())
	})
	require.Eventually(t, func() bool {
		status := h.packetSpool.Status()
		return status.PendingRecords == 0 && status.AckedSequence == 3
	}, 10*time.Second, 5*time.Millisecond)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots})))
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	client := management.NewManagementServiceClient(conn)
	require.Eventually(t, func() bool {
		query, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		status, err := client.GetHunterStatus(query, &management.StatusRequest{})
		return err == nil && status.ProcessorStats.TotalPacketsReceived == 3
	}, 5*time.Second, 5*time.Millisecond)
	// Graceful output shutdown precedes file inspection. The registered cleanup
	// consumes Start's completion, so only initiate shutdown here.
	cancel()
	require.NoError(t, <-done)
	hunterStopped = true
	require.NoError(t, p.Shutdown())
	file, err := os.Open(output)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	for i, want := range expected {
		got, info, err := reader.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.Equal(t, time.Unix(1700000000, int64(i+1)*1000000).UnixNano(), info.Timestamp.UnixNano())
	}
}
