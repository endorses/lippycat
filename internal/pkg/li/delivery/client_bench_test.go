//go:build li

package delivery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
)

// generateBenchCert generates a self-signed certificate for benchmarking.
func generateBenchCert(b *testing.B) (certPEM, keyPEM []byte) {
	b.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(b, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

// startBenchTLSServer starts a high-performance TLS server for benchmarking.
type benchServer struct {
	listener     net.Listener
	port         int
	bytesRecv    int64
	pdusRecv     int64
	conns        int64
	done         chan struct{}
	wg           sync.WaitGroup
	shutdownOnce sync.Once
}

func startBenchTLSServer(b *testing.B, certPEM, keyPEM []byte) *benchServer {
	b.Helper()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(b, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(b, err)

	port := listener.Addr().(*net.TCPAddr).Port

	bs := &benchServer{
		listener: listener,
		port:     port,
		done:     make(chan struct{}),
	}

	bs.wg.Add(1)
	go bs.accept()

	return bs
}

func (bs *benchServer) accept() {
	defer bs.wg.Done()

	for {
		conn, err := bs.listener.Accept()
		if err != nil {
			select {
			case <-bs.done:
				return
			default:
				continue
			}
		}

		atomic.AddInt64(&bs.conns, 1)
		bs.wg.Add(1)
		go bs.handleConn(conn)
	}
}

func (bs *benchServer) handleConn(conn net.Conn) {
	defer bs.wg.Done()
	defer conn.Close()

	buf := make([]byte, 32*1024) // 32KB buffer for high throughput.
	for {
		select {
		case <-bs.done:
			return
		default:
		}

		// Set read deadline to allow periodic done checks.
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		atomic.AddInt64(&bs.bytesRecv, int64(n))
		atomic.AddInt64(&bs.pdusRecv, 1)
	}
}

func (bs *benchServer) close() {
	bs.shutdownOnce.Do(func() {
		close(bs.done)
		bs.listener.Close()
		bs.wg.Wait()
	})
}

// BenchmarkClient_SendX2 benchmarks async X2 delivery throughput.
func BenchmarkClient_SendX2(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)
	server := startBenchTLSServer(b, certPEM, keyPEM)
	defer server.close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
	managerConfig.DialTimeout = 2 * time.Second
	managerConfig.MaxPoolSize = 8

	manager, err := NewManager(managerConfig)
	require.NoError(b, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.port,
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(b, err)

	// Wait for connection.
	time.Sleep(200 * time.Millisecond)
	require.True(b, manager.IsConnected(did))

	clientConfig := DefaultClientConfig()
	clientConfig.QueueSize = 100000
	clientConfig.Workers = 4
	clientConfig.BatchSize = 100
	clientConfig.BatchTimeout = 5 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	// Test PDU (typical X2 IRI size).
	pdu := make([]byte, 256)
	rand.Read(pdu)

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := client.SendX2(xid, destIDs, pdu)
		if err != nil {
			b.Fatalf("SendX2 failed: %v", err)
		}
	}

	// Wait for delivery to complete.
	for client.QueueDepth() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	b.StopTimer()

	stats := client.Stats()
	b.ReportMetric(float64(stats.X2Sent), "sent")
	b.ReportMetric(float64(stats.X2Dropped), "dropped")
}

// BenchmarkClient_SendX3 benchmarks async X3 delivery throughput.
func BenchmarkClient_SendX3(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)
	server := startBenchTLSServer(b, certPEM, keyPEM)
	defer server.close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
	managerConfig.MaxPoolSize = 8

	manager, err := NewManager(managerConfig)
	require.NoError(b, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.port,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(b, err)

	time.Sleep(200 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.QueueSize = 100000
	clientConfig.Workers = 4
	clientConfig.BatchSize = 100
	clientConfig.BatchTimeout = 5 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	// Test PDU (typical X3 CC size with G.711 payload).
	pdu := make([]byte, 256) // ~100 byte header + 160 byte G.711 payload
	rand.Read(pdu)

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := client.SendX3(xid, destIDs, pdu)
		if err != nil {
			b.Fatalf("SendX3 failed: %v", err)
		}
	}

	// Wait for delivery.
	for client.QueueDepth() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	b.StopTimer()

	stats := client.Stats()
	b.ReportMetric(float64(stats.X3Sent), "sent")
}

// BenchmarkClient_SendX3_HighVolume benchmarks X3 delivery under high-volume RTP load.
func BenchmarkClient_SendX3_HighVolume(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)
	server := startBenchTLSServer(b, certPEM, keyPEM)
	defer server.close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
	managerConfig.MaxPoolSize = 16

	manager, err := NewManager(managerConfig)
	require.NoError(b, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.port,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(b, err)

	time.Sleep(200 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.QueueSize = 500000
	clientConfig.Workers = 8
	clientConfig.BatchSize = 200
	clientConfig.BatchTimeout = 2 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	// G.711 20ms PDU.
	pdu := make([]byte, 260)
	rand.Read(pdu)

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	b.ReportAllocs()
	b.ResetTimer()

	start := time.Now()
	for i := 0; i < b.N; i++ {
		_ = client.SendX3(xid, destIDs, pdu)
	}

	// Wait for delivery.
	for client.QueueDepth() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	elapsed := time.Since(start)

	b.StopTimer()

	stats := client.Stats()
	pduPerSec := float64(stats.X3Sent) / elapsed.Seconds()

	b.ReportMetric(pduPerSec, "pdu/s")
	b.ReportMetric(pduPerSec/50, "calls@G.711")
}

// BenchmarkClient_SendX2_Parallel benchmarks parallel X2 delivery.
func BenchmarkClient_SendX2_Parallel(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)
	server := startBenchTLSServer(b, certPEM, keyPEM)
	defer server.close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
	managerConfig.MaxPoolSize = 16

	manager, err := NewManager(managerConfig)
	require.NoError(b, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.port,
		X2Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(b, err)

	time.Sleep(200 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.QueueSize = 500000
	clientConfig.Workers = 8
	clientConfig.BatchSize = 100
	clientConfig.BatchTimeout = 5 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	pdu := make([]byte, 256)
	rand.Read(pdu)

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = client.SendX2(xid, destIDs, pdu)
		}
	})

	// Wait for delivery.
	for client.QueueDepth() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}

// BenchmarkClient_SendX3_Parallel benchmarks parallel X3 delivery.
func BenchmarkClient_SendX3_Parallel(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)
	server := startBenchTLSServer(b, certPEM, keyPEM)
	defer server.close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	managerConfig := DefaultConfig()
	managerConfig.MaxPoolSize = 16

	manager, err := NewManager(managerConfig)
	require.NoError(b, err)
	defer manager.Stop()

	did := uuid.New()
	err = manager.AddDestination(&li.Destination{
		DID:       did,
		Address:   "127.0.0.1",
		Port:      server.port,
		X3Enabled: true,
		TLSConfig: &tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	})
	require.NoError(b, err)

	time.Sleep(200 * time.Millisecond)

	clientConfig := DefaultClientConfig()
	clientConfig.QueueSize = 500000
	clientConfig.Workers = 8
	clientConfig.BatchSize = 100
	clientConfig.BatchTimeout = 5 * time.Millisecond

	client := NewClient(manager, clientConfig)
	client.Start()
	defer client.Stop()

	pdu := make([]byte, 260)
	rand.Read(pdu)

	xid := uuid.New()
	destIDs := []uuid.UUID{did}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = client.SendX3(xid, destIDs, pdu)
		}
	})

	// Wait for delivery.
	for client.QueueDepth() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}

// BenchmarkClient_SendToMultipleDestinations benchmarks delivery to multiple destinations.
func BenchmarkClient_SendToMultipleDestinations(b *testing.B) {
	certPEM, keyPEM := generateBenchCert(b)

	destCounts := []int{1, 2, 4, 8}

	for _, numDests := range destCounts {
		b.Run(fmt.Sprintf("dests_%d", numDests), func(b *testing.B) {
			servers := make([]*benchServer, numDests)
			destIDs := make([]uuid.UUID, numDests)

			for i := 0; i < numDests; i++ {
				servers[i] = startBenchTLSServer(b, certPEM, keyPEM)
				defer servers[i].close()
			}

			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(certPEM)

			managerConfig := DefaultConfig()
			managerConfig.MaxPoolSize = 4

			manager, err := NewManager(managerConfig)
			require.NoError(b, err)
			defer manager.Stop()

			for i := 0; i < numDests; i++ {
				did := uuid.New()
				destIDs[i] = did
				err = manager.AddDestination(&li.Destination{
					DID:       did,
					Address:   "127.0.0.1",
					Port:      servers[i].port,
					X2Enabled: true,
					X3Enabled: true,
					TLSConfig: &tls.Config{
						RootCAs:            certPool,
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS12,
					},
				})
				require.NoError(b, err)
			}

			time.Sleep(300 * time.Millisecond)

			clientConfig := DefaultClientConfig()
			clientConfig.QueueSize = 100000
			clientConfig.Workers = 4
			clientConfig.BatchSize = 50
			clientConfig.BatchTimeout = 5 * time.Millisecond

			client := NewClient(manager, clientConfig)
			client.Start()
			defer client.Stop()

			pdu := make([]byte, 256)
			rand.Read(pdu)

			xid := uuid.New()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = client.SendX2(xid, destIDs, pdu)
			}

			// Wait for delivery.
			for client.QueueDepth() > 0 {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)

			b.StopTimer()

			stats := client.Stats()
			// Each PDU sent to N destinations = N sends recorded.
			b.ReportMetric(float64(stats.X2Sent)/float64(b.N), "sends/pdu")
		})
	}
}

// BenchmarkClient_SequenceNumbering benchmarks sequence number generation overhead.
func BenchmarkClient_SequenceNumbering(b *testing.B) {
	manager, err := NewManager(DefaultConfig())
	require.NoError(b, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid := uuid.New()
	did := uuid.New()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = client.NextSequence(xid, did)
	}
}

// BenchmarkClient_SequenceNumbering_ManyStreams benchmarks sequence numbering with many streams.
func BenchmarkClient_SequenceNumbering_ManyStreams(b *testing.B) {
	manager, err := NewManager(DefaultConfig())
	require.NoError(b, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	// Pre-generate XIDs and DIDs.
	numXIDs := 100
	numDIDs := 10
	xids := make([]uuid.UUID, numXIDs)
	dids := make([]uuid.UUID, numDIDs)

	for i := 0; i < numXIDs; i++ {
		xids[i] = uuid.New()
	}
	for i := 0; i < numDIDs; i++ {
		dids[i] = uuid.New()
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		xid := xids[i%numXIDs]
		did := dids[i%numDIDs]
		_ = client.NextSequence(xid, did)
	}
}

// BenchmarkClient_SequenceNumbering_Parallel benchmarks concurrent sequence numbering.
func BenchmarkClient_SequenceNumbering_Parallel(b *testing.B) {
	manager, err := NewManager(DefaultConfig())
	require.NoError(b, err)
	defer manager.Stop()

	client := NewClient(manager, DefaultClientConfig())

	xid := uuid.New()
	did := uuid.New()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = client.NextSequence(xid, did)
		}
	})
}
