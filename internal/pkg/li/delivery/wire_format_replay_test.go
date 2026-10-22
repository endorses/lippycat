//go:build li && linux

package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Read the original wire bytes using each frame's lengths: format migration can
// change the header size, and a receiver must accept the mixed stream as-is.
func wireFormatMDF(t *testing.T, certPEM, keyPEM []byte) (int, <-chan []byte) {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	frames := make(chan []byte, 32)
	var mu sync.Mutex
	var workers sync.WaitGroup
	connections := make(map[net.Conn]struct{})
	closed := false
	workers.Add(1)
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
				if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Logf("close fixture connection: %v", err)
				}
				return
			}
			connections[connection] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer func() {
					if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Logf("close fixture connection: %v", err)
					}
					mu.Lock()
					delete(connections, connection)
					mu.Unlock()
				}()
				if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Errorf("set fixture deadline: %v", err)
					return
				}
				for {
					header := make([]byte, 40)
					if _, err := io.ReadFull(connection, header); err != nil {
						return // Health and delivery connections close independently.
					}
					length := uint64(binary.BigEndian.Uint32(header[4:])) + uint64(binary.BigEndian.Uint32(header[8:]))
					if length < 40 || length > 1<<20 {
						t.Errorf("invalid fixture frame length: %d", length)
						return
					}
					frame := make([]byte, int(length))
					copy(frame, header)
					if _, err := io.ReadFull(connection, frame[40:]); err != nil {
						t.Errorf("read fixture frame: %v", err)
						return
					}
					frames <- frame
				}
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		for connection := range connections {
			if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Logf("close active fixture connection: %v", err)
			}
		}
		mu.Unlock()
		require.NoError(t, listener.Close())
		workers.Wait()
	})
	return listener.Addr().(*net.TCPAddr).Port, frames
}

func wireFormatReplayProduct(t *testing.T, protocol string, sequencer *x2x3.Sequencer, xid uuid.UUID, captured time.Time, timestampFormat x2x3.TimestampFormat, typed bool) []byte {
	t.Helper()
	var product *x2x3.PDU
	var err error
	target := li.TargetIdentity{Type: li.TargetTypeSIPURI, Value: "sip:alice@example.invalid"}
	switch protocol {
	case "sip":
		encoder, createErr := x2x3.NewX2EncoderWithTimestampFormat(sequencer, "format-domain", "stable-processor", timestampFormat)
		require.NoError(t, createErr)
		raw := []byte("INVITE sip:bob@example.invalid SIP/2.0\r\nCall-ID: wire-format-replay\r\nFrom: <sip:alice@example.invalid>;tag=a\r\nTo: <sip:bob@example.invalid>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
		packet := &types.PacketDisplay{Timestamp: captured, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "5060", DstPort: "5060", RawData: raw, VoIPData: &types.VoIPMetadata{CallID: "wire-format-replay", Method: "INVITE", RawSIP: raw}}
		product, err = encoder.EncodeIRI(packet, xid)
	case "rtp":
		encoder, createErr := x2x3.NewX3EncoderWithTimestampFormat(sequencer, "format-domain", "stable-processor", timestampFormat)
		require.NoError(t, createErr)
		raw := make([]byte, 16)
		raw[0] = 0x80
		binary.BigEndian.PutUint32(raw[8:], 42)
		copy(raw[12:], "test")
		packet := &types.PacketDisplay{Timestamp: captured, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "2000", DstPort: "3000", Transport: 17, RawData: raw, VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 42, CallID: "wire-format-replay"}}
		product, err = encoder.EncodeCC(packet, xid)
	case "radius":
		encoder, createErr := x2x3.NewRADIUSEncoderWithTimestampFormat(sequencer, "format-domain", "stable-processor", "stable-processor", timestampFormat)
		require.NoError(t, createErr)
		raw := make([]byte, 20)
		raw[0], raw[1], raw[3] = 1, 7, 20
		message, decodeErr := radius.Decode(raw)
		require.NoError(t, decodeErr)
		observation := &radius.Observation{Message: message, Capture: radius.CaptureInfo{Timestamp: captured}, Endpoints: radius.Endpoints{IPFamily: 4, Source: netip.MustParseAddrPort("192.0.2.1:2000"), Destination: netip.MustParseAddrPort("192.0.2.2:3000")}}
		product, err = encoder.Encode(observation, xid, 42)
		target = li.TargetIdentity{Type: li.TargetTypeNAI, Value: "alice@example.invalid"}
	default:
		t.Fatalf("unknown synthetic protocol: %s", protocol)
	}
	require.NoError(t, err)
	if typed {
		value, err := li.MarshalTargetIdentifier(target)
		require.NoError(t, err)
		product.AddAttribute(x2x3.NewAttributeBuilder().MatchedTargetIdentifier(value))
	} else if protocol != "radius" {
		product.AddAttribute(x2x3.NewAttributeBuilder().MatchedTargetIdentifier(target.Value))
	}
	data, err := product.MarshalBinary()
	require.NoError(t, err)
	return data
}

func TestWireFormatJournalMixedReplayLiveAndRollback(t *testing.T) {
	for _, protocol := range []string{"sip", "rtp", "radius"} {
		for _, change := range []struct {
			name      string
			timestamp x2x3.TimestampFormat
			typed     bool
		}{
			{"timestamp-only", x2x3.TimestampFormatETSI8, false},
			{"target-only", x2x3.TimestampFormatLegacy12, true},
			{"both", x2x3.TimestampFormatETSI8, true},
		} {
			t.Run(protocol+"/"+change.name, func(t *testing.T) {
				cfg, _, did, xid, metadata, _ := x3ClientFixture(t)
				isX3 := protocol == "rtp"
				if !isX3 {
					cfg.X2SpoolDir, cfg.X2SpoolKeyFile, cfg.X2SpoolKeyID, cfg.X2SpoolMaxBytes = cfg.X3SpoolDir, cfg.X3SpoolKeyFile, cfg.X3SpoolKeyID, cfg.X3SpoolMaxBytes
					cfg.X3SpoolDir, cfg.X3SpoolKeyFile, cfg.X3SpoolKeyID, cfg.X3SpoolMaxBytes = "", "", "", 0
				}
				certPEM, keyPEM := generateTestCert(t)
				port, received := wireFormatMDF(t, certPEM, keyPEM)
				roots := x509.NewCertPool()
				require.True(t, roots.AppendCertsFromPEM(certPEM))
				manager, err := NewManager(testConfigWithCerts(t))
				require.NoError(t, err)
				defer manager.Stop()
				destination := &li.Destination{DID: did, Address: "127.0.0.1", Port: port, X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3", CreatedAt: time.Now(), DeliveryRevision: 1, TLSConfig: &tls.Config{RootCAs: roots, Certificates: manager.tlsConfig.Certificates, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
				require.NoError(t, manager.AddDestination(destination))
				metadata.DestinationGeneration = li.DestinationDeliveryGeneration(destination)
				metadata.Provenance.SourceKind = protocol
				client := NewClient(manager, cfg)
				require.NoError(t, client.Err())
				defer func() { client.Stop() }()
				send := func(data []byte, meta DeliveryMetadata) error {
					if isX3 {
						return client.SendX3WithMetadata(xid, []uuid.UUID{did}, data, meta)
					}
					return client.SendX2WithMetadata(xid, []uuid.UUID{did}, data, meta)
				}
				sequencer := x2x3.NewSequencer(10)
				original := wireFormatReplayProduct(t, protocol, sequencer, xid, metadata.CapturedAt, x2x3.TimestampFormatLegacy12, false)
				require.NoError(t, send(original, metadata))
				require.NoError(t, client.FlushPersistence(context.Background()))
				client.Stop()
				client = NewClient(manager, cfg)
				require.NoError(t, client.Err())
				journal := client.x2Journal
				if isX3 {
					journal = client.x3Journal
				}
				require.Equal(t, 1, journal.Stats().Held)
				require.Zero(t, client.QueueDepth(), "a restart cannot authorize old product")
				require.NoError(t, journal.VisitHeld(func(record JournalRecord) error {
					require.Equal(t, original, record.Data)
					require.Equal(t, metadata.TaskGeneration, record.TaskGeneration)
					require.Equal(t, metadata.DestinationGeneration, record.DestinationGeneration)
					require.True(t, metadata.CapturedAt.Equal(record.CapturedAt))
					require.True(t, metadata.AdmittedAt.Equal(record.AdmittedAt))
					if isX3 {
						require.Equal(t, metadata.Provenance, record.Provenance)
					}
					require.True(t, metadata.Deadline.Equal(record.Deadline) || !isX3)
					return nil
				}))
				sequencer = x2x3.NewSequencer(10)
				require.NoError(t, client.RestoreJournalSequences(sequencer))
				manifest := filepath.Join(t.TempDir(), "approved.json")
				require.NoError(t, os.Chmod(filepath.Dir(manifest), 0700))
				export := client.ExportHeldJournalManifest
				replay := client.ReplayJournalManifest
				if isX3 {
					export = client.ExportHeldX3JournalManifest
					replay = client.ReplayX3JournalManifest
				}
				require.NoError(t, export(manifest))
				require.NoError(t, replay(manifest, func(JournalRecord) bool { return false }))
				require.Zero(t, client.QueueDepth(), "a manifest does not replace current task authorization")
				require.NoError(t, replay(manifest, func(record JournalRecord) bool { return record.TaskGeneration == metadata.TaskGeneration+1 }))
				require.Zero(t, client.QueueDepth(), "another task activation cannot authorize historical product")
				require.NoError(t, replay(manifest, func(record JournalRecord) bool {
					return record.DestinationGeneration == metadata.DestinationGeneration+1
				}))
				require.Zero(t, client.QueueDepth(), "another destination generation cannot authorize historical product")
				if isX3 {
					client.SetX3TaskAuthorization(xid, metadata.TaskGeneration, metadata.Deadline)
				}
				require.NoError(t, replay(manifest, func(record JournalRecord) bool {
					return record.XID == xid && record.DID == did && record.TaskGeneration == metadata.TaskGeneration && record.DestinationGeneration == metadata.DestinationGeneration && (!isX3 || record.Provenance == metadata.Provenance)
				}))
				require.Eventually(t, func() bool { return client.QueueDepth() == 1 }, time.Second, time.Millisecond)

				// Encode fresh standard output and then roll back while the old
				// replay remains queued. None of the three byte strings may change.
				var expected = [][]byte{original}
				for index, mode := range []struct {
					timestamp x2x3.TimestampFormat
					typed     bool
				}{{change.timestamp, change.typed}, {x2x3.TimestampFormatLegacy12, false}} {
					meta := metadata
					meta.CapturedAt = meta.CapturedAt.Add(time.Duration(index+1) * time.Microsecond)
					meta.Provenance.ObservationSequence = uint64(index + 2)
					data := wireFormatReplayProduct(t, protocol, sequencer, xid, meta.CapturedAt, mode.timestamp, mode.typed)
					expected = append(expected, append([]byte(nil), data...))
					require.NoError(t, send(data, meta))
					// Admission owns immutable bytes even if the producer recycles
					// its buffer before the receiver becomes available.
					clear(data)
				}
				require.NoError(t, client.FlushPersistence(context.Background()))
				client.Start()
				for index, originalBytes := range expected {
					select {
					case data := <-received:
						require.Equal(t, originalBytes, data, "recovery and rollback must retain each original wire representation")
						var product x2x3.PDU
						require.NoError(t, product.UnmarshalBinary(data))
						require.Equal(t, xid, product.Header.XID)
						require.Equal(t, uint32(index), binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
						require.Equal(t, "stable-processor", string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
						attribute := x2x3.FindAttribute(product.Attributes, x2x3.AttrTimestamp)
						require.NotNil(t, attribute)
						size := x2x3.LegacyTimestampSize
						if index == 1 && change.timestamp == x2x3.TimestampFormatETSI8 {
							size = x2x3.StandardTimestampSize
						}
						require.Len(t, attribute.Value, size)
						captured, err := x2x3.NewAttributeParser().ParseTimestamp(attribute)
						require.NoError(t, err)
						require.True(t, metadata.CapturedAt.Add(time.Duration(index)*time.Microsecond).Equal(captured))
						matched := x2x3.FindAttribute(product.Attributes, x2x3.AttrMatchedTargetIdentifier)
						if protocol == "radius" && (index != 1 || !change.typed) {
							require.Nil(t, matched)
						} else {
							require.NotNil(t, matched)
							if index == 1 && change.typed {
								expectedTarget := "<sipUri>sip:alice@example.invalid</sipUri>"
								if protocol == "radius" {
									expectedTarget = "<nai>alice@example.invalid</nai>"
								}
								require.Equal(t, expectedTarget, string(matched.Value))
							} else {
								require.Equal(t, "sip:alice@example.invalid", string(matched.Value))
							}
						}
					case <-time.After(5 * time.Second):
						t.Fatal("mixed-format product did not reach synthetic receiver")
					}
				}
				require.Eventually(t, func() bool {
					if isX3 {
						return client.Stats().X3Sent == 3
					}
					return client.Stats().X2Sent == 3
				}, time.Second, time.Millisecond)
				require.NoError(t, client.FlushPersistence(context.Background()))
				require.Zero(t, journal.Stats().Persisted)
			})
		}
	}
}
