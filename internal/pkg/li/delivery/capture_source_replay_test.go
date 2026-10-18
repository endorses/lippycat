//go:build li && linux

package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This exercises the delivery client's supported non_call journal variant. Task
// provisioning and packet selection belong to its caller; no raw-IP task is
// enabled here. The product itself comes from the production RTP X3 encoder.
func TestCaptureSourceNonCallRTPJournalReplayToReceiver(t *testing.T) {
	cfg, _, did, xid, metadata, _ := x3ClientFixture(t)
	encoder := x2x3.NewX3EncoderWithSequencer(nil, "delivery-domain", "stable-processor")
	encoder.SetCaptureSourceMetadata(true)
	var originals, sourceBytes [][]byte
	var metadataCopies []DeliveryMetadata
	for index, node := range []string{"hunter-a", "hunter-b"} {
		raw := make([]byte, 16)
		raw[0] = 0x80
		binary.BigEndian.PutUint16(raw[2:], uint16(index+1))
		binary.BigEndian.PutUint32(raw[8:], 42)
		copy(raw[12:], "test")
		packet := &types.PacketDisplay{
			NodeID: node, Interface: "eth0", ObservationDomain: uint32(index), ObservationDomainKnown: true,
			Timestamp: metadata.CapturedAt.Add(time.Duration(index) * time.Microsecond), RawData: raw,
			SrcIP: metadata.Provenance.SourceAddress, DstIP: metadata.Provenance.DestinationAddress,
			SrcPort: "2000", DstPort: "3000", Transport: 17,
			VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 42, SequenceNum: uint16(index + 1)},
		}
		product, err := encoder.EncodeCC(packet, xid)
		require.NoError(t, err)
		encoded, err := product.MarshalBinary()
		require.NoError(t, err)
		originals = append(originals, encoded)
		sourceBytes = append(sourceBytes, append([]byte(nil), x2x3.FindAttribute(product.Attributes, x2x3.AttrProprietary).Value...))
		meta := metadata
		meta.CapturedAt = packet.Timestamp
		meta.Provenance.OriginNodeID = node
		meta.Provenance.SourceID = packet.Interface
		meta.Provenance.CaptureEpoch = uuid.New()
		meta.Provenance.ObservationSequence = uint64(index + 1)
		metadataCopies = append(metadataCopies, meta)
	}
	require.Len(t, originals[0], len(originals[1]), "fixed-size fixture receiver reads one product at a time")
	certPEM, keyPEM := generateTestCert(t)
	receiver := newRestartableMDF(t, certPEM, keyPEM, len(originals[0]))
	receiver.Start(t)
	defer receiver.Close()
	port := receiver.Port()
	receiver.Stop()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))
	managerConfig := testConfigWithCerts(t)
	managerConfig.InitialBackoff = 10 * time.Millisecond
	managerConfig.MaxBackoff = 30 * time.Millisecond
	managerConfig.DialTimeout = 50 * time.Millisecond
	manager, err := NewManager(managerConfig)
	require.NoError(t, err)
	defer manager.Stop()
	destination := &li.Destination{DID: did, Address: "127.0.0.1", Port: port, ProtocolType: "X3", X3Enabled: true, CreatedAt: time.Now(), DeliveryRevision: 1, TLSConfig: &tls.Config{RootCAs: roots, Certificates: manager.tlsConfig.Certificates, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	require.NoError(t, manager.AddDestination(destination))
	cfg.RetryInitialBackoff = 10 * time.Millisecond
	cfg.RetryMaxBackoff = 30 * time.Millisecond
	cfg.SendTimeout = 100 * time.Millisecond
	client := NewClient(manager, cfg)
	require.NoError(t, client.Err())
	for index, encoded := range originals {
		metadataCopies[index].DestinationGeneration = li.DestinationDeliveryGeneration(destination)
		require.NoError(t, client.SendX3WithMetadata(xid, []uuid.UUID{did}, encoded, metadataCopies[index]))
	}
	require.NoError(t, client.FlushPersistence(context.Background()))
	require.Equal(t, 2, client.X3JournalStats().Persisted)
	client.Stop()
	client = NewClient(manager, cfg)
	require.NoError(t, client.Err())
	defer client.Stop()
	require.Equal(t, 2, client.X3JournalStats().Held)
	require.Zero(t, client.QueueDepth(), "restart alone does not authorize transport")
	held := 0
	require.NoError(t, client.x3Journal.VisitHeld(func(record JournalRecord) error {
		require.Less(t, held, len(originals))
		require.Equal(t, originals[held], record.Data)
		require.Equal(t, "non_call", record.Provenance.Kind)
		require.Equal(t, metadataCopies[held].Provenance, record.Provenance)
		source, available, err := x2x3.DecodeProductCaptureSource(record.Data)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, metadataCopies[held].Provenance.OriginNodeID, source.NodeID())
		held++
		return nil
	}))
	require.Equal(t, 2, held)
	manifest := filepath.Join(t.TempDir(), "approval.json")
	require.NoError(t, os.Chmod(filepath.Dir(manifest), 0700))
	require.NoError(t, client.ExportHeldX3JournalManifest(manifest))
	client.Start()
	require.NoError(t, client.ReplayX3JournalManifest(manifest, func(JournalRecord) bool { return false }))
	require.Zero(t, client.QueueDepth(), "operator identity alone does not replace current authorization")
	client.SetX3TaskAuthorization(xid, metadata.TaskGeneration, time.Now().Add(time.Minute))
	require.NoError(t, client.ReplayX3JournalManifest(manifest, func(record JournalRecord) bool {
		return record.XID == xid && record.TaskGeneration == metadata.TaskGeneration && record.DID == did && record.DestinationGeneration == li.DestinationDeliveryGeneration(destination) && record.Provenance.Kind == "non_call"
	}))
	receiver.Start(t)
	for index := range originals {
		received := []byte(receiver.Receive(t, 3*time.Second))
		require.Equal(t, originals[index], received, "actual receiver gets the original accepted bytes")
		source, available, err := x2x3.DecodeProductCaptureSource(received)
		require.NoError(t, err)
		require.True(t, available)
		require.Equal(t, []string{"hunter-a", "hunter-b"}[index], source.NodeID())
		require.Equal(t, "eth0", source.Interface())
		domain, known := source.ObservationDomain()
		require.True(t, known)
		require.Equal(t, uint32(index), domain)
		var product x2x3.PDU
		require.NoError(t, product.UnmarshalBinary(received))
		require.Equal(t, sourceBytes[index], x2x3.FindAttribute(product.Attributes, x2x3.AttrProprietary).Value)
		require.Equal(t, uint32(index), binary.BigEndian.Uint32(x2x3.FindAttribute(product.Attributes, x2x3.AttrSequenceNumber).Value))
		require.Equal(t, "stable-processor", string(x2x3.FindAttribute(product.Attributes, x2x3.AttrIPID).Value))
		require.Equal(t, x2x3.NewAttributeBuilder().Timestamp(metadataCopies[index].CapturedAt).Value, x2x3.FindAttribute(product.Attributes, x2x3.AttrTimestamp).Value)
	}
	require.Eventually(t, func() bool { return client.Stats().X3Sent == 2 }, time.Second, time.Millisecond)
	require.NoError(t, client.FlushPersistence(context.Background()))
	require.Zero(t, client.X3JournalStats().Persisted)
}
