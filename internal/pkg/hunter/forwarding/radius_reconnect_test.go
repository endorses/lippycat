//go:build hunter || all

package forwarding

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

func TestRADIUSForwardingManagerReconnectStartsNewCaptureEpoch(t *testing.T) {
	file, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var packets []gopacket.Packet
	for range 2 {
		raw, ci, err := reader.ReadPacketData()
		require.NoError(t, err)
		packet := gopacket.NewPacket(raw, reader.LinkType(), gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		packets = append(packets, packet)
	}
	predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateUserName, Value: "alice@example.test", FilterID: "user", FilterRevision: 1})
	require.NoError(t, err)
	matcher := &radiusSourceFilter{predicate: predicate}
	// Hunter.CreateForwardingManager constructs a new manager on each transport
	// connection, sharing only the persistent packet batch queue. Quiesce senders
	// so this test can inspect the queued pre-reconnect observation unchanged.
	queue := make(chan *pipeline.PacketBatch, 2)
	newManager := func() *Manager {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		manager := New(Config{HunterID: "hunter", BatchSize: 2}, &flowStats{}, nil, ctx, queue)
		manager.senderWg.Wait()
		require.NotNil(t, manager.radiusProcessor)
		t.Cleanup(manager.radiusProcessor.Close)
		return manager
	}
	first := newManager()
	request := first.radiusProcessor.Process(packets[0], reader.LinkType(), "eth0", matcher)
	require.Len(t, request.Direct, 1)
	queued := &pipeline.PacketBatch{Packets: []*pipeline.PacketEnvelope{{RADIUS: request}}}
	first.radiusProcessor.Close()
	second := newManager()
	// Add through the old manager after both senders are quiescent, avoiding
	// a canceled sender racing to dequeue the inspection fixture.
	first.batchQueue <- queued
	response := second.radiusProcessor.Process(packets[1], reader.LinkType(), "eth0", matcher)
	require.Equal(t, radius.AssociationMissing, response.Association.Status)
	require.Empty(t, response.Inherited)
	require.NotEqual(t, request.Scope.Epoch, response.Scope.Epoch)
	require.Equal(t, queue, second.batchQueue)
	retained := <-second.batchQueue
	require.Same(t, queued, retained)
	require.Equal(t, request.Scope.Epoch, retained.Packets[0].RADIUS.Scope.Epoch)
	require.Len(t, retained.Packets[0].RADIUS.Direct, 1)
}
