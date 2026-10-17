package upstream

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
)

func TestTryForwardReportsQueueOwnershipAndRejection(t *testing.T) {
	manager := NewManager(Config{OutboundQueueSize: 1}, nil)
	t.Cleanup(func() { manager.Disconnect() })
	packet := &data.PacketBatch{Packets: []*data.CapturedPacket{{Data: []byte{1}}}}
	require.False(t, manager.TryForward(packet), "unavailable stream never accepts ownership")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	generation := &connection{ctx: ctx, cancel: cancel, queue: make(chan *data.PacketBatch, 1)}
	generation.accepting.Store(true)
	manager.generation = generation
	require.True(t, manager.TryForward(packet))
	require.False(t, manager.TryForward(packet), "full queue never accepts ownership")
	generation.accepting.Store(false)
	<-generation.queue
	require.False(t, manager.TryForward(packet), "retired generation never accepts ownership")
	require.EqualValues(t, 3, manager.DroppedPackets())
}
