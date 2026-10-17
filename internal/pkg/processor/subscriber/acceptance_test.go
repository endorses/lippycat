//go:build processor || tap || all

package subscriber

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
)

func TestBroadcastFilteredEligibilityPrecedesPerSubscriberOwnership(t *testing.T) {
	manager := NewManager(10)
	active := manager.Add("active")
	full := manager.Add("full")
	hidden := manager.Add("hidden")
	manager.SetFilter("hidden", []string{"another-source"})
	manager.SetPacketEligibility("active", func(packet *data.CapturedPacket) bool { return len(packet.Data) > 0 && packet.Data[0] == 2 })
	for range cap(full) {
		full <- &data.PacketBatch{}
	}
	batch := &data.PacketBatch{HunterId: "source", Packets: []*data.CapturedPacket{{Data: []byte{1}}, {Data: []byte{2}}}, ProducerSessionId: "session", CaptureEpoch: "epoch"}
	decisions := make(map[string]bool)
	manager.BroadcastFiltered(batch, func(client string, eligible *data.PacketBatch) (*data.PacketBatch, func(bool)) {
		require.NotEqual(t, "hidden", client)
		if client == "active" {
			require.Len(t, eligible.Packets, 1)
			require.Same(t, batch.Packets[1], eligible.Packets[0])
		}
		return eligible, func(accepted bool) { decisions[client] = accepted }
	})
	require.True(t, decisions["active"])
	require.False(t, decisions["full"])
	require.Len(t, decisions, 2)
	require.Empty(t, hidden)
	accepted := <-active
	require.Equal(t, "session", accepted.ProducerSessionId)
	require.Equal(t, "epoch", accepted.CaptureEpoch)
	require.Len(t, accepted.Packets, 1)
}
