//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestNetworkLocalBridgeLiveAndOffline(t *testing.T) {
	assertLocalBridgeFixture(t, nil, eventfixture.NetworkMessages, eventfixture.AssertNetworkMessages)
}
func TestInventoryLocalBridgeLiveAndOffline(t *testing.T) {
	assertLocalBridgeFixture(t, eventfixture.InventoryPolicy(), eventfixture.InventoryMessages, eventfixture.AssertInventory)
}
func assertLocalBridgeFixture(t *testing.T, policy *eventconfig.Config, fixture func() ([]capture.PacketInfo, error), assertFixture func(testing.TB, []events.Event) []events.Event) {
	packets, err := fixture()
	require.NoError(t, err)
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "offline"}[offline], func(t *testing.T) {
			pendingPackets.drainPackets(1 << 20)
			t.Cleanup(func() { pendingPackets.drainPackets(1 << 20) })
			var observed []events.Event
			bridge := newEnvelopeBridgePipeline(nil, NewPauseSignal(), nil, offline, nil)
			bridge.analysis = LocalEventAnalysisOptions{Policy: policy, NodeID: "watch-test", InputIdentity: "network-fixture", AnalysisProfile: "network-test", SourceOrdering: []string{"network.pcap"}, deliver: func(batch types.EventBatch) {
				require.Empty(t, batch.Losses)
				observed = append(observed, batch.Events...)
			}}
			ch := make(chan capture.PacketInfo, len(packets))
			for _, info := range packets {
				ch <- info
			}
			close(ch)
			kind := pipeline.SourceLiveCapture
			if offline {
				kind = pipeline.SourcePCAPReplay
			}
			bridge.run(NormalizeCaptureStream(context.Background(), ch, kind))
			assertFixture(t, observed)
		})
	}
}

func TestNetworkOfflineIndexerPreservesMessageEvents(t *testing.T) {
	assertOfflineIndexerFixture(t, nil, eventfixture.NetworkMessages, eventfixture.AssertNetworkMessages)
}
func TestInventoryOfflineIndexerPreservesDerivedEvents(t *testing.T) {
	assertOfflineIndexerFixture(t, eventfixture.InventoryPolicy(), eventfixture.InventoryMessages, eventfixture.AssertInventory)
}
func assertOfflineIndexerFixture(t *testing.T, policy *eventconfig.Config, fixture func() ([]capture.PacketInfo, error), assertFixture func(testing.TB, []events.Event) []events.Event) {
	packets, err := fixture()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "network.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(f)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, info := range packets {
		require.NoError(t, writer.WritePacket(info.Packet.Metadata().CaptureInfo, info.Packet.Data()))
	}
	require.NoError(t, f.Close())
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 1, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 32, Analysis: LocalEventAnalysisOptions{Policy: policy}}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	require.Equal(t, uint64(len(packets)), session.Dataset.Count())
	require.Zero(t, session.EventStore.Stats().TransportLost)
	var observed []events.Event
	for _, item := range session.EventStore.Events() {
		observed = append(observed, item.Event)
	}
	got := assertFixture(t, observed)
	for _, e := range got {
		require.Equal(t, path, e.Envelope().Provenance.InputFile)
	}
}
