//go:build hunter || all

package hunter

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
)

func TestNetworkHunterEventSpoolProfiles(t *testing.T) {
	assertHunterSpoolFixture(t, nil, eventfixture.NetworkMessages, eventfixture.AssertNetworkMessages)
}
func TestInventoryHunterEventSpoolProfiles(t *testing.T) {
	assertHunterSpoolFixture(t, eventfixture.InventoryPolicy(), eventfixture.InventoryMessages, eventfixture.AssertInventory)
}
func assertHunterSpoolFixture(t *testing.T, policy *eventconfig.Config, fixture func() ([]capture.PacketInfo, error), assertFixture func(testing.TB, []events.Event) []events.Event) {
	for _, profile := range []string{"memory_only", "reliable"} {
		t.Run(profile, func(t *testing.T) {
			dir := t.TempDir()
			h, err := New(Config{EventAnalysis: policy, ProcessorAddr: "processor:55555", HunterID: "network-hunter", ForwardMode: "events", EventSpoolDir: dir, EventDeliveryProfile: profile})
			require.NoError(t, err)
			h.ctx, h.cancel = context.WithCancel(context.Background())
			defer h.cancel()
			require.NoError(t, h.initializeEventForwarding())
			packets, err := fixture()
			require.NoError(t, err)
			for _, info := range packets {
				require.NoError(t, h.eventRuntime.ObservePacket(eventanalysis.Source{NodeID: "network-hunter", CaptureSource: "fixture0"}, info))
			}
			h.eventRuntime.EOF()
			h.eventRuntime.Close()
			require.NoError(t, h.eventDispatcher.Close(context.Background()))
			var observed []events.Event
			var identities []string
			for _, batch := range h.eventSpool.Batches() {
				for _, p := range batch.Events {
					e, omitted, err := protoadapter.FromProto(p)
					require.NoError(t, err)
					require.Nil(t, omitted)
					observed = append(observed, e)
					identities = append(identities, e.Envelope().EventID)
				}
			}
			assertFixture(t, observed)
			require.NoError(t, h.eventSpool.Close())
			recovered, err := eventspool.Open(eventspool.Config{Directory: dir})
			require.NoError(t, err)
			defer func() { require.NoError(t, recovered.Close()) }()
			var retried []string
			for _, batch := range recovered.Batches() {
				for _, p := range batch.Events {
					retried = append(retried, p.EventId)
				}
			}
			require.Equal(t, identities, retried, "reconnect replays immutable event identities")
		})
	}
}
