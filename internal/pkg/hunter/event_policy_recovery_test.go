//go:build hunter || all

package hunter

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRecoveredEventAnalysisPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		legacy, drained, inventory bool
		change                     string
		reject, rotate             bool
	}{
		{name: "unchanged pending", inventory: true},
		{name: "equivalent CIDRs pending", inventory: true, change: "equivalent"},
		{name: "changed CIDRs pending", inventory: true, change: "cidr", reject: true},
		{name: "changed bounds pending", change: "bounds", reject: true},
		{name: "changed CIDRs drained", inventory: true, change: "cidr", drained: true, rotate: true},
		{name: "changed bounds drained", change: "bounds", drained: true, rotate: true},
		{name: "unchanged drained", drained: true},
		{name: "legacy default pending", legacy: true},
		{name: "legacy enabled inventory pending", legacy: true, change: "enable", reject: true},
		{name: "legacy enabled inventory drained", legacy: true, change: "enable", drained: true, rotate: true},
		{name: "legacy changed pending", legacy: true, change: "bounds", reject: true},
		{name: "legacy changed drained", legacy: true, change: "bounds", drained: true, rotate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const node = "policy-hunter"
			const session = "30313233343536373839616263646566"
			dir := t.TempDir()
			old := eventconfig.Default()
			old.Inventory.Enabled = tc.inventory
			if tc.inventory {
				old.Inventory.LocalCIDRs = []string{"192.0.2.0/24", "2001:db8::/32"}
			}
			config := Config{ProcessorAddr: "processor:55555", HunterID: node, ForwardMode: "events", EventSpoolDir: dir, EventDeliveryProfile: "reliable", EventAnalysis: &old}
			h, err := New(config)
			require.NoError(t, err)
			policy := h.eventSessionPolicy(session)
			if tc.legacy {
				policy.AnalysisFingerprint = ""
			}
			spool, err := eventspool.Open(eventspool.Config{Directory: dir})
			require.NoError(t, err)
			require.NoError(t, spool.BindSessionPolicy(policy))
			e := events.NewDNSEvent(events.Envelope{Timestamp: time.Unix(1, 0), NodeID: node, ProducerSessionID: session, EventSequence: 7, EventID: events.DeliveryEventID(node, session, 7), UID: "uid", Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 53000, DestinationPort: 53}, CaptureScope: events.CaptureScopeFiltered})
			batch, err := protoadapter.ToProtoBatch(node, session, 3, []events.Event{e}, nil, 1)
			require.NoError(t, err)
			result, err := spool.Enqueue(batch)
			require.NoError(t, err)
			require.True(t, result.Stored)
			batch = spool.Batches()[0] // Include canonical gap-loss accounting assigned at admission.
			if tc.drained {
				require.NoError(t, spool.Ack(node, session, 3))
			}
			require.NoError(t, spool.Close())
			next := old.Clone()
			switch tc.change {
			case "enable":
				next.Inventory.Enabled = true
			case "cidr":
				next.Inventory.LocalCIDRs = []string{"198.51.100.0/24"}
			case "bounds":
				next.NTP.MaxEntries++
			case "equivalent":
				next.Inventory.LocalCIDRs = []string{"2001:db8::1/32", "192.0.2.12/24", "192.0.2.0/24"}
			}
			config.EventAnalysis = &next
			h, err = New(config)
			require.NoError(t, err)
			// The owner snapshot must remain independent from later caller mutations.
			next.NTP.MaxEntries++
			h.ctx = context.Background()
			err = h.initializeEventForwarding()
			if tc.reject {
				require.ErrorContains(t, err, "pending records use policy")
				recovered, openErr := eventspool.Open(eventspool.Config{Directory: dir})
				require.NoError(t, openErr)
				defer func() { require.NoError(t, recovered.Close()) }()
				require.Len(t, recovered.Batches(), 1)
				require.True(t, proto.Equal(batch, recovered.Batches()[0]))
				saved, ok := recovered.SessionPolicy()
				require.True(t, ok)
				require.Equal(t, policy, saved)
				return
			}
			require.NoError(t, err)
			defer func() {
				h.eventRuntime.Close()
				require.NoError(t, h.eventDispatcher.Close(context.Background()))
				require.NoError(t, h.eventSpool.Close())
			}()
			_, gotSession, gotEvent, gotBatch, err := h.eventSpool.RecoveryState()
			require.NoError(t, err)
			if tc.rotate {
				require.NotEqual(t, session, gotSession)
				require.Zero(t, gotEvent)
				require.Zero(t, gotBatch)
				saved, ok := h.eventSpool.SessionPolicy()
				require.True(t, ok)
				require.Equal(t, h.config.EventAnalysis.Fingerprint(), saved.AnalysisFingerprint)
			} else {
				require.Equal(t, session, gotSession)
				require.EqualValues(t, 7, gotEvent)
				require.EqualValues(t, 3, gotBatch)
			}
			if !tc.drained {
				require.Len(t, h.eventSpool.Batches(), 1)
				require.True(t, proto.Equal(batch, h.eventSpool.Batches()[0]))
			}
		})
	}
}
