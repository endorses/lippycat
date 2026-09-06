package conntrack

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/stretchr/testify/require"
)

func TestSourceOrdering(t *testing.T) {
	now := time.Unix(1700000000, 0)
	base := testEnv(now, false)
	// Later fields deliberately oppose earlier fields to verify precedence.
	cases := []struct {
		name string
		low  events.SourceProvenance
		high events.SourceProvenance
	}{
		{"capture_source", events.SourceProvenance{CaptureSource: "a", InterfaceName: "z"}, events.SourceProvenance{CaptureSource: "b", InterfaceName: "a"}},
		{"interface_name", events.SourceProvenance{InterfaceName: "a", InterfaceIndex: 100}, events.SourceProvenance{InterfaceName: "b", InterfaceIndex: 1}},
		{"interface_index", events.SourceProvenance{InterfaceIndex: 2, InputFile: "z"}, events.SourceProvenance{InterfaceIndex: 10, InputFile: "a"}},
		{"input_file", events.SourceProvenance{InputFile: "a.pcap"}, events.SourceProvenance{InputFile: "b.pcap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			low, high := base, base
			low.Provenance, high.Provenance = tc.low, tc.high
			checkConnectionOrdering(t, low, high)
		})
	}
	// Provenance remains subordinate to the established node/flow ordering.
	t.Run("node_before_source", func(t *testing.T) {
		low, high := base, base
		low.NodeID, high.NodeID = "a", "b"
		low.Provenance.InputFile, high.Provenance.InputFile = "z.pcap", "a.pcap"
		checkConnectionOrdering(t, low, high)
	})
	t.Run("flow_before_source", func(t *testing.T) {
		low, high := base, base
		high.Flow.SourcePort++
		low.Provenance.InputFile, high.Provenance.InputFile = "z.pcap", "a.pcap"
		checkConnectionOrdering(t, low, high)
	})
}

func checkConnectionOrdering(t *testing.T, low, high events.Envelope) {
	t.Helper()
	lowFlow, err := flowid.Normalize(low.Flow)
	require.NoError(t, err)
	highFlow, err := flowid.Normalize(high.Flow)
	require.NoError(t, err)
	lowKey := trackerKeyForEnvelope(lowFlow, low)
	highKey := trackerKeyForEnvelope(highFlow, high)
	// Verify the eviction comparator directly so map iteration cannot mask a tie.
	require.True(t, trackerKeyLess(lowKey, highKey))
	require.False(t, trackerKeyLess(highKey, lowKey))
	require.False(t, trackerKeyLess(lowKey, lowKey))
	for _, order := range [][]events.Envelope{{low, high}, {high, low}} {
		// Direct sorting verifies both permutations without depending on map order.
		out := []events.ConnEvent{events.NewConnEvent(order[0]), events.NewConnEvent(order[1])}
		sortConnEvents(out)
		require.Equal(t, low, out[0].Envelope())
		require.Equal(t, high, out[1].Envelope())
		for _, operation := range []string{"close", "expire", "evict"} {
			t.Run(operation, func(t *testing.T) {
				capacity := 2
				if operation == "evict" {
					capacity = 1
				}
				tr, err := New(Config{MaxFlows: capacity, IdleTimeout: time.Minute, HalfOpenTimeout: time.Second})
				require.NoError(t, err)
				var evicted []events.ConnEvent
				for _, env := range order {
					got, err := tr.Observe(Observation{Envelope: env, TCP: &TCPFlags{SYN: true}})
					require.NoError(t, err)
					evicted = append(evicted, got...)
				}
				var got []events.ConnEvent
				switch operation {
				case "close":
					got = tr.Close()
				case "expire":
					got = tr.Expire(low.Timestamp.Add(time.Minute))
				case "evict":
					require.Len(t, evicted, 1)
					require.Equal(t, uint64(1), tr.Stats().Evictions)
					got = append(evicted, tr.Close()...)
				}
				require.Len(t, got, 2)
				for i, want := range []events.Envelope{low, high} {
					// One-way observations are partial connection summaries.
					want.Partial = true
					require.Equal(t, want, got[i].Envelope())
				}
				require.Zero(t, tr.Stats().Depth)
			})
		}
	}
}
