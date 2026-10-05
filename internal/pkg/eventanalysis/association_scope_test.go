package eventanalysis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
)

func TestAssociationScopePreservesEveryBoundary(t *testing.T) {
	r := &Runtime{cfg: Config{AnalysisEpoch: "analysis"}, generation: 1}
	src := Source{CaptureEpoch: "capture"}
	env := events.Envelope{NodeID: "node", Provenance: events.SourceProvenance{CaptureSource: "pcap", InterfaceName: "fixture0", InterfaceIndex: 1, InputFile: "fixture.pcap"}}
	previous := r.associationScope(src, env)
	for _, change := range []func(){
		func() { env.NodeID = "node/quoted\"" }, func() { r.cfg.AnalysisEpoch = "next" }, func() { src.CaptureEpoch = "next" }, func() { r.generation++ }, func() { env.Provenance.CaptureSource = "live" }, func() { env.Provenance.InterfaceName = "fixture1" }, func() { env.Provenance.InterfaceIndex++ }, func() { env.Provenance.InputFile = "other.pcap" },
	} {
		change()
		p := env.Provenance
		want := fmt.Sprintf("%q/%q/%q/%d/%q/%q/%d/%q", env.NodeID, r.cfg.AnalysisEpoch, src.CaptureEpoch, r.generation, p.CaptureSource, p.InterfaceName, p.InterfaceIndex, p.InputFile)
		got := r.associationScope(src, env)
		require.Equal(t, want, got)
		require.NotEqual(t, previous, got)
		require.Equal(t, got, r.associationScope(src, env))
		previous = got
	}
}

func TestCachedScopeAllowsInventoryReemission(t *testing.T) {
	for _, mode := range []string{"eviction", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			r, d, s := inventoryRuntime(t)
			if mode == "eviction" {
				r.cfg.Policy.Inventory.MaxEntries = 2
				r.cfg.Policy.Inventory.MaxEntriesPerScope = 2
			} else {
				r.cfg.Policy.Inventory.Retention = time.Second
			}
			require.NoError(t, r.Reset())
			source := Source{NodeID: "node", CaptureSource: "fixture", CaptureEpoch: "same"}
			at := time.Unix(1000, 0)
			observe := func(src, dst string, sp, dp uint16, ts time.Time) {
				p, err := eventfixture.NetworkDatagram(src, dst, sp, dp, []byte{1, 2, 3}, ts)
				require.NoError(t, err)
				require.NoError(t, r.ObservePacket(source, p))
			}
			observe("192.0.2.10", "192.0.2.20", 41000, 41001, at)
			observe("192.0.2.20", "192.0.2.10", 41001, 41000, at)
			if mode == "eviction" {
				observe("192.0.2.30", "192.0.2.40", 42000, 42001, at)
				observe("192.0.2.40", "192.0.2.30", 42001, 42000, at)
			} else {
				at = at.Add(2 * time.Second)
			}
			// Existing bidirectional flow proof must be offered to the tracker again.
			observe("192.0.2.10", "192.0.2.20", 41000, 41001, at)
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			want := 4
			if mode == "eviction" {
				want = 6
			}
			require.Len(t, inventoryEvents(s), want)
			require.LessOrEqual(t, r.Stats().Inventory.Entries, 2)
		})
	}
}
