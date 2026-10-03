//go:build tui || all

package store

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/stretchr/testify/require"
)

type packetScanPredicate struct {
	match func(filters.Filterable) bool
}

func (f packetScanPredicate) Match(record filters.Filterable) bool { return f.match(record) }
func (packetScanPredicate) String() string                         { return "test packet scan" }
func (packetScanPredicate) Type() string                           { return "test" }
func (packetScanPredicate) Selectivity() float64                   { return 0.5 }
func (packetScanPredicate) SupportedRecordTypes() []string         { return []string{"packet"} }

func scanChain(match func(filters.Filterable) bool) *filters.FilterChain {
	chain := filters.NewFilterChain()
	chain.Add(packetScanPredicate{match: match})
	return chain
}

func scanPacket(info, protocol string) components.PacketDisplay {
	return components.PacketDisplay{Info: info, Protocol: protocol}
}

func TestPacketFilterScanDoesNotBlockArrivals(t *testing.T) {
	ps := NewPacketStore(8)
	old := scanPacket("old", "TCP")
	fresh := scanPacket("new", "TCP")
	old.CaptureID, fresh.CaptureID = 1, 3
	ps.AddPacketBatch([]components.PacketDisplay{old, scanPacket("excluded", "UDP")})
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var once sync.Once
	scan := ps.BeginFilter(scanChain(func(record filters.Filterable) bool {
		if record.GetStringField("info") == "old" {
			once.Do(func() { close(entered) })
			<-release
		}
		return record.GetStringField("protocol") == "TCP"
	}))
	finished := make(chan *PacketFilterResult, 1)
	go func() { finished <- scan.Run() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot predicate was not reached")
	}
	added := make(chan struct{})
	go func() {
		ps.AddPacketBatch([]components.PacketDisplay{fresh, scanPacket("new excluded", "UDP")})
		close(added)
	}()
	select {
	case <-added:
	case <-time.After(5 * time.Second):
		t.Fatal("ingestion waited on background snapshot filtering")
	}
	require.Equal(t, []components.PacketDisplay{fresh}, ps.GetFilteredPackets())
	// Allow the scan to finish without closing release twice in deferred cleanup.
	release <- struct{}{}
	result := <-finished
	require.True(t, ps.CompleteFilter(result))
	require.Equal(t, []components.PacketDisplay{old, fresh}, ps.GetFilteredPackets())
	total, matched := ps.Stats()
	require.EqualValues(t, 4, total)
	require.EqualValues(t, 2, matched)
	require.False(t, ps.CompleteFilter(result), "results install at most once")
}

func TestPacketFilterScanPreservesIdenticalArrivals(t *testing.T) {
	ps := NewPacketStore(8)
	packet := scanPacket("identical", "TCP")
	ps.AddPacketBatch([]components.PacketDisplay{packet, packet})
	chain := scanChain(func(record filters.Filterable) bool { return record.GetStringField("protocol") == "TCP" })
	scan := ps.BeginFilter(chain)
	// Changes to the caller's chain must not change either installed predicate set.
	chain.Add(packetScanPredicate{match: func(filters.Filterable) bool { return false }})
	ps.AddPacketBatch([]components.PacketDisplay{packet, packet})
	require.True(t, ps.CompleteFilter(scan.Run()))
	require.Equal(t, []components.PacketDisplay{scanPacketID(1, packet), scanPacketID(2, packet), scanPacketID(3, packet), scanPacketID(4, packet)}, ps.GetFilteredPackets())
	_, matched := ps.Stats()
	require.EqualValues(t, 4, matched)
}

func TestPacketFilterScanOmitsEvictedSnapshotMatches(t *testing.T) {
	ps := NewPacketStore(3)
	oldest, middle, newest := scanPacket("oldest", "TCP"), scanPacket("middle", "TCP"), scanPacket("newest", "TCP")
	oldest.CaptureID, middle.CaptureID, newest.CaptureID = 1, 2, 3
	ps.AddPacketBatch([]components.PacketDisplay{oldest, middle, newest})
	scan := ps.BeginFilter(scanChain(func(record filters.Filterable) bool { return record.GetStringField("protocol") == "TCP" }))
	result := scan.Run()
	ps.AddPacket(scanPacket("nonmatching arrival", "UDP"))
	require.True(t, ps.CompleteFilter(result))
	require.Equal(t, []components.PacketDisplay{middle, newest}, ps.GetFilteredPackets())
	_, matched := ps.Stats()
	require.EqualValues(t, 2, matched)
}

func TestPacketFilterScanPreservesWrappedOrder(t *testing.T) {
	ps := NewPacketStore(3)
	ps.AddPacketBatch([]components.PacketDisplay{scanPacket("0", "TCP"), scanPacket("1", "TCP"), scanPacket("2", "TCP"), scanPacket("3", "TCP")})
	scan := ps.BeginFilter(filters.NewFilterChain())
	ps.AddPacket(scanPacket("4", "TCP"))
	require.True(t, ps.CompleteFilter(scan.Run()))
	require.Equal(t, []components.PacketDisplay{scanPacketID(3, scanPacket("2", "TCP")), scanPacketID(4, scanPacket("3", "TCP")), scanPacketID(5, scanPacket("4", "TCP"))}, ps.GetFilteredPackets())
}

func TestPacketFilterScanKeepsArrivalHistoryBounded(t *testing.T) {
	ps := NewPacketStore(2)
	ps.AddPacket(scanPacket("old", "TCP"))
	scan := ps.BeginFilter(filters.NewFilterChain())
	ps.AddPacketBatch([]components.PacketDisplay{scanPacket("1", "TCP"), scanPacket("2", "TCP"), scanPacket("3", "TCP")})
	require.True(t, ps.CompleteFilter(scan.Run()))
	require.Equal(t, []components.PacketDisplay{scanPacketID(3, scanPacket("2", "TCP")), scanPacketID(4, scanPacket("3", "TCP"))}, ps.GetFilteredPackets())
	_, matched := ps.Stats()
	require.EqualValues(t, 3, matched, "incremental matched counter remains cumulative")
}

func TestPacketFilterScanRejectsInvalidatedResults(t *testing.T) {
	mutations := map[string]func(*PacketStore){
		"replacement scan": func(ps *PacketStore) { ps.BeginFilter(filters.NewFilterChain()) },
		"clear":            (*PacketStore).Clear,
		"clear and resize": func(ps *PacketStore) { ps.ClearAndResize(4) },
		"replace packets":  func(ps *PacketStore) { ps.SetPackets(make([]components.PacketDisplay, 4), 0, 0) },
		"set filter":       func(ps *PacketStore) { ps.SetFilter(filters.NewFilterChain()) },
		"clear filter":     (*PacketStore).ClearFilter,
		"add filter": func(ps *PacketStore) {
			ps.AddFilter(packetScanPredicate{match: func(filters.Filterable) bool { return false }})
		},
		"reapply filters": (*PacketStore).ReapplyFilters,
		"clear filtered":  (*PacketStore).ClearFilteredPackets,
		"resize":          func(ps *PacketStore) { ps.ResizeBuffer(3) },
		"set buffer size": func(ps *PacketStore) { ps.SetBufferSize(3) },
		"reset counts":    (*PacketStore).ResetCounts,
		"cancel":          (*PacketStore).CancelFilter,
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ps := NewPacketStore(4)
			ps.AddPacket(scanPacket("old", "TCP"))
			scan := ps.BeginFilter(filters.NewFilterChain())
			result := scan.Run()
			mutate(ps)
			before := ps.GetFilteredPackets()
			require.False(t, ps.CompleteFilter(result))
			require.Equal(t, before, ps.GetFilteredPackets())
			require.Nil(t, scan.Run(), "invalidated scans stop before evaluating packets")
		})
	}
}

func TestPacketFilterScanRejectsPreviousSessionWithSameCounters(t *testing.T) {
	ps := NewPacketStore(4)
	ps.AddPacket(scanPacket("old session", "TCP"))
	oldScan := ps.BeginFilter(filters.NewFilterChain())
	result := oldScan.Run()
	ps.Clear()
	fresh := scanPacketID(2, scanPacket("new session", "TCP"))
	ps.AddPacket(fresh)
	newScan := ps.BeginFilter(filters.NewFilterChain())
	require.False(t, ps.CompleteFilter(result))
	require.True(t, ps.CompleteFilter(newScan.Run()))
	require.Equal(t, []components.PacketDisplay{fresh}, ps.GetFilteredPackets())
}

func TestPacketFilterScanCancellation(t *testing.T) {
	ps := NewPacketStore(2)
	ps.AddPacket(scanPacket("old", "TCP"))
	var scan *PacketFilterScan
	calls := 0
	scan = ps.BeginFilter(scanChain(func(filters.Filterable) bool {
		calls++
		scan.Cancel()
		return true
	}))
	require.Nil(t, scan.Run(), "cancellation during the final predicate discards its result")
	require.Equal(t, 1, calls)
	require.False(t, ps.CompleteFilter(nil))
}

func scanPacketID(id uint64, p components.PacketDisplay) components.PacketDisplay {
	p.CaptureID = id
	return p
}
