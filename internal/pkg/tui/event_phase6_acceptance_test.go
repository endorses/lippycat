//go:build tui || all

package tui

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// Exercise the same interaction sequence across local delivery, remote delivery,
// and an installed offline session. Offline events here are controlled retained
// history inputs; production indexing/EOF delivery is covered by indexer tests.
func TestEventPhase6MixedModeAcceptance(t *testing.T) {
	for _, mode := range []string{"live", "remote", "offline-ready"} {
		t.Run(mode, func(t *testing.T) {
			var m Model
			if mode == "offline-ready" {
				m = readyOfflineBrowser(t)
				m.eventStore.Reset()
			} else {
				m = NewModel(8, 8, "test0", "", nil, false, mode == "remote", "", true)
				t.Cleanup(func() { m.Shutdown() })
			}
			m.uiState.Tabs.SetActive(0)
			m.uiState.ViewMode = "events"
			m.uiState.Width, m.uiState.Height = 160, 32
			m.uiState.EventShowDetails = true
			now := time.Now().Add(time.Hour)
			m.syncEventsViewAt(now)
			full := m.eventViewFullSyncCount
			for batch := range 10 {
				msg := EventBatchMsg{Batch: makeEventBatch(4, fmt.Sprintf("batch-%d", batch)), Local: mode != "remote"}
				for i, event := range msg.Batch.Events {
					envelope := event.Envelope()
					envelope.Provenance.CaptureSource = "fixture"
					msg.Batch.Events[i] = events.NewDNSEvent(envelope)
				}
				before := m.eventViewSyncCount
				m, _ = m.handleEventBatchMsg(msg)
				m.refreshEventsView(now)
				require.Equal(t, before, m.eventViewSyncCount)
				now = now.Add(time.Second)
				m.refreshEventsView(now)
				require.Equal(t, before+1, m.eventViewSyncCount)
				require.Equal(t, full, m.eventViewFullSyncCount, "ordinary arrivals must remain incremental")
			}
			stats := m.eventStore.Stats()
			require.EqualValues(t, 40, stats.Arrived)
			require.EqualValues(t, 8, stats.Retained)
			require.EqualValues(t, 32, stats.Evicted)
			require.Zero(t, stats.TransportLost)

			// Protocol, source and user filters intersect without changing totals.
			m.eventStore.SetKindFilter([]events.Kind{events.KindDNS})
			m.eventStore.SetSourceFilter([]string{"fixture"})
			require.NoError(t, m.eventStore.AddUserFilter("kind:dns"))
			m.syncEventsView()
			require.Len(t, m.eventStore.Events(), 8)
			require.Equal(t, stats, m.eventStore.Stats())
			m.eventStore.SetSourceFilter([]string{"missing"})
			m.syncEventsView()
			require.Empty(t, m.uiState.EventsView.SelectedID())
			m.eventStore.SetSourceFilter(nil)
			m.eventStore.ClearUserFilters()
			m.syncEventsView()

			for _, msg := range []tea.Msg{
				tea.KeyMsg{Type: tea.KeyUp},
				tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp, X: 5, Y: 10},
				tea.WindowSizeMsg{Width: 120, Height: 24},
			} {
				updated, _ := m.update(msg)
				m = updated.(Model)
				m.prepareViewChrome()
			}
			require.NotEmpty(t, m.eventStore.SelectedID())
			require.NotEqual(t, "batch-9-3", m.eventStore.SelectedID())
			m.uiState.EventsView.ScrollDetailsToBottom()
			beforeView := fmt.Sprintf("%#v", *m.uiState.EventsView)
			beforeSync := m.eventViewSyncCount
			for range 3 {
				require.NotEmpty(t, m.View())
			}
			require.Equal(t, beforeView, fmt.Sprintf("%#v", *m.uiState.EventsView))
			require.Equal(t, beforeSync, m.eventViewSyncCount)

			m, _ = m.handlePauseResume()
			m, _ = m.handleEventBatchMsg(EventBatchMsg{Local: mode != "remote", Batch: types.EventBatch{
				Events: makeEventBatch(3, "paused").Events, Losses: []types.EventLoss{{Count: 2}}, CompatibilityOmissions: 1,
			}})
			m, _ = m.handlePauseResume()
			require.EqualValues(t, 43, m.eventStore.Stats().Arrived)
			require.EqualValues(t, 3, m.eventStore.Stats().Paused)
			require.EqualValues(t, 3, m.eventStore.Stats().TransportLost)
			require.EqualValues(t, 8, m.eventStore.Stats().Retained)
			m, _ = m.handleClearPackets()
			require.Empty(t, m.uiState.EventsView.SelectedID())
			require.Zero(t, m.eventStore.Stats().Arrived)
			if mode == "offline-ready" {
				require.EqualValues(t, 1077, m.offlineSession.Dataset.Count(), "clearing event history must preserve the packet dataset")
			}
		})
	}
}

// Ready offline sessions have no arrival work. Include model ticks/chrome and
// rendering after publication and one page/detail/relationship load; setup and
// indexing are outside the timer. This is idle CPU per UI cycle, not frame time
// during indexing or a substitute for the active-stream benchmarks above.
func BenchmarkEventPhase6OfflineReadyViews(b *testing.B) {
	for _, view := range []string{"events", "packets", "statistics"} {
		b.Run(view, func(b *testing.B) {
			previous := viper.ConfigFileUsed()
			viper.SetConfigFile(filepath.Join(b.TempDir(), "config.yaml"))
			b.Cleanup(func() { viper.SetConfigFile(previous) })
			paths := writePhase6MixedSources(b, b.TempDir(), 20000, 1)
			m := NewModel(10000, 8, "", "", paths, false, false, "", false)
			open := FreezeOfflineOpen(paths, "", 10000)
			open.Limits.Directory = b.TempDir()
			m, cmd := m.openOffline(open)
			result := cmd().(tea.BatchMsg)[0]().(offlineOpenCompleteMsg)
			require.NoError(b, result.err)
			m, _ = m.completeOffline(result)
			b.Cleanup(func() { require.NoError(b, m.CloseOffline()); m.Shutdown() })
			m.uiState.Width, m.uiState.Height = 160, 40
			m.uiState.ViewMode = view
			m.uiState.EventShowDetails = true
			if view == "statistics" {
				m.uiState.Tabs.SetActive(2)
			} else if view == "packets" {
				msg := m.syncOfflineBrowser()().(offlineBrowseMsg)
				require.NoError(b, msg.result.err)
				m, _ = m.handleOfflineBrowse(msg)
			} else {
				m.syncEventsView()
				if cmd := m.requestOfflineRelated(); cmd != nil {
					msg := cmd().(offlineRelatedMsg)
					require.NoError(b, msg.err)
					m, _ = m.handleOfflineRelated(msg)
				}
			}
			m.prepareViewChrome()
			before := m.eventViewSyncCount
			clock := time.Now().Add(time.Hour)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				clock = clock.Add(constants.TUITickInterval)
				m, _ = m.handleTickMsg(TickMsg{Time: clock})
				m.prepareViewChrome()
				if m.View() == "" {
					b.Fatal("empty ready view")
				}
			}
			b.StopTimer()
			require.Equal(b, before, m.eventViewSyncCount, "idle ready views must not reproject event history")
			require.EqualValues(b, 20000, m.offlineSession.Dataset.Count())
		})
	}
}

// Compare identical bounded delivery/ingestion workloads in each active view.
// This isolates presentation CPU from network, analyzers, and terminal output;
// BenchmarkModelEventDNSReplay separately includes decoding and DNS analysis.
func BenchmarkEventPhase6ModeViews(b *testing.B) {
	for _, remote := range []bool{false, true} {
		mode := "live"
		if remote {
			mode = "remote"
		}
		for _, view := range []string{"events", "packets", "statistics"} {
			b.Run(mode+"/"+view, func(b *testing.B) {
				pendingLocalEvents.clear()
				b.Cleanup(pendingLocalEvents.clear)
				previousTelemetry := GetIngressTelemetrySnapshot()
				b.Cleanup(func() { publishIngressTelemetry(previousTelemetry) })
				m := NewModel(10000, 8, "test0", "", nil, false, remote, "", true)
				b.Cleanup(func() { m.Shutdown() })
				m.uiState.Capturing = true
				m.uiState.ViewMode = view
				m.uiState.Tabs.SetActive(0)
				m.uiState.Width, m.uiState.Height = 160, 40
				if view == "statistics" {
					m.uiState.Tabs.SetActive(2)
				}
				pool := makeEventBatch(10050, mode).Events
				packets := make([]components.PacketDisplay, 50)
				for i := range packets {
					packets[i] = components.PacketDisplay{Timestamp: time.Unix(1, 0), Protocol: "DNS", Length: 100, SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "80", Transport: 6}
					if remote {
						packets[i].NodeID = "processor"
					}
				}
				m.eventStore.AddBatch(pool[:10000])
				for range 200 {
					m, _ = m.handlePacketBatchMsg(PacketBatchMsg{Packets: packets})
				}
				m.syncEventsView()
				m.prepareViewChrome()
				initialSync := m.eventViewSyncCount
				clock := time.Now().Add(time.Hour)
				next := 0
				delivered := int64(10000)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					batch := types.EventBatch{Events: pool[next : next+50]}
					if remote {
						m.pendingRemoteEvents.addBatch(batch)
					} else {
						pendingLocalEvents.addBatch(batch)
					}
					m, _ = m.handlePacketBatchMsg(PacketBatchMsg{Packets: packets})
					delivered += 50
					if !remote {
						// Live totals arrive separately from the sampled packet feed.
						publishIngressTelemetry(IngressTelemetrySnapshot{
							Packets: delivered, Bytes: delivered * 100, MinPacketSize: 100, MaxPacketSize: 100,
							ProtocolCounts: map[string]int64{"TCP": delivered},
							SourceCounts:   map[string]int64{"192.0.2.1": delivered}, DestCounts: map[string]int64{"198.51.100.2": delivered},
						})
					}
					clock = clock.Add(constants.TUITickInterval)
					m, _ = m.handleTickMsg(TickMsg{Time: clock})
					m.prepareViewChrome()
					if m.View() == "" {
						b.Fatal("empty view")
					}
					next = (next + 50) % len(pool)
				}
				b.StopTimer()
				require.Zero(b, m.eventStore.Stats().TransportLost)
				require.EqualValues(b, 10000, m.eventStore.Stats().Retained)
				require.EqualValues(b, 10000+50*b.N, m.eventStore.Stats().Arrived)
				require.EqualValues(b, 10000+50*b.N, m.statistics.TotalPackets)
				require.Equal(b, 10000, m.packetStore.Count())
				if view == "events" {
					require.EqualValues(b, uint64(b.N), m.eventViewSyncCount-initialSync)
				} else {
					require.Equal(b, initialSync, m.eventViewSyncCount)
				}
				b.ReportMetric(50, "packets/op")
			})
		}
	}
}
