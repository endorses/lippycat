//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

// Opt-in terminal acceptance at the live delivery/presentation boundary. It
// intentionally requires no capture privileges and does not benchmark a NIC.
// Run the compiled test in a PTY with LIPPYCAT_PHASE6_TERMINAL_SMOKE=1.
func TestPhase6LiveTerminalSmoke(t *testing.T) {
	if os.Getenv("LIPPYCAT_PHASE6_TERMINAL_SMOKE") != "1" {
		t.Skip("opt-in interactive terminal smoke")
	}
	m := NewModel(8, 8, "controlled-live-delivery", "", nil, false, false, "", true)
	t.Cleanup(m.Shutdown)
	previousTelemetry := GetIngressTelemetrySnapshot()
	t.Cleanup(func() { publishIngressTelemetry(previousTelemetry) })
	publishIngressTelemetry(IngressTelemetrySnapshot{})
	m.uiState.Capturing = true
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseAllMotion())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			at := time.Now()
			packets := []components.PacketDisplay{{Timestamp: at, Protocol: "DNS", Length: 64, SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "53", Transport: 17}}
			delivered := int64(i + 1)
			publishIngressTelemetry(IngressTelemetrySnapshot{
				Packets: delivered, Bytes: delivered * 64, MinPacketSize: 64, MaxPacketSize: 64,
				ProtocolCounts: map[string]int64{"UDP": delivered},
				SourceCounts:   map[string]int64{"192.0.2.1": delivered}, DestCounts: map[string]int64{"198.51.100.2": delivered},
			})
			p.Send(PacketBatchMsg{Packets: packets})
			envelope := testEventEnvelope(fmt.Sprintf("terminal-%d", i), uint64(i+1))
			envelope.Timestamp = at
			envelope.NodeID = "watch-local"
			envelope.Flow.Protocol = 17
			envelope.Flow.DestinationPort = 53
			p.Send(EventBatchMsg{Local: true, Batch: types.EventBatch{Events: []events.Event{events.NewDNSEvent(envelope)}}})
		}
	}()
	result, err := p.Run()
	cancel()
	<-done
	require.NoError(t, err)
	final := result.(Model)
	stats := final.eventStore.Stats()
	require.Positive(t, stats.Arrived)
	require.Positive(t, stats.Evicted)
	require.Zero(t, stats.TransportLost)
	require.LessOrEqual(t, stats.Retained, uint64(8))
	require.Equal(t, stats.Arrived, stats.Retained+stats.Evicted+stats.Paused)
	fmt.Printf("LIVE_TERMINAL_RESULT arrived=%d retained=%d evicted=%d paused=%d lost=%d\n", stats.Arrived, stats.Retained, stats.Evicted, stats.Paused, stats.TransportLost)
}
