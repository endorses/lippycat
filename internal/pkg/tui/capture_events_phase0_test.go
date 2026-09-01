package tui

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/require"
)

func TestCaptureTelemetryMsgPreservesNamedLocalBufferDrops(t *testing.T) {
	m := Model{uiState: store.NewUIState(themes.Solarized())}

	updatedModel, _ := m.Update(CaptureTelemetryMsg(capture.Telemetry{
		PacketsReceived:          100,
		PacketBufferDrops:        9,
		PacketBufferRegularDrops: 6,
		PacketBufferSIPDrops:     3,
	}))
	updated, ok := updatedModel.(Model)
	require.True(t, ok)

	summary := updated.uiState.StatisticsView.GetDropSummary()
	require.Equal(t, int64(9), summary.BufferDrops)
	require.Equal(t, int64(6), summary.BufferRegularDrops)
	require.Equal(t, int64(3), summary.BufferSIPDrops)
}

func TestHandleHunterStatusMsgUpdatesExistingHunterLossCounters(t *testing.T) {
	processorAddr := "processor.test:55555"
	m := Model{
		uiState:       store.NewUIState(themes.Solarized()),
		connectionMgr: store.NewConnectionManager(),
	}
	m.connectionMgr.HuntersByProcessor[processorAddr] = []components.HunterInfo{{
		ID:            "hunter-test",
		ProcessorAddr: processorAddr,
	}}

	updated, _ := m.handleHunterStatusMsg(HunterStatusMsg{
		ProcessorAddr:   processorAddr,
		ProcessorStatus: management.ProcessorStatus_PROCESSOR_HEALTHY,
		Hunters: []components.HunterInfo{{
			ID:                        "hunter-test",
			PacketsDropped:            9,
			CaptureBufferRegularDrops: 4,
			CaptureBufferSIPDrops:     2,
			BatchChannelDrops:         3,
		}},
	})

	require.Len(t, updated.connectionMgr.HuntersByProcessor[processorAddr], 1)
	got := updated.connectionMgr.HuntersByProcessor[processorAddr][0]
	require.Equal(t, uint64(9), got.PacketsDropped)
	require.Equal(t, uint64(4), got.CaptureBufferRegularDrops)
	require.Equal(t, uint64(2), got.CaptureBufferSIPDrops)
	require.Equal(t, uint64(3), got.BatchChannelDrops)
}
