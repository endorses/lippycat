//go:build tui || all

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
		PacketsReceived:           100,
		PacketBufferDrops:         9,
		PacketBufferRegularDrops:  6,
		PacketBufferSIPDrops:      3,
		PacketBufferSIPDemotions:  4,
		PacketBufferRegularLength: 5, PacketBufferRegularCap: 15,
		PacketBufferSIPLength: 6, PacketBufferSIPCap: 16,
		PacketBufferOutputLength: 7, PacketBufferOutputCap: 17,
	}))
	updated, ok := updatedModel.(Model)
	require.True(t, ok)

	summary := updated.uiState.StatisticsView.GetDropSummary()
	require.Equal(t, int64(9), summary.BufferDrops)
	require.Equal(t, int64(6), summary.BufferRegularDrops)
	require.Equal(t, int64(3), summary.BufferSIPDrops)
	require.Equal(t, int64(4), summary.SIPDemotions)
	require.Equal(t, 5, summary.BufferRegularLength)
	require.Equal(t, 15, summary.BufferRegularCapacity)
	require.Equal(t, 6, summary.BufferSIPLength)
	require.Equal(t, 16, summary.BufferSIPCapacity)
	require.Equal(t, 7, summary.BufferOutputLength)
	require.Equal(t, 17, summary.BufferOutputCapacity)
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
			CaptureBufferSIPDemotions: 8,
			BatchChannelDrops:         3,
			CaptureBufferRegularLen:   10, CaptureBufferRegularCapacity: 20,
			CaptureBufferSIPLen: 11, CaptureBufferSIPCapacity: 21,
			CaptureBufferOutputLen: 12, CaptureBufferOutputCapacity: 22,
		}},
	})

	require.Len(t, updated.connectionMgr.HuntersByProcessor[processorAddr], 1)
	got := updated.connectionMgr.HuntersByProcessor[processorAddr][0]
	require.Equal(t, uint64(9), got.PacketsDropped)
	require.Equal(t, uint64(4), got.CaptureBufferRegularDrops)
	require.Equal(t, uint64(2), got.CaptureBufferSIPDrops)
	require.Equal(t, uint64(8), got.CaptureBufferSIPDemotions)
	require.Equal(t, uint64(3), got.BatchChannelDrops)
	require.Equal(t, uint64(10), got.CaptureBufferRegularLen)
	require.Equal(t, uint64(20), got.CaptureBufferRegularCapacity)
	require.Equal(t, uint64(11), got.CaptureBufferSIPLen)
	require.Equal(t, uint64(21), got.CaptureBufferSIPCapacity)
	require.Equal(t, uint64(12), got.CaptureBufferOutputLen)
	require.Equal(t, uint64(22), got.CaptureBufferOutputCapacity)
}
