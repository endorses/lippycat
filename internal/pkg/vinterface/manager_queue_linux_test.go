//go:build linux

package vinterface

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestInjectPacketReturnsQueueFullWhenPacketIsDropped(t *testing.T) {
	m := newStartedTestManager(t, 1)
	require.NoError(t, m.InjectPacket([]byte("first")))

	err := m.InjectPacket([]byte("second"))

	require.ErrorIs(t, err, ErrQueueFull)
	require.Equal(t, uint64(1), m.Stats().PacketsDropped)
}

func TestInjectPacketBatchReturnsQueueFullWhenAnyPacketIsDropped(t *testing.T) {
	m := newStartedTestManager(t, 1)
	packet := types.PacketDisplay{RawData: []byte{0x45, 0, 0, 20}, LinkType: 101}

	err := m.InjectPacketBatch([]types.PacketDisplay{packet, packet})

	require.ErrorIs(t, err, ErrQueueFull)
	require.Equal(t, uint64(1), m.Stats().PacketsDropped)
}

func newStartedTestManager(t *testing.T, bufferSize int) *linuxManager {
	t.Helper()
	mgr, err := NewManager(Config{Name: "test0", Type: "tun", BufferSize: bufferSize, MTU: 1500})
	require.NoError(t, err)
	m := mgr.(*linuxManager)
	m.started.Store(true)
	return m
}
