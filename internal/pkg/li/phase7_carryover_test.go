//go:build li

package li

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestPhase7ExpiryGatesPacketsAndRetriesFilterRemoval(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	task.EndTime = time.Now().Add(20 * time.Millisecond)
	task.ImplicitDeactivationAllowed = true
	require.NoError(t, m.ActivateTask(task))
	filterID := m.filters.GetFiltersForXID(task.XID)[0]
	pusher.failDeletes[filterID] = true

	var processed atomic.Int64
	m.SetPacketProcessor(func(*InterceptTask, *types.PacketDisplay) { processed.Add(1) })
	time.Sleep(25 * time.Millisecond)
	m.registry.checkExpiredTasks()

	got, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusDeactivated, got.Status, "failed withdrawal remains enforcement-gated")
	m.ProcessPacket(&types.PacketDisplay{}, []string{filterID})
	assert.Zero(t, processed.Load())

	delete(pusher.failDeletes, filterID)
	require.NoError(t, m.DeactivateTask(task.XID))
	require.NoError(t, m.DeactivateTask(task.XID), "concurrent/retried cleanup is idempotent")
	got, err = m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusDeactivated, got.Status)
	assert.Empty(t, pusher.installed)
}

func TestPhase7PacketCallbackReplacementIsRaceSafe(t *testing.T) {
	m, _, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	filterID := m.filters.GetFiltersForXID(task.XID)[0]
	pkt := &types.PacketDisplay{}

	var calls atomic.Int64
	callback := func(*InterceptTask, *types.PacketDisplay) { calls.Add(1) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2_000; i++ {
			m.SetPacketProcessor(callback)
			if i%3 == 0 {
				m.SetPacketProcessor(nil)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2_000; i++ {
			m.ProcessPacket(pkt, []string{filterID})
			m.ProcessPacket(pkt, []string{"unmatched"})
		}
	}()
	wg.Wait()

	m.SetPacketProcessor(callback)
	m.ProcessPacket(pkt, []string{filterID})
	assert.Positive(t, calls.Load())
}
