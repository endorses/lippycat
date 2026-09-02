package detector

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStateMachineCleanupExpirationIsBounded(t *testing.T) {
	sm := NewStateMachine(time.Minute)
	t.Cleanup(sm.Close)

	now := time.Now()
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("expired-%d", i)
		sm.Set(key, i)
		sm.mu.Lock()
		sm.states[key].LastUpdate = now.Add(-2 * time.Minute)
		sm.mu.Unlock()
	}
	sm.Set("live", 6)

	assert.Equal(t, 2, sm.cleanupExpired(now, 2))
	assert.Equal(t, 4, sm.Size())
	_, live := sm.Get("live")
	assert.True(t, live)

	assert.Equal(t, 3, sm.cleanupExpired(now, 16))
	assert.Equal(t, 1, sm.Size())
}

func TestStateMachineCleanupSchedulingTracksDeleteAndClear(t *testing.T) {
	sm := NewStateMachine(time.Minute)
	t.Cleanup(sm.Close)

	sm.Set("delete", 1)
	sm.Set("clear", 2)
	sm.Delete("delete")
	assert.NotContains(t, sm.cleanupElements, "delete")
	assert.Equal(t, 1, sm.cleanupOrder.Len())

	sm.Clear()
	assert.Empty(t, sm.cleanupElements)
	assert.Zero(t, sm.cleanupOrder.Len())
}

func TestStateMachineCloseIsConcurrentAndWaitable(t *testing.T) {
	sm := NewStateMachine(time.Hour)

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sm.Close()
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-sm.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("state cleanup goroutine survived Close")
	}
}
