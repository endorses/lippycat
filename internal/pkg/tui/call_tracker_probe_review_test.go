//go:build tui || all

package tui

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/stretchr/testify/require"
)

type insertionProbeReviewRegistry struct {
	*callregistry.Core
	probes int
}

func (s *insertionProbeReviewRegistry) Call(id string) (callregistry.Call, bool) {
	s.probes++
	return s.Core.Call(id)
}

func (*insertionProbeReviewRegistry) ActiveCalls() []callregistry.Call {
	panic("insertion must not snapshot active calls")
}

func TestCallTrackerInsertionProbesDoNotGrowWithCapacity(t *testing.T) {
	for _, capacity := range []int{1, 100, DefaultMaxTrackedCalls} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			tracker := NewCallTrackerWithCapacity(capacity)
			core := tracker.registry.(*callregistry.Core)
			for i := 0; i < capacity; i++ {
				require.True(t, core.Upsert(callregistry.Call{CallID: fmt.Sprint(i)}))
			}
			spy := &insertionProbeReviewRegistry{Core: core}
			tracker.registry = spy
			tracker.mu.Lock()
			tracker.touchCallLocked("new")
			tracker.touchCallLocked("new")
			tracker.mu.Unlock()
			require.Equal(t, 2, spy.probes, "one existence probe per touch, regardless of capacity")
			require.Equal(t, capacity, core.ActiveCallCount())
			_, oldestRemains := core.Call("0")
			require.False(t, oldestRemains)
		})
	}
}
