package filtering

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

// Pause the first capability lookup after a mutation has committed, while
// allowing later lookups to proceed. This exposes distribution ordering without
// blocking the manager's storage mutex or requiring an actual gRPC connection.
type radiusBlockingCapabilities struct {
	armed     atomic.Bool
	entered   chan struct{}
	release   chan struct{}
	readState func() int
}

func (c *radiusBlockingCapabilities) GetCapabilities(string) *management.HunterCapabilities {
	if c.readState != nil {
		c.readState() // Distribution callbacks may inspect current state.
	}
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return &management.HunterCapabilities{FilterTypes: []string{"radius_username"}, RadiusFilterVersion: 1}
}

func TestRADIUSConcurrentMutationDistributionOrder(t *testing.T) {
	for _, tc := range []struct {
		name         string
		firstDelete  bool
		secondDelete bool
	}{
		{name: "modify_then_modify"},
		{name: "modify_then_delete", secondDelete: true},
		{name: "delete_then_recreate", firstDelete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := &radiusBlockingCapabilities{entered: make(chan struct{}), release: make(chan struct{})}
			m := NewManager("", nil, caps, nil, nil)
			caps.readState = m.Count
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(caps.release) }) }
			defer release()
			updates := m.AddChannel("hunter")
			filter := func(revision uint64) *management.Filter {
				return &management.Filter{Id: "user", Revision: revision, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Enabled: true}
			}
			_, err := m.Update(filter(1))
			require.NoError(t, err)
			<-updates

			caps.armed.Store(true)
			firstDone := make(chan error, 1)
			go func() {
				var err error
				if tc.firstDelete {
					_, err = m.Delete("user")
				} else {
					_, err = m.Update(filter(2))
				}
				firstDone <- err
			}()
			select {
			case <-caps.entered:
			case <-time.After(time.Second):
				release()
				t.Fatal("first mutation did not reach distribution")
			}
			secondStarted := make(chan struct{})
			secondDone := make(chan error, 1)
			go func() {
				close(secondStarted)
				var err error
				if tc.secondDelete {
					_, err = m.Delete("user")
				} else {
					_, err = m.Update(filter(3))
				}
				secondDone <- err
			}()
			<-secondStarted
			// The first distribution is deliberately held open. A serialized
			// second mutation must wait; the previous implementation completed
			// it here and sent its update ahead of the first mutation.
			var secondErr error
			secondFinished := false
			select {
			case secondErr = <-secondDone:
				secondFinished = true
			case <-time.After(50 * time.Millisecond):
			}
			release()
			select {
			case err = <-firstDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("first mutation did not finish")
			}
			if !secondFinished {
				select {
				case secondErr = <-secondDone:
				case <-time.After(time.Second):
					t.Fatal("second mutation did not finish")
				}
			}
			require.NoError(t, secondErr)
			require.Len(t, updates, 2, "both mutations must distribute exactly one update")
			first, second := <-updates, <-updates
			if tc.firstDelete {
				require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, first.UpdateType)
				require.Equal(t, management.FilterUpdateType_UPDATE_ADD, second.UpdateType)
				require.EqualValues(t, 3, second.Filter.Revision)
			} else {
				require.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, first.UpdateType)
				require.EqualValues(t, 2, first.Filter.Revision)
				if tc.secondDelete {
					require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, second.UpdateType)
					require.Empty(t, m.GetAll())
				} else {
					require.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, second.UpdateType)
					require.EqualValues(t, 3, second.Filter.Revision)
				}
			}
			if !tc.secondDelete {
				require.EqualValues(t, 3, m.GetAll()[0].Revision)
			}
		})
	}
}
