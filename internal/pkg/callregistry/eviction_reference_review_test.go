package callregistry

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type evictionReviewObserver struct{ events []string }

func (o *evictionReviewObserver) OnCallStarted(c Call) {
	o.events = append(o.events, "start:"+c.CallID)
}

func (o *evictionReviewObserver) OnCallEnded(c Call, reason EndReason) {
	o.events = append(o.events, "end:"+c.CallID+":"+string(reason))
}

// A constant-zero callback retains the original full eviction scan. Compare it
// with the nil-priority shortcut across mutations, including nested pins and
// shared endpoints whose cached winner depends on recency.
func TestEvictionShortcutMatchesOriginalFullScan(t *testing.T) {
	for _, capacity := range []int{1, 3, 11} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			fastObserver, referenceObserver := &evictionReviewObserver{}, &evictionReviewObserver{}
			config := Config{MaxCalls: capacity, MaxEndpointsPerCall: 3, MaxEndpointAssociations: 9, Observers: []LifecycleObserver{fastObserver}}
			fast := New(config)
			config.Observers = []LifecycleObserver{referenceObserver}
			config.EvictionPriority = func(Call) int { return 0 }
			reference := New(config)
			random := rand.New(rand.NewSource(72341))
			for step := 0; step < 1500; step++ {
				id := fmt.Sprint(random.Intn(17))
				endpoint := fmt.Sprint(random.Intn(7))
				at := time.Unix(int64(step), 0)
				switch random.Intn(12) {
				case 0, 1, 2, 3, 4:
					before := reference.ActiveCalls()
					call := Call{CallID: id, State: endpoint, LastUpdated: at}
					accepted, evicted := fast.UpsertWithEviction(call)
					require.Equal(t, reference.Upsert(call), accepted)
					// Independently derive eviction as the original tracker did.
					wantEvicted := ""
					for _, previous := range before {
						if _, remains := reference.Call(previous.CallID); !remains {
							require.Empty(t, wantEvicted)
							wantEvicted = previous.CallID
						}
					}
					require.Equal(t, wantEvicted, evicted)
				case 5:
					fast.Pin(id)
					reference.Pin(id)
				case 6:
					fast.Unpin(id)
					reference.Unpin(id)
				case 7:
					require.Equal(t, reference.Touch(id, at), fast.Touch(id, at))
				case 8:
					require.Equal(t, reference.Remove(id, EndCompleted), fast.Remove(id, EndCompleted))
				case 9:
					require.Equal(t, reference.TryAssociateEndpoint(id, endpoint), fast.TryAssociateEndpoint(id, endpoint))
				case 10:
					fast.DissociateEndpoints(id)
					reference.DissociateEndpoints(id)
				case 11:
					if step%31 == 0 {
						fast.Clear()
						reference.Clear()
					}
				}
				require.Equal(t, reference.ActiveCalls(), fast.ActiveCalls(), "step %d", step)
				require.Equal(t, referenceObserver.events, fastObserver.events, "step %d", step)
				require.Equal(t, reference.EndpointAssociationCount(), fast.EndpointAssociationCount())
				for n := 0; n < 17; n++ {
					id := fmt.Sprint(n)
					require.Equal(t, reference.IsPinned(id), fast.IsPinned(id))
					require.Equal(t, reference.EndpointsForCall(id), fast.EndpointsForCall(id))
				}
				for n := 0; n < 7; n++ {
					endpoint := fmt.Sprint(n)
					require.Equal(t, reference.CallIDsForEndpoint(endpoint), fast.CallIDsForEndpoint(endpoint))
					want, wantOK := reference.MostRecentCallIDForEndpoint(endpoint)
					got, gotOK := fast.MostRecentCallIDForEndpoint(endpoint)
					require.Equal(t, want, got)
					require.Equal(t, wantOK, gotOK)
				}
			}
			fast.Close()
			reference.Close()
			require.Equal(t, referenceObserver.events, fastObserver.events)
			accepted, evicted := fast.UpsertWithEviction(Call{CallID: "closed"})
			require.False(t, accepted)
			require.Empty(t, evicted)
		})
	}
}
