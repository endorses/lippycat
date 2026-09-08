//go:build li

package li

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDestinationUpdatesSerializeDeliveryCallbacks(t *testing.T) {
	for _, action := range []string{"modify", "reconcile", "remove"} {
		t.Run(action, func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true}, nil)
			did := uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "initial", Port: 443}))
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			var mu sync.Mutex
			delivered := "initial"
			m.SetDestinationModifiedCallback(func(dest *Destination) {
				// Read access and callback registration must remain safe under dispatch.
				_, err := m.GetDestination(did)
				require.NoError(t, err)
				m.SetDestinationCreatedCallback(nil)
				if dest.Address == "first" {
					close(entered)
					<-release
				}
				mu.Lock()
				delivered = dest.Address
				mu.Unlock()
			})
			m.SetDestinationRemovedCallback(func(uuid.UUID) { mu.Lock(); delivered = ""; mu.Unlock() })
			firstDone := make(chan error, 1)
			go func() { firstDone <- m.ModifyDestination(did, &Destination{DID: did, Address: "first", Port: 443}) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("first callback did not start")
			}
			secondDone := make(chan error, 1)
			go func() {
				dest := &Destination{DID: did, Address: "second", Port: 443}
				switch action {
				case "modify":
					secondDone <- m.ModifyDestination(did, dest)
				case "reconcile":
					secondDone <- m.syncDestination(dest)
				case "remove":
					secondDone <- m.RemoveDestination(did)
				}
			}()
			var early bool
			select {
			case err := <-secondDone:
				require.NoError(t, err)
				early = true
			case <-time.After(30 * time.Millisecond):
			}
			unblock()
			require.NoError(t, <-firstDone)
			if !early {
				require.NoError(t, <-secondDone)
			}
			mu.Lock()
			actual := delivered
			mu.Unlock()
			expected := "second"
			if action == "remove" {
				expected = ""
			}
			require.Equal(t, expected, actual, "delivery must finish at the newest canonical destination")
			require.False(t, early, "later destination updates must wait for the prior delivery callback")
		})
	}
}
