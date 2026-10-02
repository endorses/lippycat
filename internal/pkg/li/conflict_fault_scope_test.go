//go:build li

package li

import (
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Current primitives fault the shared administrative owner on interrupted
// withdrawal. These cases document why a task-local filter cleanup alone cannot
// safely reopen unrelated admission after a failed narrowing.
func TestConflictFaultScopeWithUnrelatedTask(t *testing.T) {
	for _, failure := range []string{"none", "product_revocation", "filter", "reservation", "uncertain_checkpoint"} {
		t.Run(failure, func(t *testing.T) {
			m, pusher, _, dids := administrativeTransactionManager(t)
			first := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
			second := idempotencyTask(uuid.New(), dids, first.StartTime)
			require.NoError(t, m.ActivateTask(first))
			require.NoError(t, m.ActivateTask(second))
			before, err := m.GetTaskDetails(first.XID)
			require.NoError(t, err)
			unrelated, err := m.GetTaskDetails(second.XID)
			require.NoError(t, err)
			switch failure {
			case "product_revocation":
				m.SetTaskConflictCallback(func(*InterceptTask) error { return errors.New("revocation incomplete") })
			case "filter":
				pusher.failNext = true
			case "reservation", "uncertain_checkpoint":
				store := m.stateStore.(*EncryptedStateStore)
				write := store.write
				t.Cleanup(func() { store.write = write })
				store.write = func(string, []byte) (securestore.Outcome, error) {
					outcome := securestore.NotCommitted
					if failure == "uncertain_checkpoint" {
						outcome = securestore.Uncertain
					}
					return outcome, errors.New("administrative storage failure")
				}
			}
			incoming := conflictSnapshot(before)
			incoming.Task.Targets = incoming.Task.Targets[:1]
			err = m.applySnapshotDefinition(incoming)
			if failure == "none" {
				require.NoError(t, err)
				require.Nil(t, m.stateFault.Load())
			} else {
				require.Error(t, err)
				require.NotNil(t, m.stateFault.Load())
			}
			lease, ok := m.AcquireTaskAdmission(second.XID, unrelated.ActivationGeneration)
			if lease != nil {
				lease.Release()
			}
			require.Equal(t, failure == "none", ok)
			lease, ok = m.AcquireTaskAdmission(first.XID, before.ActivationGeneration)
			if lease != nil {
				lease.Release()
			}
			require.False(t, ok, "the withdrawn generation must never resume")
			current, err := m.GetTaskDetails(second.XID)
			require.NoError(t, err)
			require.Equal(t, unrelated, current, "global admission fault does not rewrite unrelated authorization")
		})
	}
}
