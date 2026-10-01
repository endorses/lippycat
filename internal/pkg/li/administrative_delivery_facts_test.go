//go:build li

package li

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCommittedTaskFactsIncludeTimingOnlyUpdateAndAreDetached(t *testing.T) {
	m, _, _, dids := administrativeTransactionManager(t)
	var facts []*InterceptTask
	m.SetCommittedTaskCallback(func(task *InterceptTask) {
		facts = append(facts, cloneInterceptTask(task))
		task.Targets[0].Value = "callback mutation"
	})
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	require.Len(t, facts, 1)
	end := task.EndTime.Add(time.Hour)
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{EndTime: &end}))
	require.Len(t, facts, 2)
	require.Equal(t, facts[0].ActivationGeneration, facts[1].ActivationGeneration)
	require.Equal(t, end, facts[1].EndTime, "timing facts publish without another packet")
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.NotEqual(t, "callback mutation", current.Targets[0].Value)
}

func TestCommittedTaskFactsExcludeFailedAndUncertainProvisionalUpdates(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			m, _, _, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			var updates int
			m.SetCommittedTaskCallback(func(*InterceptTask) { updates++ })
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			writes := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				writes++
				if writes == 2 {
					if outcome == securestore.Committed {
						_, err := write(name, data)
						require.NoError(t, err)
					}
					return outcome, errors.New("injected final snapshot outcome")
				}
				return write(name, data)
			}
			end := task.EndTime.Add(time.Hour)
			err := m.ModifyTask(task.XID, &TaskModification{EndTime: &end})
			require.Error(t, err)
			if outcome == securestore.Committed {
				require.Equal(t, 1, updates, "committed cleanup error still publishes current facts")
			} else {
				require.Zero(t, updates)
			}
		})
	}
}
