//go:build li

package li

import (
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// recoverAdministrativeLocked never grants admission. It completes durable
// revocations/cleanup and abandons unfinished new authorization conservatively.
// An unfinished destination removal closes every enforcing dependent task before
// removing the endpoint. The original intent/control identities survive retries.
func (m *Manager) recoverAdministrativeLocked(state *StateSnapshot) error {
	changed := len(state.CleanupNeeded) != 0
	controls := make(map[uuid.UUID]*StateRevocation, len(state.Revocations))
	for _, c := range state.Revocations {
		controls[c.ControlID] = c
	}
	for _, intent := range state.Intents {
		if intent.Phase == StateFinished {
			continue
		}
		changed = true
		planned := make([]*StateRevocation, 0, len(intent.RevocationIDs))
		for _, id := range intent.RevocationIDs {
			planned = append(planned, controls[id])
		}
		if _, err := m.commitRevocationsLocked(planned); err != nil {
			return err
		}
	}
	for _, task := range state.Tasks {
		if IsRADIUSTask(task) {
			if err := m.withdrawPersistedRADIUS(task, state.CleanupNeeded[task.XID]); err != nil {
				return err
			}
			delete(state.CleanupNeeded, task.XID)
		}
	}
	// With a listing-capable pusher, absent IDs are already complete. This matters
	// after a crash between remote deletion and the administrative checkpoint.
	var present map[string]bool
	if lister, ok := m.config.FilterPusher.(FilterLister); ok {
		present = make(map[string]bool)
		for _, id := range lister.ListFilterIDs() {
			present[id] = true
		}
	}
	cleanup := make(map[string]bool)
	for _, ids := range state.CleanupNeeded {
		for _, id := range ids {
			cleanup[id] = true
		}
	}
	for _, intent := range state.Intents {
		if intent.Phase != StateFinished {
			for _, id := range intent.CleanupFilterIDs {
				cleanup[id] = true
			}
		}
	}
	if m.config.FilterPusher != nil {
		for id := range cleanup {
			if present != nil && !present[id] {
				continue
			}
			if err := m.config.FilterPusher.DeleteFilter(id); err != nil {
				return fmt.Errorf("resume administrative filter cleanup: %w", err)
			}
		}
	}
	for _, intent := range state.Intents {
		if intent.Phase == StateFinished {
			continue
		}
		switch intent.Kind {
		case StateTaskActivate, StateTaskReactivate, StateTaskPromote, StateTaskConfirm, StateTaskModify:
			task := cloneInterceptTask(intent.CandidateTask)
			task.Status, task.LastError, task.DeactivatedAt = TaskStatusFailed, "interrupted administrative authorization abandoned", time.Now().UTC()
			replaceSnapshotTask(state, task)
			intent.Failed = true
		case StateTaskUpdate:
			// Metadata-only changes retain the committed generation; startup still
			// requires confirmation for any active/suspended task restored from disk.
			replaceSnapshotTask(state, intent.CandidateTask)
		case StateTaskDeactivate, StateTaskExpire, StateTaskFail:
			for _, task := range state.Tasks {
				if task.XID == *intent.XID {
					task.Status, task.DeactivatedAt = TaskStatusDeactivated, time.Now().UTC()
					if intent.Kind == StateTaskDeactivate {
						task.Definition.Conflict, task.Definition.ConflictDisarmed = false, false
						task.Definition.ConflictReason = ""
					}
					if intent.Kind == StateTaskFail {
						task.Status = TaskStatusFailed
						task.LastError = "interrupted administrative withdrawal"
					}
				}
			}
		case StateDestinationRemove:
			for _, task := range state.Tasks {
				if task.Status != TaskStatusActive && task.Status != TaskStatusSuspended {
					continue
				}
				for _, did := range task.DestinationIDs {
					if did == *intent.DID {
						task.Status = TaskStatusDeactivated
						task.DeactivatedAt = time.Now().UTC()
						break
					}
				}
			}
			kept := make([]*StateDestination, 0, len(state.Destinations))
			for _, d := range state.Destinations {
				if d.DID != *intent.DID {
					kept = append(kept, d)
				}
			}
			state.Destinations = kept
		case StateDestinationCreate, StateDestinationModify, StateDestinationUpdate:
			// Complete the reserved endpoint identity after revocation. Restored tasks
			// remain unconfirmed, so this cannot authorize delivery. Reverting to the
			// previous endpoint would resurrect an identity already revoked by a journal.
			replaced := false
			for n, d := range state.Destinations {
				if d.DID == *intent.DID {
					state.Destinations[n] = intent.CandidateDestination
					replaced = true
					break
				}
			}
			if !replaced {
				state.Destinations = append(state.Destinations, intent.CandidateDestination)
			}
		case StatePurge:
			if intent.XID != nil {
				kept := make([]*InterceptTask, 0, len(state.Tasks))
				for _, task := range state.Tasks {
					if task.XID != *intent.XID {
						kept = append(kept, task)
					}
				}
				state.Tasks = kept
			}
		case StateCleanup:
		default:
			return stateError("recovery intent kind")
		}
		intent.Phase = StateFinished
		if intent.Kind != StateCleanup {
			intent.CleanupFilterIDs = []string{}
		}
	}
	state.CleanupNeeded = make(map[uuid.UUID][]string)
	if changed {
		state.WrittenAt = time.Now().UTC()
		out, err := m.stateStore.SaveControl(state)
		if err != nil || out != securestore.Committed {
			if err == nil {
				err = errors.New("administrative recovery did not commit")
			}
			return &securestore.CommitError{Outcome: out, Op: "reconcile administrative intents", Err: err}
		}
	}
	return nil
}
