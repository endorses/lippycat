//go:build li

package li

import (
	"errors"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// RevocationRequest is a detached previous authorization identity. Numeric
// destination revisions are deliberately separate from the delivery identity
// hash, which also binds the destination's creation identity and endpoint.
type RevocationRequest struct {
	OperationID           uuid.UUID
	StateIncarnation      uuid.UUID
	Kind                  StateIntentKind
	Task                  *InterceptTask
	Destination           *StateDestination
	DestinationGeneration uint64
}

// DurableRevoker separates side-effect-free planning from journal mutation.
// Prepare returns at most one exact control per affected journal (at most 256),
// without writing or revoking anything. The coordinator persists that complete
// plan before Commit. Commit is idempotent for the supplied stable control IDs
// and reports the outcome of the complete multi-journal boundary. An uncertain
// or partially committed result must be Uncertain, never NotCommitted.
// Methods run under administrative/admission barriers and may read manager state
// but must not recursively mutate it or acquire task admission.
type DurableRevoker interface {
	Prepare(RevocationRequest) ([]*StateRevocation, error)
	Commit([]*StateRevocation) (securestore.Outcome, error)
}

// SetDurableRevoker must run before Start or any administrative mutation. A nil
// hook preserves current memory-only revocation behavior; real journal wiring
// installs a hook before exposing a manager to capture or X1 administration.
func (m *Manager) SetDurableRevoker(revoker DurableRevoker) error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.administrativeError(); err != nil {
		return err
	}
	if m.stateReady.Load() || m.registry.TaskCount() != 0 || m.registry.DestinationCount() != 0 {
		return errors.New("durable revoker must be registered before administrative startup")
	}
	if revoker != nil && m.config.StateFile == "" {
		return errors.New("durable revocation requires encrypted administrative state")
	}
	m.durableRevoker = revoker
	return nil
}

func stateDestination(d *Destination) *StateDestination {
	if d == nil {
		return nil
	}
	return &StateDestination{DID: d.DID, Address: d.Address, Port: d.Port, X2Enabled: d.X2Enabled, X3Enabled: d.X3Enabled,
		ProtocolType: d.ProtocolType, Description: d.Description, CreatedAt: d.CreatedAt, DeliveryRevision: d.DeliveryRevision}
}

func (m *Manager) prepareRevocationsLocked(intent *StateIntent, task *InterceptTask, dest *Destination) ([]*StateRevocation, error) {
	if m.durableRevoker == nil {
		return []*StateRevocation{}, nil
	}
	request := RevocationRequest{OperationID: intent.OperationID, StateIncarnation: m.stateID, Kind: intent.Kind,
		Task: cloneInterceptTask(task), Destination: stateDestination(dest)}
	if dest != nil {
		request.DestinationGeneration = DestinationDeliveryGeneration(dest)
	}
	controls, err := m.durableRevoker.Prepare(request)
	if err != nil {
		return nil, &securestore.CommitError{Outcome: securestore.NotCommitted, Op: "prepare administrative revocation", Err: err}
	}
	if len(controls) > maxStateReferences {
		return nil, &securestore.CommitError{Outcome: securestore.NotCommitted, Op: "prepare administrative revocation", Err: stateError("revocation plan count")}
	}
	ids, journals := make(map[uuid.UUID]bool), make(map[uuid.UUID]bool)
	detached := make([]*StateRevocation, 0, len(controls))
	for _, control := range controls {
		if err := validateStateRevocation(control, m.stateID); err != nil {
			return nil, err
		}
		if ids[control.ControlID] || journals[control.JournalUUID] {
			return nil, stateError("duplicate revocation plan identity")
		}
		ids[control.ControlID], journals[control.JournalUUID] = true, true
		if task != nil {
			if control.Scope != StateRevokeTask || control.XID == nil || *control.XID != task.XID || control.TaskGeneration == nil || *control.TaskGeneration != task.ActivationGeneration {
				return nil, stateError("prepared task revocation binding")
			}
		} else if dest != nil {
			if control.Scope != StateRevokeDestination || control.DID == nil || *control.DID != dest.DID || control.DestinationGeneration == nil || *control.DestinationGeneration != request.DestinationGeneration {
				return nil, stateError("prepared destination revocation binding")
			}
		} else {
			return nil, stateError("revocation plan subject")
		}
		for _, existing := range m.stateRevocations {
			if existing.ControlID == control.ControlID {
				return nil, stateError("reused revocation control identity")
			}
		}
		detached = append(detached, cloneStateRevocation(control))
	}
	return detached, nil
}

func (m *Manager) commitRevocationsLocked(controls []*StateRevocation) (securestore.Outcome, error) {
	if len(controls) == 0 {
		return securestore.Committed, nil
	}
	if m.durableRevoker == nil {
		return securestore.NotCommitted, errors.New("recorded journal revocations require a durable revoker")
	}
	// A hook cannot change the administrative owner’s recorded plan.
	copies := make([]*StateRevocation, len(controls))
	for n, control := range controls {
		copies[n] = cloneStateRevocation(control)
	}
	out, err := m.durableRevoker.Commit(copies)
	if err == nil && out != securestore.Committed {
		err = errors.New("journal revocation did not commit")
	}
	if err != nil {
		return out, &securestore.CommitError{Outcome: out, Op: "commit administrative revocation", Err: err}
	}
	return out, nil
}

func cloneStateRevocation(control *StateRevocation) *StateRevocation {
	copyControl := *control
	if control.XID != nil {
		id := *control.XID
		copyControl.XID = &id
	}
	if control.DID != nil {
		id := *control.DID
		copyControl.DID = &id
	}
	if control.CallIncarnation != nil {
		id := *control.CallIncarnation
		copyControl.CallIncarnation = &id
	}
	if control.TaskGeneration != nil {
		value := *control.TaskGeneration
		copyControl.TaskGeneration = &value
	}
	if control.DestinationGeneration != nil {
		value := *control.DestinationGeneration
		copyControl.DestinationGeneration = &value
	}
	if control.CallGeneration != nil {
		value := *control.CallGeneration
		copyControl.CallGeneration = &value
	}
	return &copyControl
}
