//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
)

var ErrStateSnapshot = errors.New("invalid LI administrative snapshot")

func stateError(class string) error { return fmt.Errorf("%w: %s", ErrStateSnapshot, class) }

// stateShape validates tokens before decoding into collections. Unlike a generic
// JSON tree, the streaming pass retains only bounded object keys and stack depth.
type stateShape struct {
	kind     byte
	fields   map[string]*stateShape
	required []string
	item     *stateShape
	nullable bool
	limit    int
	count    byte
	memory   int
}

func stateJSONSchema(legacy bool) *stateShape {
	str := &stateShape{kind: 's'}
	uid := &stateShape{kind: 'q'}
	num := &stateShape{kind: 'u'}
	boolean := &stateShape{kind: 'b'}
	stamp := &stateShape{kind: 't'}
	if legacy {
		stamp = &stateShape{kind: 'T'}
	}
	nullID := &stateShape{kind: 'q', nullable: true}
	nullNumber := &stateShape{kind: 'u', nullable: true}
	scope := &stateShape{kind: 'o', fields: map[string]*stateShape{"operator_scope": str, "profile_revision": str, "origin_node_id": str, "source_id": str}}
	target := &stateShape{kind: 'o', required: []string{"Type", "Value"}, memory: 40, fields: map[string]*stateShape{"Type": num, "Value": str}}
	completeness := &stateShape{kind: 'o', fields: map[string]*stateShape{"Mediation": boolean, "Start": boolean, "End": boolean, "EndProvided": boolean, "Implicit": boolean}}
	definition := &stateShape{kind: 'o', fields: map[string]*stateShape{"Source": str, "Completeness": completeness, "Restored": boolean, "Candidate": boolean, "Conflict": boolean, "ConflictDisarmed": boolean, "ConflictReason": str}}
	task := &stateShape{kind: 'o', memory: 384, required: []string{"XID", "Targets", "DestinationIDs", "DeliveryType", "Status"}, fields: map[string]*stateShape{
		"definition": definition,
		"XID":        uid, "Targets": {kind: 'a', item: target, limit: maxStateReferences, count: 't'}, "RADIUSScope": scope, "RADIUSMACProfile": str,
		"DestinationIDs": {kind: 'a', item: uid, limit: maxStateReferences, count: 'd'}, "DeliveryType": num, "StartTime": stamp, "EndTime": stamp,
		"ImplicitDeactivationAllowed": boolean, "Status": num, "ActivatedAt": stamp, "DeactivatedAt": stamp, "LastError": str, "ActivationGeneration": num,
	}}
	destination := &stateShape{kind: 'o', memory: 160, required: []string{"did", "address", "port", "x2_enabled", "x3_enabled", "created_at"}, fields: map[string]*stateShape{
		"did": uid, "address": str, "port": num, "x2_enabled": boolean, "x3_enabled": boolean, "protocol_type": str, "description": str, "created_at": stamp, "delivery_revision": num,
	}}
	candidateTask, candidateDestination := *task, *destination
	candidateTask.nullable, candidateDestination.nullable = true, true
	intent := &stateShape{kind: 'o', memory: 320, fields: map[string]*stateShape{
		"operation_id": uid, "kind": str, "state_incarnation": uid, "xid": nullID, "did": nullID, "previous_generation": num, "reserved_generation": num, "phase": str,
		"candidate_task": &candidateTask, "candidate_destination": &candidateDestination, "cleanup_filter_ids": {kind: 'a', item: str, limit: maxStateReferences},
		"revocation_ids": {kind: 'a', item: uid, limit: maxStateReferences}, "failed": boolean,
	}}
	for field := range intent.fields {
		intent.required = append(intent.required, field)
	}
	controlTime := &stateShape{kind: 'o', required: []string{"seconds", "nanos"}, fields: map[string]*stateShape{"seconds": {kind: 'i'}, "nanos": num}}
	revocation := &stateShape{kind: 'o', memory: 256, fields: map[string]*stateShape{
		"version": num, "control_id": uid, "journal_uuid": uid, "state_incarnation": uid, "scope": str, "xid": nullID, "task_generation": nullNumber, "did": nullID,
		"destination_generation": nullNumber, "call_incarnation": nullID, "call_generation": nullNumber, "covered_record_highwater": num, "covered_admission_highwater": num, "revoked_at": controlTime,
	}}
	for field := range revocation.fields {
		revocation.required = append(revocation.required, field)
	}
	root := &stateShape{kind: 'o', required: []string{"version", "written_at", "tasks", "destinations"}, fields: map[string]*stateShape{
		"version": num, "written_at": stamp, "tasks": {kind: 'a', item: task, limit: MaxStateTasks, nullable: legacy},
		"destinations":   {kind: 'a', item: destination, limit: MaxStateDestinations, nullable: legacy},
		"cleanup_needed": {kind: 'm', limit: MaxStateObligations, item: &stateShape{kind: 'a', item: str, limit: maxStateReferences}, nullable: legacy},
		"generations":    {kind: 'm', limit: MaxStateObligations, item: num, nullable: legacy},
	}}
	if !legacy {
		root.fields["incarnation"] = uid
		root.fields["radius_correlation_state_file"] = str
		root.fields["intents"] = &stateShape{kind: 'a', item: intent, limit: MaxStateObligations}
		root.fields["revocations"] = &stateShape{kind: 'a', item: revocation, limit: MaxStateRevocations}
		root.required = append(root.required, "incarnation", "cleanup_needed", "generations", "intents", "revocations")
	}
	return root
}

type stateBudget struct {
	memory, targets, destinations int
	limit                         int // zero preserves the ordinary decoder ceiling
	shared                        bool
}

func (b *stateBudget) charge(n int) error {
	limit := b.limit
	if limit == 0 {
		limit = maxStateDecodeBytes
	}
	if n < 0 || n > limit-b.memory {
		return stateError("decode memory limit exceeded")
	}
	b.memory += n
	return nil
}

func checkStateJSON(d *json.Decoder, s *stateShape, b *stateBudget, depth int) error {
	if depth > 16 {
		return stateError("JSON depth limit exceeded")
	}
	charge := 32 + s.memory
	if b.shared {
		// Include typed slice spare capacity, semantic reference indexes and
		// RADIUS conversion scratch as well as streaming parser allocations.
		charge = 128 + 3*s.memory
	}
	if err := b.charge(charge); err != nil {
		return err
	}
	token, err := d.Token()
	if err != nil {
		return stateError("malformed JSON")
	}
	if token == nil && s.nullable {
		return nil
	}
	switch s.kind {
	case 'o', 'm':
		if token != json.Delim('{') {
			return stateError("object schema")
		}
		seen := make(map[string]bool)
		for d.More() {
			keyToken, err := d.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return stateError("invalid or duplicate field")
			}
			child := s.fields[key]
			if s.kind == 'm' {
				if !canonicalStateUUID(key) || len(seen) >= s.limit {
					return stateError("map identity or count limit")
				}
				child = s.item
			} else if child == nil {
				return stateError("unknown field")
			}
			charge := 96 + len(key)
			if b.shared {
				charge = 192 + 2*len(key)
			}
			if err := b.charge(charge); err != nil {
				return err
			}
			seen[key] = true
			if err := checkStateJSON(d, child, b, depth+1); err != nil {
				return err
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') {
			return stateError("object framing")
		}
		for _, key := range s.required {
			if !seen[key] {
				return stateError("required field missing")
			}
		}
	case 'a':
		if token != json.Delim('[') {
			return stateError("array schema")
		}
		for n := 0; d.More(); n++ {
			if n >= s.limit {
				return stateError("collection limit exceeded")
			}
			switch s.count {
			case 't':
				b.targets++
				if b.targets > maxStateTotalReferences {
					return stateError("total target limit")
				}
			case 'd':
				b.destinations++
				if b.destinations > maxStateTotalReferences {
					return stateError("total destination reference limit")
				}
			}
			if err := checkStateJSON(d, s.item, b, depth+1); err != nil {
				return err
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim(']') {
			return stateError("array framing")
		}
	case 'b':
		if _, ok := token.(bool); !ok {
			return stateError("boolean schema")
		}
	case 'u', 'i':
		n, ok := token.(json.Number)
		if !ok || !stateInteger(n.String(), s.kind == 'i') {
			return stateError("integer schema")
		}
	default:
		value, ok := token.(string)
		if !ok || len(value) > maxStateStringBytes {
			return stateError("string schema or size")
		}
		if s.kind == 'q' && !canonicalStateUUID(value) {
			return stateError("UUID schema")
		}
		if s.kind == 't' || s.kind == 'T' {
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || s.kind == 't' && (at.Location() != time.UTC || at.Format(time.RFC3339Nano) != value) {
				return stateError("UTC timestamp schema")
			}
		}
	}
	return nil
}

func stateInteger(value string, signed bool) bool {
	if strings.ContainsAny(value, ".eE+") {
		return false
	}
	if signed {
		_, err := strconv.ParseInt(value, 10, 64)
		return err == nil
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func canonicalStateUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// JSON replaces invalid UTF-16 surrogate escapes with U+FFFD by default. Reject
// those inputs rather than silently changing stored selectors or identifiers.
func stateUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+5 > len(data) {
			return false
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+7 > len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func decodeState(data []byte, legacy bool) (*StateSnapshot, error) {
	return decodeStateBudget(data, legacy, &stateBudget{memory: 4 * len(data)})
}

func decodeStateBudget(data []byte, legacy bool, budget *stateBudget) (*StateSnapshot, error) {
	if len(data) == 0 || len(data) > MaxStateSnapshotBytes || !stateUnicode(data) {
		return nil, stateError("document size or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := checkStateJSON(d, stateJSONSchema(legacy), budget, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, stateError("trailing document")
	}
	var state StateSnapshot
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, stateError("invalid typed fields")
	}
	return &state, nil
}

// UnmarshalStateSnapshot admits at most 32 MiB of source and a conservative
// 256 MiB transient reservation: four source copies, 32 bytes per token/value,
// 96 bytes plus key length per object field, and typed-entry storage. Collection
// ceilings and this aggregate reservation are checked by a streaming token pass
// before allocating typed slices/maps; no intermediate JSON tree is built.
func UnmarshalStateSnapshot(data []byte) (*StateSnapshot, error) {
	state, err := decodeState(data, false)
	if err != nil {
		return nil, err
	}
	if err := ValidateStateSnapshot(state); err != nil {
		return nil, err
	}
	return state, nil
}

// UnmarshalStateSnapshotWithBudget admits a strict modern payload within the
// caller's remaining aggregate allowance, never a second independent 256 MiB.
// Before typed allocation it charges 64 KiB fixed scratch, four source lengths,
// 128 bytes per value plus three typed-entry sizes, and 192 plus twice the key
// length per field. These conservative charges include typed collection spare
// capacity, semantic indexes and bounded RADIUS validation scratch. It retains
// all ordinary schema and collection limits and never activates restored data.
func UnmarshalStateSnapshotWithBudget(data []byte, remainingDecodeBytes int64) (*StateSnapshot, error) {
	if remainingDecodeBytes <= 0 || remainingDecodeBytes > maxStateDecodeBytes {
		return nil, stateError("decode memory allowance")
	}
	budget := &stateBudget{limit: int(remainingDecodeBytes), shared: true}
	if err := budget.charge(64<<10 + 4*len(data)); err != nil {
		return nil, err
	}
	state, err := decodeStateBudget(data, false, budget)
	if err != nil {
		return nil, err
	}
	if err := ValidateStateSnapshot(state); err != nil {
		return nil, err
	}
	return state, nil
}

// DecodeLegacyStateSnapshot is an explicit offline conversion. It never reads a
// path, installs filters, grants replay, or invents a new activation generation.
func DecodeLegacyStateSnapshot(data []byte, incarnation uuid.UUID) (*StateSnapshot, error) {
	state, err := decodeState(data, true)
	if err != nil {
		return nil, err
	}
	if state.Version != 1 || incarnation == uuid.Nil {
		return nil, stateError("legacy version or incarnation")
	}
	state.Version, state.Incarnation = StateSchemaVersion, incarnation
	state.WrittenAt = state.WrittenAt.UTC()
	for _, d := range state.Destinations {
		if d != nil {
			d.CreatedAt = d.CreatedAt.UTC()
		}
	}
	if state.Tasks == nil {
		state.Tasks = []*InterceptTask{}
	}
	if state.Destinations == nil {
		state.Destinations = []*StateDestination{}
	}
	if state.CleanupNeeded == nil {
		state.CleanupNeeded = make(map[uuid.UUID][]string)
	}
	if state.Generations == nil {
		state.Generations = make(map[uuid.UUID]uint64)
	}
	state.Intents = []*StateIntent{}
	state.Revocations = []*StateRevocation{}
	for _, task := range state.Tasks {
		if task != nil {
			normalizeTaskTimes(task)
		}
		if task != nil && task.ActivationGeneration > state.Generations[task.XID] {
			state.Generations[task.XID] = task.ActivationGeneration
		}
	}
	if err := ValidateStateSnapshot(state); err != nil {
		return nil, err
	}
	return state, nil
}

func validStateTime(at time.Time, optional bool) bool {
	_, offset := at.Zone()
	return (optional || !at.IsZero()) && at.Year() >= 1 && at.Year() <= 9999 && offset == 0
}

func stateStrings(b *stateBudget, values ...string) error {
	for _, value := range values {
		if len(value) > maxStateStringBytes || !utf8.ValidString(value) {
			return stateError("string size or encoding")
		}
		if err := b.charge(32 + len(value)); err != nil {
			return err
		}
	}
	return nil
}

func validateStateTask(task *InterceptTask, b *stateBudget) error {
	if task == nil || task.XID == uuid.Nil || task.Targets == nil || task.DestinationIDs == nil || len(task.Targets) == 0 || len(task.Targets) > maxStateReferences || len(task.DestinationIDs) == 0 || len(task.DestinationIDs) > maxStateReferences {
		return stateError("task identity or references")
	}
	d := task.Definition
	if d.Source != "" && d.Source != DefinitionPush && d.Source != DefinitionPull && d.Source != DefinitionRestore {
		return stateError("definition provenance")
	}
	switch d.ConflictReason {
	case "", "common_scope", "expired", "empty_window", "no_common_targets", "no_confirmed_destinations", "no_common_delivery":
	default:
		return stateError("definition conflict reason")
	}
	if d.ConflictDisarmed && (!d.Conflict || task.Status == TaskStatusActive || task.Status == TaskStatusPending) {
		return stateError("disarmed conflict lifecycle")
	}
	if d.Candidate && task.Status != TaskStatusPending {
		return stateError("definition candidate lifecycle")
	}
	if d.Completeness.EndProvided && (!d.Completeness.End || task.EndTime.IsZero()) {
		return stateError("definition end presence")
	}
	if task.Status < TaskStatusPending || task.Status > TaskStatusFailed || task.DeliveryType < DeliveryX2Only || task.DeliveryType > DeliveryX2andX3 {
		return stateError("task enum")
	}
	if (task.Status == TaskStatusActive || task.Status == TaskStatusSuspended) && task.ActivationGeneration == 0 {
		return stateError("enforcing task generation")
	}
	for _, at := range []time.Time{task.StartTime, task.EndTime, task.ActivatedAt, task.DeactivatedAt} {
		if !validStateTime(at, true) {
			return stateError("task timestamp")
		}
	}
	if !task.StartTime.IsZero() && !task.EndTime.IsZero() && !task.EndTime.After(task.StartTime) {
		return stateError("task validity interval")
	}
	if err := b.charge(384 + 40*len(task.Targets) + 16*len(task.DestinationIDs)); err != nil {
		return err
	}
	b.targets += len(task.Targets)
	b.destinations += len(task.DestinationIDs)
	if b.targets > maxStateTotalReferences || b.destinations > maxStateTotalReferences {
		return stateError("total task reference limit")
	}
	if err := stateStrings(b, task.RADIUSMACProfile, task.LastError, task.RADIUSScope.OperatorScope, task.RADIUSScope.ProfileRevision, task.RADIUSScope.OriginNodeID, task.RADIUSScope.SourceID); err != nil {
		return err
	}
	seenTargets := make(map[TargetIdentity]bool, len(task.Targets))
	for _, target := range task.Targets {
		if target.Type < TargetTypeSIPURI || target.Type > TargetTypeE164 || target.Value == "" || seenTargets[target] {
			return stateError("target identity or enum")
		}
		seenTargets[target] = true
		if err := stateStrings(b, target.Value); err != nil {
			return err
		}
		switch target.Type {
		case TargetTypeE164:
			if !schema.ValidE164Number(target.Value) {
				return stateError("target E.164 number")
			}
		case TargetTypeIPv4Address, TargetTypeIPv6Address:
			addr, err := netip.ParseAddr(target.Value)
			if err != nil || addr.Zone() != "" || addr.Is4() != (target.Type == TargetTypeIPv4Address) {
				return stateError("target address")
			}
		case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
			prefix, err := netip.ParsePrefix(target.Value)
			if err != nil || prefix.Addr().Is4() != (target.Type == TargetTypeIPv4CIDR) {
				return stateError("target prefix")
			}
		}
	}
	seen := make(map[uuid.UUID]bool, len(task.DestinationIDs))
	for _, id := range task.DestinationIDs {
		if id == uuid.Nil || seen[id] {
			return stateError("duplicate or invalid destination reference")
		}
		seen[id] = true
	}
	if IsRADIUSTask(task) {
		// Legacy unscoped NAI identities remain data, never fresh RADIUS authority.
		legacy := task.RADIUSScope.OperatorScope == "" && task.RADIUSScope.ProfileRevision == ""
		if legacy {
			for _, target := range task.Targets {
				if target.Type != TargetTypeNAI {
					return stateError("unscoped RADIUS definition")
				}
			}
		} else {
			candidate := *task
			if candidate.ActivationGeneration == 0 {
				candidate.ActivationGeneration = 1
			}
			if _, err := NewFilterManager(nil).radiusFilterForTask(&candidate); err != nil {
				return stateError("RADIUS definition")
			}
		}
	}
	return nil
}

func validateStateDestination(d *StateDestination, b *stateBudget) error {
	if d == nil || d.DID == uuid.Nil || d.Address == "" || d.Port <= 0 || d.Port > 65535 || !validStateTime(d.CreatedAt, false) {
		return stateError("destination definition")
	}
	if err := b.charge(160); err != nil {
		return err
	}
	return stateStrings(b, d.Address, d.ProtocolType, d.Description)
}

func validateStateIDs(ids []string, b *stateBudget) error {
	if ids == nil || len(ids) > maxStateReferences {
		return stateError("cleanup reference limit")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := stateCleanupOwner(id); !ok || seen[id] {
			return stateError("invalid or duplicate cleanup reference")
		}
		seen[id] = true
		if err := stateStrings(b, id); err != nil {
			return err
		}
	}
	return nil
}

// stateCleanupOwner accepts only canonical LI ownership forms. Legacy suffixes
// remain opaque, but their short owner must be the hexadecimal UUID prefix.
func stateCleanupOwner(id string) (string, bool) {
	if strings.ContainsRune(id, 0) {
		return "", false
	}
	owner, ok := liFilterXIDPrefix(id)
	if !ok {
		return "", false
	}
	if len(owner) == 8 {
		for _, r := range owner {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return "", false
			}
		}
	} else if !canonicalStateUUID(owner) {
		return "", false
	}
	return owner, true
}
func validateStateCleanupSubject(ids []string, xid *uuid.UUID) error {
	for _, id := range ids {
		owner, ok := stateCleanupOwner(id)
		if !ok {
			return stateError("cleanup filter ownership")
		}
		if xid != nil && owner != xid.String() && owner != xid.String()[:8] {
			return stateError("cleanup task ownership mismatch")
		}
	}
	return nil
}
func stateIntentRootTask(s *StateSnapshot, id *uuid.UUID) *InterceptTask {
	if id == nil {
		return nil
	}
	for _, task := range s.Tasks {
		if task.XID == *id {
			return task
		}
	}
	return nil
}

func nonzeroStateID(id *uuid.UUID) bool     { return id != nil && *id != uuid.Nil }
func nonzeroStateGeneration(n *uint64) bool { return n != nil && *n != 0 }

func validateStateRevocation(r *StateRevocation, incarnation uuid.UUID) error {
	if r == nil || r.Version != 1 || r.ControlID == uuid.Nil || r.JournalUUID == uuid.Nil || r.StateIncarnation != incarnation {
		return stateError("revocation identity")
	}
	if r.RevokedAt.Nanos >= 1_000_000_000 || r.RevokedAt.Seconds < -62135596800 || r.RevokedAt.Seconds > 253402300799 {
		return stateError("revocation timestamp")
	}
	task := nonzeroStateID(r.XID) && nonzeroStateGeneration(r.TaskGeneration)
	dest := nonzeroStateID(r.DID) && nonzeroStateGeneration(r.DestinationGeneration)
	call := nonzeroStateID(r.CallIncarnation) && nonzeroStateGeneration(r.CallGeneration)
	switch r.Scope {
	case StateRevokeTask:
		if !task || r.DID != nil || r.DestinationGeneration != nil || r.CallIncarnation != nil || r.CallGeneration != nil {
			return stateError("task revocation scope")
		}
	case StateRevokeDestination:
		if !dest || r.XID != nil || r.TaskGeneration != nil || r.CallIncarnation != nil || r.CallGeneration != nil {
			return stateError("destination revocation scope")
		}
	case StateRevokeCall:
		if !task || !dest || !call {
			return stateError("call revocation scope")
		}
	default:
		return stateError("revocation scope enum")
	}
	return nil
}

func validateStateIntent(i *StateIntent, s *StateSnapshot, b *stateBudget) error {
	if i == nil || i.OperationID == uuid.Nil || i.StateIncarnation != s.Incarnation || i.RevocationIDs == nil || len(i.RevocationIDs) > maxStateReferences {
		return stateError("intent identity or references")
	}
	if err := b.charge(320); err != nil {
		return err
	}
	if err := validateStateIDs(i.CleanupFilterIDs, b); err != nil {
		return err
	}
	taskKind, destKind, needsTask, needsDest, revokes := false, false, false, false, false
	switch i.Kind {
	case StateTaskActivate, StateTaskReactivate, StateTaskPromote, StateTaskConfirm:
		taskKind, needsTask = true, true
	case StateTaskModify:
		taskKind, needsTask, revokes = true, true, true
	case StateTaskUpdate:
		taskKind, needsTask = true, true
	case StateTaskDeactivate, StateTaskExpire, StateTaskFail:
		taskKind, revokes = true, true
	case StateDestinationCreate:
		destKind, needsDest = true, true
	case StateDestinationModify:
		destKind, needsDest, revokes = true, true, true
	case StateDestinationUpdate:
		destKind, needsDest = true, true
	case StateDestinationRemove:
		destKind, revokes = true, true
	case StateCleanup, StatePurge:
	default:
		return stateError("intent kind enum")
	}
	if i.Phase != StateReserved && i.Phase != StateFinished && i.Phase != StatePolicyCommitted && i.Phase != StateRevocationCommitted {
		return stateError("intent phase enum")
	}
	if i.Phase == StateRevocationCommitted && !revokes || (i.Kind == StateTaskUpdate || i.Kind == StateDestinationUpdate || i.Kind == StatePurge) && i.Phase != StateReserved && i.Phase != StateFinished {
		return stateError("intent phase for kind")
	}
	if taskKind && (!nonzeroStateID(i.XID) || i.DID != nil) || destKind && (!nonzeroStateID(i.DID) || i.XID != nil) {
		return stateError("intent subject")
	}
	if !taskKind && !destKind && i.Kind != StateCleanup && (!nonzeroStateID(i.XID) && !nonzeroStateID(i.DID) || i.XID != nil && i.DID != nil) {
		return stateError("cleanup subject")
	}
	if i.Kind == StateCleanup {
		if i.XID != nil && i.DID != nil || i.PreviousGeneration != 0 || i.ReservedGeneration != 0 || len(i.RevocationIDs) != 0 || i.XID == nil && i.DID == nil && len(i.CleanupFilterIDs) == 0 {
			return stateError("cleanup operation binding")
		}
	}
	if i.XID != nil && *i.XID == uuid.Nil || i.DID != nil && *i.DID == uuid.Nil {
		return stateError("intent subject UUID")
	}
	if err := validateStateCleanupSubject(i.CleanupFilterIDs, i.XID); err != nil {
		return err
	}
	if !revokes && len(i.RevocationIDs) != 0 {
		return stateError("nonrevoking intent references control")
	}
	if i.Kind == StatePurge {
		if !nonzeroStateID(i.XID) || i.DID != nil || i.ReservedGeneration != 0 || len(i.CleanupFilterIDs) != 0 {
			return stateError("purge task binding")
		}
		if i.Phase != StateFinished {
			task := stateIntentRootTask(s, i.XID)
			if task == nil || (task.Status != TaskStatusDeactivated && task.Status != TaskStatusFailed) || task.DeactivatedAt.IsZero() || task.ActivationGeneration != i.PreviousGeneration || len(s.CleanupNeeded[*i.XID]) != 0 {
				return stateError("purge requires exact eligible retained task")
			}
		}
	}
	if i.Kind == StateTaskReactivate && i.PreviousGeneration == 0 {
		if i.ReservedGeneration == 0 {
			return stateError("legacy reactivation generation")
		}
		if i.Phase != StateFinished {
			task := stateIntentRootTask(s, i.XID)
			if task == nil || task.ActivationGeneration != 0 || (task.Status != TaskStatusDeactivated && !(i.Failed && task.Status == TaskStatusFailed)) {
				return stateError("legacy reactivation retained identity")
			}
		}
	}
	if needsTask != (i.CandidateTask != nil) || needsDest != (i.CandidateDestination != nil) {
		return stateError("intent candidate kind")
	}
	if needsTask {
		if err := validateStateTask(i.CandidateTask, b); err != nil {
			return err
		}
		if i.CandidateTask.XID != *i.XID || i.CandidateTask.ActivationGeneration != i.ReservedGeneration {
			return stateError("candidate task identity")
		}
		disarmedModification := i.Kind == StateTaskModify && i.CandidateTask.Status == TaskStatusSuspended && i.CandidateTask.Definition.ConflictDisarmed
		if i.Kind != StateTaskUpdate && !disarmedModification && i.CandidateTask.Status != TaskStatusActive && i.CandidateTask.Status != TaskStatusPending || (i.Kind == StateTaskPromote || i.Kind == StateTaskConfirm) && i.CandidateTask.Status != TaskStatusActive {
			return stateError("candidate task status for operation")
		}
	}
	if needsDest {
		if err := validateStateDestination(i.CandidateDestination, b); err != nil {
			return err
		}
		if i.CandidateDestination.DID != *i.DID || i.CandidateDestination.DeliveryRevision != i.ReservedGeneration {
			return stateError("candidate destination identity")
		}
	}
	if needsTask && i.Kind != StateTaskUpdate || needsDest && i.Kind != StateDestinationUpdate {
		if i.ReservedGeneration == 0 {
			return stateError("reserved generation is required")
		}
	}
	if i.Kind == StateTaskPromote || i.Kind == StateTaskConfirm || i.Kind == StateTaskUpdate || i.Kind == StateDestinationUpdate {
		if i.PreviousGeneration != i.ReservedGeneration {
			return stateError("preserved generation mismatch")
		}
	} else if (needsTask || needsDest) && i.ReservedGeneration <= i.PreviousGeneration {
		return stateError("nonmonotonic reserved generation")
	}
	if revokes && taskKind && i.PreviousGeneration == 0 {
		if (i.Kind != StateTaskModify && i.ReservedGeneration != 0) || len(i.RevocationIDs) != 0 {
			return stateError("legacy task withdrawal cannot invent generation or controls")
		}
		if i.Phase != StateFinished {
			var retained *InterceptTask
			for _, task := range s.Tasks {
				if task.XID == *i.XID {
					retained = task
					break
				}
			}
			if retained == nil || retained.ActivationGeneration != 0 || retained.Status == TaskStatusActive || retained.Status == TaskStatusSuspended {
				return stateError("legacy zero generation withdrawal requires nonenforcing subject")
			}
		}
	}
	if i.Kind == StateTaskConfirm && len(i.RevocationIDs) != 0 {
		return stateError("task confirmation cannot revoke its retained generation")
	}
	if i.Kind == StateDestinationCreate && i.PreviousGeneration != 0 {
		return stateError("previous generation for operation")
	}
	if i.XID != nil && s.Generations[*i.XID] < max(i.PreviousGeneration, i.ReservedGeneration) {
		return stateError("intent exceeds generation watermark")
	}
	seen := make(map[uuid.UUID]bool, len(i.RevocationIDs))
	for _, id := range i.RevocationIDs {
		if id == uuid.Nil || seen[id] {
			return stateError("duplicate or invalid revocation reference")
		}
		seen[id] = true
	}
	return nil
}

// ValidateStateSnapshot performs no registry, filter, admission or filesystem
// effects. Expired/historical definitions remain data and are never activated.
func ValidateStateSnapshot(s *StateSnapshot) error {
	if s == nil || s.Version != StateSchemaVersion || s.Incarnation == uuid.Nil || !validStateTime(s.WrittenAt, false) {
		return stateError("snapshot version or identity")
	}
	if s.Tasks == nil || s.Destinations == nil || s.CleanupNeeded == nil || s.Generations == nil || s.Intents == nil || s.Revocations == nil {
		return stateError("null snapshot collection")
	}
	if len(s.Tasks) > MaxStateTasks || len(s.Destinations) > MaxStateDestinations || len(s.CleanupNeeded) > MaxStateObligations || len(s.Generations) > MaxStateObligations || len(s.Intents) > MaxStateObligations || len(s.Revocations) > MaxStateRevocations {
		return stateError("snapshot collection limit")
	}
	b := &stateBudget{}
	if err := stateStrings(b, s.RADIUSCorrelationStateFile); err != nil {
		return err
	}
	if pin := s.RADIUSCorrelationStateFile; pin != "" && (!filepath.IsAbs(pin) || filepath.Clean(pin) != pin || strings.ContainsRune(pin, 0)) {
		return stateError("RADIUS correlation path pin")
	}
	destinations := make(map[uuid.UUID]*StateDestination, len(s.Destinations))
	for _, d := range s.Destinations {
		if err := validateStateDestination(d, b); err != nil {
			return err
		}
		if destinations[d.DID] != nil {
			return stateError("duplicate destination")
		}
		destinations[d.DID] = d
	}
	tasks := make(map[uuid.UUID]bool, len(s.Tasks))
	checkDestinations := func(task *InterceptTask) error {
		if task.Status == TaskStatusActive || task.Status == TaskStatusSuspended {
			for _, did := range task.DestinationIDs {
				if destinations[did] == nil {
					return stateError("enforcing task references missing destination")
				}
			}
		}
		return nil
	}
	for _, task := range s.Tasks {
		if err := validateStateTask(task, b); err != nil {
			return err
		}
		if tasks[task.XID] {
			return stateError("duplicate task")
		}
		tasks[task.XID] = true
		if s.Generations[task.XID] < task.ActivationGeneration {
			return stateError("task exceeds generation watermark")
		}
		if err := checkDestinations(task); err != nil {
			return err
		}
	}
	for id, ids := range s.CleanupNeeded {
		if id == uuid.Nil {
			return stateError("cleanup owner UUID")
		}
		if err := validateStateIDs(ids, b); err != nil {
			return err
		}
		if err := validateStateCleanupSubject(ids, &id); err != nil {
			return err
		}
		if err := b.charge(96); err != nil {
			return err
		}
	}
	for id := range s.Generations {
		if id == uuid.Nil {
			return stateError("generation owner UUID")
		}
		if err := b.charge(80); err != nil {
			return err
		}
	}
	revocations := make(map[uuid.UUID]*StateRevocation, len(s.Revocations))
	taskObligations := make(map[uuid.UUID]bool)
	for _, r := range s.Revocations {
		if err := validateStateRevocation(r, s.Incarnation); err != nil {
			return err
		}
		if r.XID != nil && s.Generations[*r.XID] < *r.TaskGeneration {
			return stateError("revocation exceeds generation watermark")
		}
		if revocations[r.ControlID] != nil {
			return stateError("duplicate revocation")
		}
		revocations[r.ControlID] = r
		if r.XID != nil {
			if !taskObligations[*r.XID] {
				if err := b.charge(96); err != nil {
					return err
				}
			}
			taskObligations[*r.XID] = true
		}
		if err := b.charge(320); err != nil {
			return err
		}
	}
	operations := make(map[uuid.UUID]bool, len(s.Intents))
	unfinished := make(map[string]bool)
	for _, i := range s.Intents {
		if err := validateStateIntent(i, s, b); err != nil {
			return err
		}
		var previousDestinationGeneration uint64
		if i.Phase != StateFinished && (i.Kind == StateDestinationModify || i.Kind == StateDestinationRemove) {
			previous := destinations[*i.DID]
			if previous == nil || previous.DeliveryRevision != i.PreviousGeneration {
				return stateError("unfinished destination prior identity")
			}
			// The old root remains until the same final snapshot finishes this intent
			// and replaces/removes the endpoint. Finished history cannot require it.
			previousDestinationGeneration = DestinationDeliveryGeneration(&Destination{
				DID: previous.DID, Address: previous.Address, Port: previous.Port,
				ProtocolType: previous.ProtocolType, X2Enabled: previous.X2Enabled,
				X3Enabled: previous.X3Enabled, CreatedAt: previous.CreatedAt,
				DeliveryRevision: previous.DeliveryRevision,
			})
		}
		if i.Kind == StatePurge && i.Phase != StateFinished && taskObligations[*i.XID] {
			return stateError("purge task has retained revocations")
		}
		if operations[i.OperationID] {
			return stateError("duplicate operation")
		}
		operations[i.OperationID] = true
		if i.CandidateTask != nil && i.Phase != StateFinished {
			if err := checkDestinations(i.CandidateTask); err != nil {
				return err
			}
		}
		subject := "d:"
		if i.XID != nil {
			subject = "t:" + i.XID.String()
		} else if i.DID != nil {
			subject += i.DID.String()
		} else {
			subject = "o:" + i.OperationID.String()
		}
		if i.Phase != StateFinished {
			if unfinished[subject] {
				return stateError("multiple unfinished subject intents")
			}
			unfinished[subject] = true
		}
		for _, id := range i.RevocationIDs {
			r := revocations[id]
			if r == nil {
				return stateError("missing referenced revocation")
			}
			if i.XID != nil && (r.Scope != StateRevokeTask || r.XID == nil || *r.XID != *i.XID || r.TaskGeneration == nil || *r.TaskGeneration != i.PreviousGeneration) {
				return stateError("revocation task mismatch")
			}
			if i.DID != nil && (r.Scope != StateRevokeDestination || r.DID == nil || *r.DID != *i.DID) {
				return stateError("revocation destination mismatch")
			}
			if previousDestinationGeneration != 0 && *r.DestinationGeneration != previousDestinationGeneration {
				return stateError("revocation destination generation mismatch")
			}
		}
	}
	return nil
}

type stateBuffer struct{ bytes.Buffer }

func (b *stateBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxStateSnapshotBytes-b.Len() {
		return 0, stateError("encoded document limit")
	}
	return b.Buffer.Write(p)
}

// MarshalStateSnapshot emits deterministic JSON using bounded per-entry writes.
// It never changes caller timestamps, collections, candidates, or generations.
func MarshalStateSnapshot(s *StateSnapshot) ([]byte, error) {
	if err := ValidateStateSnapshot(s); err != nil {
		return nil, err
	}
	var out stateBuffer
	put := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return stateError("encode snapshot")
		}
		_, err = out.Write(data)
		return err
	}
	write := func(v string) error { _, err := out.Write([]byte(v)); return err }
	if err := write(`{"version":2,"written_at":`); err != nil {
		return nil, err
	}
	if err := put(s.WrittenAt); err != nil {
		return nil, err
	}
	if err := write(`,"incarnation":`); err != nil {
		return nil, err
	}
	if err := put(s.Incarnation); err != nil {
		return nil, err
	}
	if s.RADIUSCorrelationStateFile != "" {
		if err := write(`,"radius_correlation_state_file":`); err != nil {
			return nil, err
		}
		if err := put(s.RADIUSCorrelationStateFile); err != nil {
			return nil, err
		}
	}
	arrays := []struct {
		name string
		n    int
		at   func(int) any
	}{{"tasks", len(s.Tasks), func(i int) any { return s.Tasks[i] }}, {"destinations", len(s.Destinations), func(i int) any { return s.Destinations[i] }}, {"intents", len(s.Intents), func(i int) any { return s.Intents[i] }}, {"revocations", len(s.Revocations), func(i int) any { return s.Revocations[i] }}}
	for _, a := range arrays {
		if err := write(`,"` + a.name + `":[`); err != nil {
			return nil, err
		}
		for i := 0; i < a.n; i++ {
			if i > 0 {
				if err := write(","); err != nil {
					return nil, err
				}
			}
			if err := put(a.at(i)); err != nil {
				return nil, err
			}
		}
		if err := write("]"); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"cleanup_needed", "generations"} {
		ids := make([]string, 0)
		if name == "cleanup_needed" {
			for id := range s.CleanupNeeded {
				ids = append(ids, id.String())
			}
		} else {
			for id := range s.Generations {
				ids = append(ids, id.String())
			}
		}
		sort.Strings(ids)
		if err := write(`,"` + name + `":{`); err != nil {
			return nil, err
		}
		for i, key := range ids {
			if i > 0 {
				if err := write(","); err != nil {
					return nil, err
				}
			}
			if err := put(key); err != nil {
				return nil, err
			}
			if err := write(":"); err != nil {
				return nil, err
			}
			id := uuid.MustParse(key)
			var value any = s.Generations[id]
			if name == "cleanup_needed" {
				value = s.CleanupNeeded[id]
			}
			if err := put(value); err != nil {
				return nil, err
			}
		}
		if err := write("}"); err != nil {
			return nil, err
		}
	}
	if err := write("}"); err != nil {
		return nil, err
	}
	// Apply the same aggregate decode admission rule to writer output.
	d := json.NewDecoder(bytes.NewReader(out.Bytes()))
	d.UseNumber()
	if err := checkStateJSON(d, stateJSONSchema(false), &stateBudget{memory: 4 * out.Len()}, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
