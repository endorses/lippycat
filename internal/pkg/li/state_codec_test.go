//go:build li

package li

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func stateFixture(t testing.TB) *StateSnapshot {
	t.Helper()
	data, err := os.ReadFile("testdata/legacy_state_v1.json")
	require.NoError(t, err)
	s, err := DecodeLegacyStateSnapshot(data, uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	require.NoError(t, err)
	return s
}

func emptyStateFixture() *StateSnapshot {
	return &StateSnapshot{Version: StateSchemaVersion, WrittenAt: time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC), Incarnation: uuid.New(),
		Tasks: []*InterceptTask{}, Destinations: []*StateDestination{}, CleanupNeeded: map[uuid.UUID][]string{}, Generations: map[uuid.UUID]uint64{},
		Intents: []*StateIntent{}, Revocations: []*StateRevocation{}}
}

func TestStateCodecLegacyLosslessAndDetached(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy_state_v1.json")
	require.NoError(t, err)
	var legacy persistedState
	require.NoError(t, json.Unmarshal(data, &legacy))
	s := stateFixture(t)
	require.Equal(t, legacy.Tasks, s.Tasks)
	require.Equal(t, legacy.WrittenAt, s.WrittenAt)
	require.Equal(t, legacy.Cleanup, s.CleanupNeeded)
	for n, dest := range legacy.Destinations {
		require.Equal(t, StateDestination(*dest), *s.Destinations[n])
	}
	for id, generation := range legacy.Generations {
		require.Equal(t, generation, s.Generations[id])
	}
	require.Equal(t, uint64(13), s.Generations[s.Tasks[5].XID], "missing watermark must be synthesized without changing the task")
	require.Equal(t, uint64(8), s.Generations[s.Tasks[3].XID], "retained highwater must never be decremented")
	before, err := json.Marshal(s)
	require.NoError(t, err)
	encoded, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	after, err := json.Marshal(s)
	require.NoError(t, err)
	require.Equal(t, before, after, "encoding must not mutate caller state")
	restored, err := UnmarshalStateSnapshot(encoded)
	require.NoError(t, err)
	require.Equal(t, s, restored)
	encodedAgain, err := MarshalStateSnapshot(restored)
	require.NoError(t, err)
	require.Equal(t, encoded, encodedAgain)
	restored.Tasks[0].Targets[0].Value = "changed"
	restored.CleanupNeeded[s.Tasks[0].XID][0] = "changed"
	restored.Destinations[0].Address = "changed"
	require.NotEqual(t, restored.Tasks[0], s.Tasks[0])
	require.NotEqual(t, restored.CleanupNeeded, s.CleanupNeeded)
	require.NotEqual(t, restored.Destinations, s.Destinations)
}

func TestStateCodecLegacyOffsetsPreserveInstantAndRetainedStatus(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy_state_v1.json")
	require.NoError(t, err)
	data = bytes.ReplaceAll(data, []byte("2026-01-02T03:04:05Z"), []byte("2026-01-02T05:04:05.123456789+02:00"))
	s, err := DecodeLegacyStateSnapshot(data, uuid.New())
	require.NoError(t, err)
	want := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	require.Equal(t, want, s.WrittenAt)
	require.Equal(t, want, s.Destinations[0].CreatedAt)
	require.Equal(t, want, s.Tasks[3].DeactivatedAt)
	require.Equal(t, TaskStatusDeactivated, s.Tasks[3].Status)
	encoded, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "+02:00")
	_, err = UnmarshalStateSnapshot(bytes.Replace(encoded, []byte("2026-01-02T03:04:05.123456789Z"), []byte("2026-01-02T05:04:05.123456789+02:00"), 1))
	require.ErrorIs(t, err, ErrStateSnapshot)
}

func TestStateCodecHistoricalDefinitionsRemainData(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusPending, TaskStatusDeactivated, TaskStatusFailed} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := stateFixture(t)
			s.Tasks = s.Tasks[2:3]
			s.Tasks[0].Status, s.Tasks[0].ActivationGeneration = status, 0
			s.Destinations = []*StateDestination{}
			require.NoError(t, ValidateStateSnapshot(s))
			encoded, err := MarshalStateSnapshot(s)
			require.NoError(t, err)
			_, err = UnmarshalStateSnapshot(encoded)
			require.NoError(t, err)
		})
	}
	for _, status := range []TaskStatus{TaskStatusActive, TaskStatusSuspended} {
		s := stateFixture(t)
		s.Tasks[2].Status = status
		require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
	}
	s := stateFixture(t)
	s.Tasks[0].ActivationGeneration = math.MaxUint64
	s.Generations[s.Tasks[0].XID] = math.MaxUint64
	encoded, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	restored, err := UnmarshalStateSnapshot(encoded)
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxUint64), restored.Tasks[0].ActivationGeneration)
	_, err = DecodeLegacyStateSnapshot([]byte(`{"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":null,"destinations":null}`), uuid.New())
	require.NoError(t, err, "legacy writers emitted null empty collections")
}

func TestStateCodecStrictJSON(t *testing.T) {
	base, err := MarshalStateSnapshot(stateFixture(t))
	require.NoError(t, err)
	cases := map[string]string{
		"duplicate field":       strings.Replace(string(base), `"version":2`, `"version":2,"version":2`, 1),
		"unknown field":         strings.Replace(string(base), `"version":2`, `"version":2,"selector-secret":0`, 1),
		"wrong case":            strings.Replace(string(base), `"written_at"`, `"Written_At"`, 1),
		"trailing document":     string(base) + `{}`,
		"null entry":            strings.Replace(string(base), `"tasks":[`, `"tasks":[null,`, 1),
		"null collection":       strings.Replace(string(base), `"intents":[]`, `"intents":null`, 1),
		"missing collection":    strings.Replace(string(base), `,"intents":[]`, ``, 1),
		"unknown task enum":     strings.Replace(string(base), `"Status":1`, `"Status":99`, 1),
		"unknown target enum":   strings.Replace(string(base), `"Type":1`, `"Type":99`, 1),
		"unknown delivery enum": strings.Replace(string(base), `"DeliveryType":3`, `"DeliveryType":99`, 1),
		"upper UUID":            strings.Replace(string(base), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", 1),
		"nil UUID":              strings.Replace(string(base), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", uuid.Nil.String(), 1),
		"fraction":              strings.Replace(string(base), `"ActivationGeneration":3`, `"ActivationGeneration":3.0`, 1),
		"exponent":              strings.Replace(string(base), `"ActivationGeneration":3`, `"ActivationGeneration":3e0`, 1),
		"overflow":              strings.Replace(string(base), `"ActivationGeneration":3`, `"ActivationGeneration":18446744073709551616`, 1),
		"negative":              strings.Replace(string(base), `"ActivationGeneration":3`, `"ActivationGeneration":-1`, 1),
		"timezone":              strings.Replace(string(base), "2026-01-02T03:04:05Z", "2026-01-02T04:04:05+01:00", 1),
		"invalid surrogate":     strings.Replace(string(base), "sip:fixture-1@example.invalid", `\ud800selector-secret`, 1),
		"invalid UTF8":          strings.Replace(string(base), "sip:fixture-1@example.invalid", "\xffselector-secret", 1),
		"oversize string":       strings.Replace(string(base), "sip:fixture-1@example.invalid", strings.Repeat("x", maxStateStringBytes+1), 1),
		"duplicate map key":     strings.Replace(string(base), `"generations":{`, `"generations":{"11111111-1111-4111-8111-111111111111":3,`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalStateSnapshot([]byte(data))
			require.ErrorIs(t, err, ErrStateSnapshot)
			require.NotContains(t, err.Error(), "selector-secret")
			require.NotContains(t, err.Error(), "fixture-1")
		})
	}
	validPair := bytes.Replace(base, []byte("sip:fixture-1@example.invalid"), []byte(`\ud83d\ude03`), 1)
	_, err = UnmarshalStateSnapshot(validPair)
	require.NoError(t, err)
}

func statePtr[T any](value T) *T { return &value }

func stateIntentFixture(t testing.TB, kind StateIntentKind) (*StateSnapshot, *StateIntent) {
	t.Helper()
	s := stateFixture(t)
	i := &StateIntent{OperationID: uuid.New(), Kind: kind, StateIncarnation: s.Incarnation, Phase: StateReserved, CleanupFilterIDs: []string{}, RevocationIDs: []uuid.UUID{}}
	s.Intents = []*StateIntent{i}
	switch kind {
	case StateDestinationCreate, StateDestinationModify, StateDestinationUpdate, StateDestinationRemove:
		i.DID, i.PreviousGeneration = statePtr(s.Destinations[0].DID), 5
		if kind != StateDestinationRemove {
			d := *s.Destinations[0]
			d.DeliveryRevision, i.ReservedGeneration = 6, 6
			i.CandidateDestination = &d
		}
		if kind == StateDestinationCreate {
			i.PreviousGeneration = 0
		}
		if kind == StateDestinationUpdate {
			i.ReservedGeneration = i.PreviousGeneration
			i.CandidateDestination.DeliveryRevision = i.ReservedGeneration
		}
	default:
		i.XID, i.PreviousGeneration = statePtr(s.Tasks[0].XID), 3
		switch kind {
		case StatePurge:
			s.Tasks[0].Status = TaskStatusDeactivated
			s.Tasks[0].DeactivatedAt = s.WrittenAt
			delete(s.CleanupNeeded, s.Tasks[0].XID)
		case StateCleanup:
			i.PreviousGeneration = 0
		case StateTaskActivate, StateTaskReactivate, StateTaskModify, StateTaskPromote, StateTaskConfirm, StateTaskUpdate:
			candidate := *s.Tasks[0]
			i.ReservedGeneration = 4
			if kind == StateTaskPromote || kind == StateTaskConfirm || kind == StateTaskUpdate {
				i.ReservedGeneration = i.PreviousGeneration
			}
			candidate.ActivationGeneration = i.ReservedGeneration
			i.CandidateTask = &candidate
			s.Generations[*i.XID] = i.ReservedGeneration
		}
	}
	return s, i
}

func TestStateCodecIntentKindsAndPhases(t *testing.T) {
	revokes := map[StateIntentKind]bool{StateTaskModify: true, StateTaskDeactivate: true, StateTaskExpire: true, StateTaskFail: true, StateDestinationModify: true, StateDestinationRemove: true}
	for _, kind := range []StateIntentKind{StateTaskActivate, StateTaskReactivate, StateTaskPromote, StateTaskConfirm, StateTaskModify, StateTaskUpdate, StateTaskDeactivate, StateTaskExpire, StateTaskFail, StateDestinationCreate, StateDestinationModify, StateDestinationUpdate, StateDestinationRemove, StateCleanup, StatePurge} {
		for _, phase := range []StateIntentPhase{StateReserved, StateRevocationCommitted, StatePolicyCommitted, StateFinished, "unknown"} {
			t.Run(string(kind)+"/"+string(phase), func(t *testing.T) {
				s, i := stateIntentFixture(t, kind)
				i.Phase = phase
				valid := phase == StateReserved || phase == StateFinished || phase == StateRevocationCommitted && revokes[kind] || phase == StatePolicyCommitted && kind != StateTaskUpdate && kind != StateDestinationUpdate && kind != StatePurge
				data, err := MarshalStateSnapshot(s)
				if !valid {
					require.ErrorIs(t, err, ErrStateSnapshot)
					return
				}
				require.NoError(t, err)
				restored, err := UnmarshalStateSnapshot(data)
				require.NoError(t, err)
				require.Equal(t, s, restored)
			})
		}
	}
}

func TestStateCodecIntentAndRevocationConsistency(t *testing.T) {
	for name, change := range map[string]func(*StateSnapshot, *StateIntent){
		"unknown kind":         func(s *StateSnapshot, i *StateIntent) { i.Kind = "secret-kind" },
		"state binding":        func(s *StateSnapshot, i *StateIntent) { i.StateIncarnation = uuid.New() },
		"subject":              func(s *StateSnapshot, i *StateIntent) { i.DID = statePtr(uuid.New()) },
		"missing candidate":    func(s *StateSnapshot, i *StateIntent) { i.CandidateTask = nil },
		"candidate identity":   func(s *StateSnapshot, i *StateIntent) { i.CandidateTask.XID = uuid.New() },
		"candidate generation": func(s *StateSnapshot, i *StateIntent) { i.CandidateTask.ActivationGeneration++ },
		"candidate status":     func(s *StateSnapshot, i *StateIntent) { i.CandidateTask.Status = TaskStatusDeactivated },
		"watermark":            func(s *StateSnapshot, i *StateIntent) { s.Generations[*i.XID] = 3 },
		"old generation":       func(s *StateSnapshot, i *StateIntent) { i.PreviousGeneration = 4 },
		"duplicate operation": func(s *StateSnapshot, i *StateIntent) {
			copyIntent := *i
			copyIntent.Phase = StateFinished
			s.Intents = append(s.Intents, &copyIntent)
		},
		"unfinished conflict": func(s *StateSnapshot, i *StateIntent) {
			copyIntent := *i
			copyIntent.OperationID = uuid.New()
			s.Intents = append(s.Intents, &copyIntent)
		},
		"missing revocation": func(s *StateSnapshot, i *StateIntent) { i.RevocationIDs = []uuid.UUID{uuid.New()} },
		"duplicate cleanup":  func(s *StateSnapshot, i *StateIntent) { i.CleanupFilterIDs = []string{"opaque", "opaque"} },
	} {
		t.Run(name, func(t *testing.T) {
			s, i := stateIntentFixture(t, StateTaskModify)
			change(s, i)
			require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
		})
	}
	s, i := stateIntentFixture(t, StateTaskModify)
	r := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: StateRevokeTask,
		XID: i.XID, TaskGeneration: statePtr(i.PreviousGeneration), CoveredRecordHighwater: math.MaxUint64, CoveredAdmissionHighwater: math.MaxUint64, RevokedAt: NewStateTimestamp(s.WrittenAt)}
	s.Revocations, i.RevocationIDs = []*StateRevocation{r}, []uuid.UUID{r.ControlID}
	require.NoError(t, ValidateStateSnapshot(s))
	for _, scope := range []StateRevocationScope{StateRevokeTask, StateRevokeDestination, StateRevokeCall} {
		t.Run(string(scope), func(t *testing.T) {
			copyControl := *r
			copyControl.Scope = scope
			if scope != StateRevokeTask {
				copyControl.DID, copyControl.DestinationGeneration = statePtr(s.Destinations[0].DID), statePtr(uint64(456))
			}
			if scope == StateRevokeDestination {
				copyControl.XID, copyControl.TaskGeneration = nil, nil
			}
			if scope == StateRevokeCall {
				copyControl.CallIncarnation, copyControl.CallGeneration = statePtr(uuid.New()), statePtr(uint64(17))
			}
			s.Revocations = []*StateRevocation{&copyControl}
			i.RevocationIDs = []uuid.UUID{}
			data, err := MarshalStateSnapshot(s)
			require.NoError(t, err)
			_, err = UnmarshalStateSnapshot(data)
			require.NoError(t, err)
			copyControl.CallGeneration = statePtr(uint64(0))
			require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
		})
	}
}

func TestStateCodecEquivalentUpdatePreservesHistoricalStatus(t *testing.T) {
	for status := TaskStatusPending; status <= TaskStatusFailed; status++ {
		s, i := stateIntentFixture(t, StateTaskUpdate)
		i.CandidateTask.Status = status
		i.Phase = StateFinished
		data, err := MarshalStateSnapshot(s)
		require.NoError(t, err)
		restored, err := UnmarshalStateSnapshot(data)
		require.NoError(t, err)
		require.Equal(t, status, restored.Intents[0].CandidateTask.Status)
	}
}

func TestStateCodecRevocationTimestamps(t *testing.T) {
	s, i := stateIntentFixture(t, StateTaskModify)
	r := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: StateRevokeTask, XID: i.XID, TaskGeneration: statePtr(uint64(3))}
	s.Revocations = []*StateRevocation{r}
	for _, at := range []StateTimestamp{{Seconds: -62135596800}, {Seconds: 253402300799, Nanos: 999999999}, {}} {
		r.RevokedAt = at
		require.NoError(t, ValidateStateSnapshot(s))
	}
	for _, at := range []StateTimestamp{{Seconds: -62135596801}, {Seconds: 253402300800}, {Seconds: math.MaxInt64}, {Nanos: 1000000000}} {
		r.RevokedAt = at
		require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
	}
}

func TestStateCodecBoundedCollections(t *testing.T) {
	s := stateFixture(t)
	s.Tasks[0].Targets = make([]TargetIdentity, maxStateReferences+1)
	_, err := MarshalStateSnapshot(s)
	require.ErrorIs(t, err, ErrStateSnapshot)
	data, err := MarshalStateSnapshot(emptyStateFixture())
	require.NoError(t, err)
	// The schema pass rejects a hostile collection before json.Unmarshal can
	// allocate the full typed slice, even though its encoded size is small.
	minimal := `{"XID":"11111111-1111-4111-8111-111111111111","Targets":[],"DestinationIDs":[],"DeliveryType":3,"Status":0}`
	data = bytes.Replace(data, []byte(`"tasks":[]`), []byte(`"tasks":[`+strings.Repeat(minimal+`,`, MaxStateTasks)+minimal+`]`), 1)
	_, err = UnmarshalStateSnapshot(data)
	require.ErrorIs(t, err, ErrStateSnapshot)
	require.Contains(t, err.Error(), "collection limit exceeded")
	_, err = UnmarshalStateSnapshot(bytes.Repeat([]byte(" "), MaxStateSnapshotBytes+1))
	require.ErrorIs(t, err, ErrStateSnapshot)
}

func TestStateCodecMaximumSmallTaskCount(t *testing.T) {
	if testing.Short() {
		t.Skip("maximum-size memory fixture")
	}
	s := emptyStateFixture()
	did := uuid.New()
	// Optional legacy fields can be absent. The canonical encoder writes them,
	// so construct the valid compact representation independently here.
	var data bytes.Buffer
	fmt.Fprintf(&data, `{"version":2,"written_at":"2026-01-02T03:04:05Z","incarnation":%q,"tasks":[`, s.Incarnation)
	for n := 0; n < MaxStateTasks; n++ {
		if n != 0 {
			data.WriteByte(',')
		}
		var id uuid.UUID
		binary.BigEndian.PutUint64(id[8:], uint64(n+1))
		fmt.Fprintf(&data, `{"XID":%q,"Targets":[{"Type":1,"Value":"sip:x"}],"DestinationIDs":[%q],"DeliveryType":3,"Status":0}`, id, did)
	}
	data.WriteString(`],"destinations":[],"cleanup_needed":{},"generations":{},"intents":[],"revocations":[]}`)
	require.Less(t, data.Len(), MaxStateSnapshotBytes)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	restored, err := UnmarshalStateSnapshot(data.Bytes())
	require.NoError(t, err)
	runtime.ReadMemStats(&after)
	require.Len(t, restored.Tasks, MaxStateTasks)
	// Heap residency includes typed collections, the streaming parser and
	// validation indexes. TotalAlloc also includes reclaimed token garbage.
	require.Less(t, after.HeapAlloc-before.HeapAlloc, uint64(maxStateDecodeBytes))
	t.Logf("%d-byte source, %d bytes additional resident heap", data.Len(), after.HeapAlloc-before.HeapAlloc)
	runtime.KeepAlive(restored)
}

func TestStateCodecSubjectlessCleanupAndHistoricalCandidate(t *testing.T) {
	s := stateFixture(t)
	cleanup := &StateIntent{OperationID: uuid.New(), Kind: StateCleanup, StateIncarnation: s.Incarnation, Phase: StateReserved, CleanupFilterIDs: []string{"li-12345678-0"}, RevocationIDs: []uuid.UUID{}}
	s.Intents = []*StateIntent{cleanup}
	require.NoError(t, ValidateStateSnapshot(s))
	copyIntent := *cleanup
	copyIntent.OperationID = uuid.New()
	s.Intents = append(s.Intents, &copyIntent)
	require.NoError(t, ValidateStateSnapshot(s), "unknown owners remain separate operation identities")
	for name, change := range map[string]func(*StateIntent){"empty": func(i *StateIntent) { i.CleanupFilterIDs = []string{} }, "generation": func(i *StateIntent) { i.PreviousGeneration = 1 }, "revocation": func(i *StateIntent) { i.RevocationIDs = []uuid.UUID{uuid.New()} }, "candidate": func(i *StateIntent) { i.CandidateTask = s.Tasks[0] }, "purge": func(i *StateIntent) { i.Kind = StatePurge }} {
		t.Run(name, func(t *testing.T) {
			bad := *cleanup
			change(&bad)
			s.Intents = []*StateIntent{&bad}
			require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
		})
	}
	historical, intent := stateIntentFixture(t, StateTaskActivate)
	intent.Phase = StateFinished
	for _, task := range historical.Tasks {
		task.Status = TaskStatusDeactivated
	}
	historical.Destinations = []*StateDestination{}
	require.NoError(t, ValidateStateSnapshot(historical))
	intent.Phase = StateReserved
	require.ErrorIs(t, ValidateStateSnapshot(historical), ErrStateSnapshot)
}
