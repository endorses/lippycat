//go:build li

package li

import (
	"time"

	"github.com/google/uuid"
)

const (
	StateSchemaVersion    = 2
	MaxStateSnapshotBytes = 32 << 20
	MaxStateTasks         = 65_536
	MaxStateDestinations  = 4_096
	MaxStateObligations   = 262_144
	// Administrative revocations share the administrative obligation ceiling;
	// journals have their own independently configured control-index limits.
	MaxStateRevocations     = MaxStateObligations
	maxStateReferences      = 256
	maxStateTotalReferences = 1_048_576
	maxStateStringBytes     = 4_096
	maxStateDecodeBytes     = 256 << 20
)

// StateSnapshot is a detached administrative document, never authorization.
// Lifecycle owners must confirm restored tasks and reconcile intents separately.
type StateSnapshot struct {
	Version                    int                    `json:"version"`
	WrittenAt                  time.Time              `json:"written_at"`
	Incarnation                uuid.UUID              `json:"incarnation"`
	RADIUSCorrelationStateFile string                 `json:"radius_correlation_state_file,omitempty"`
	Tasks                      []*InterceptTask       `json:"tasks"`
	Destinations               []*StateDestination    `json:"destinations"`
	CleanupNeeded              map[uuid.UUID][]string `json:"cleanup_needed"`
	Generations                map[uuid.UUID]uint64   `json:"generations"`
	Intents                    []*StateIntent         `json:"intents"`
	Revocations                []*StateRevocation     `json:"revocations"`
}

// StateDestination deliberately excludes transport TLS configuration and keys.
type StateDestination struct {
	DID              uuid.UUID `json:"did"`
	Address          string    `json:"address"`
	Port             int       `json:"port"`
	X2Enabled        bool      `json:"x2_enabled"`
	X3Enabled        bool      `json:"x3_enabled"`
	ProtocolType     string    `json:"protocol_type,omitempty"`
	Description      string    `json:"description,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	DeliveryRevision uint64    `json:"delivery_revision,omitempty"`
}

type StateIntentKind string
type StateIntentPhase string

const (
	StateTaskActivate        StateIntentKind  = "task_activate"
	StateTaskReactivate      StateIntentKind  = "task_reactivate"
	StateTaskPromote         StateIntentKind  = "task_promote"
	StateTaskConfirm         StateIntentKind  = "task_confirm"
	StateTaskModify          StateIntentKind  = "task_modify"
	StateTaskUpdate          StateIntentKind  = "task_update"
	StateTaskDeactivate      StateIntentKind  = "task_deactivate"
	StateTaskExpire          StateIntentKind  = "task_expire"
	StateTaskFail            StateIntentKind  = "task_fail"
	StateDestinationCreate   StateIntentKind  = "destination_create"
	StateDestinationModify   StateIntentKind  = "destination_modify"
	StateDestinationUpdate   StateIntentKind  = "destination_update"
	StateDestinationRemove   StateIntentKind  = "destination_remove"
	StateCleanup             StateIntentKind  = "cleanup"
	StatePurge               StateIntentKind  = "purge"
	StateReserved            StateIntentPhase = "reserved"
	StateRevocationCommitted StateIntentPhase = "revocation_committed"
	StatePolicyCommitted     StateIntentPhase = "policy_committed"
	StateFinished            StateIntentPhase = "finished"
)

type StateIntent struct {
	OperationID          uuid.UUID         `json:"operation_id"`
	Kind                 StateIntentKind   `json:"kind"`
	StateIncarnation     uuid.UUID         `json:"state_incarnation"`
	XID                  *uuid.UUID        `json:"xid"`
	DID                  *uuid.UUID        `json:"did"`
	PreviousGeneration   uint64            `json:"previous_generation"`
	ReservedGeneration   uint64            `json:"reserved_generation"`
	Phase                StateIntentPhase  `json:"phase"`
	CandidateTask        *InterceptTask    `json:"candidate_task"`
	CandidateDestination *StateDestination `json:"candidate_destination"`
	CleanupFilterIDs     []string          `json:"cleanup_filter_ids"`
	RevocationIDs        []uuid.UUID       `json:"revocation_ids"`
	Failed               bool              `json:"failed"`
}

type StateRevocationScope string

const (
	StateRevokeTask        StateRevocationScope = "task"
	StateRevokeDestination StateRevocationScope = "destination"
	StateRevokeCall        StateRevocationScope = "call"
)

type StateTimestamp struct {
	Seconds int64  `json:"seconds"`
	Nanos   uint32 `json:"nanos"`
}

func NewStateTimestamp(at time.Time) StateTimestamp {
	return StateTimestamp{Seconds: at.Unix(), Nanos: uint32(at.Nanosecond())}
}

type StateRevocation struct {
	Version                   int                  `json:"version"`
	ControlID                 uuid.UUID            `json:"control_id"`
	JournalUUID               uuid.UUID            `json:"journal_uuid"`
	StateIncarnation          uuid.UUID            `json:"state_incarnation"`
	Scope                     StateRevocationScope `json:"scope"`
	XID                       *uuid.UUID           `json:"xid"`
	TaskGeneration            *uint64              `json:"task_generation"`
	DID                       *uuid.UUID           `json:"did"`
	DestinationGeneration     *uint64              `json:"destination_generation"`
	CallIncarnation           *uuid.UUID           `json:"call_incarnation"`
	CallGeneration            *uint64              `json:"call_generation"`
	CoveredRecordHighwater    uint64               `json:"covered_record_highwater"`
	CoveredAdmissionHighwater uint64               `json:"covered_admission_highwater"`
	RevokedAt                 StateTimestamp       `json:"revoked_at"`
}
