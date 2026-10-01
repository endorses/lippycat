package li

// TaskDefinitionSource identifies the source of the effective definition.
type TaskDefinitionSource string

const (
	DefinitionPush    TaskDefinitionSource = "x1"
	DefinitionPull    TaskDefinitionSource = "admf"
	DefinitionRestore TaskDefinitionSource = "restore"
)

// DefinitionCompleteness distinguishes omitted fields from explicit values.
// End is knowledge of the end boundary; EndProvided distinguishes a timestamp
// from an explicitly open end in a complete mediation window.
type DefinitionCompleteness struct {
	Mediation   bool
	Start       bool
	End         bool
	EndProvided bool
	Implicit    bool
}

func (c DefinitionCompleteness) Complete() bool { return c.Mediation && c.Start && c.End && c.Implicit }

type TaskDefinitionState struct {
	Source       TaskDefinitionSource
	Completeness DefinitionCompleteness
	// Restored is evidence of local recovery, not current ADMF confirmation.
	Restored bool
	// Candidate never belongs to the enforcing registry or filter path.
	Candidate bool
	Conflict  bool
}

func authoritativeDefinition(task *InterceptTask) TaskDefinitionState {
	return TaskDefinitionState{Source: DefinitionPush, Completeness: DefinitionCompleteness{
		Mediation: true, Start: true, End: true, EndProvided: !task.EndTime.IsZero(), Implicit: true,
	}}
}

// DefinitionStats uses aggregate counts only, with no target/destination labels.
type DefinitionStats struct {
	Incomplete     uint64
	PullOnly       uint64
	Conflicts      uint64
	UnknownWindows uint64
	OpenEnded      uint64
	Repairs        uint64
}
