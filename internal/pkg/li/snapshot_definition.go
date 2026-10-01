//go:build li

package li

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
)

// SnapshotTask preserves presence independently of the values in Task.
type SnapshotTask struct {
	Task                  *InterceptTask
	Completeness          DefinitionCompleteness
	confirmedDestinations map[uuid.UUID]bool
}

func ConvertSnapshotTask(details *schema.TaskResponseDetails) (*SnapshotTask, error) {
	task, err := TaskResponseDetailsToInterceptTask(details)
	if err != nil {
		return nil, err
	}
	if IsRADIUSTask(task) {
		return &SnapshotTask{Task: task}, nil
	}
	td := details.TaskDetails
	c := DefinitionCompleteness{Implicit: td.ImplicitDeactivationAllowed != nil}
	if list := td.ListOfMediationDetails; list != nil {
		c.Mediation = true
		if len(list.MediationDetails) == 0 {
			return nil, fmt.Errorf("empty mediation definition")
		}
		for i, md := range list.MediationDetails {
			if md == nil {
				return nil, fmt.Errorf("nil mediation entry")
			}
			if md.StartTime != nil && *md.StartTime == "" || md.EndTime != nil && *md.EndTime == "" {
				return nil, fmt.Errorf("empty mediation timestamp")
			}
			start, end := md.StartTime != nil, md.EndTime != nil
			if i > 0 && (c.Start != start || c.EndProvided != end) {
				return nil, fmt.Errorf("inconsistent mediation presence")
			}
			c.Start, c.EndProvided = start, end
			c.End = start || end
		}
	}
	task.Definition = TaskDefinitionState{Source: DefinitionPull, Completeness: c}
	return &SnapshotTask{Task: task, Completeness: c}, nil
}
