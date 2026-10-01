//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCompletenessOnlyRepairCountsAndLogsWithoutValues(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	incomplete := convergenceDetails(xid, did, true)
	flag := false
	incomplete.TaskDetails.ImplicitDeactivationAllowed = &flag
	converted, err := ConvertSnapshotTask(incomplete)
	require.NoError(t, err)
	// Legacy definitions may retain values without knowing the end boundary.
	converted.Task.Definition.Completeness.End = false
	require.NoError(t, m.ActivateTask(converted.Task))
	before, _ := m.GetTaskDetails(xid)
	var output bytes.Buffer
	logger.UseFile(&output)
	t.Cleanup(logger.UseStderr)
	full := convergenceDetails(xid, did, true)
	full.TaskDetails.ImplicitDeactivationAllowed = &flag
	applyConvergence(t, m, full)
	require.EqualValues(t, 1, m.Stats().Definitions.Repairs)
	require.Zero(t, m.Stats().Definitions.Incomplete)
	after, _ := m.GetTaskDetails(xid)
	require.Equal(t, before.ActivationGeneration, after.ActivationGeneration)
	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.Equal(t, "LI task definition repaired", record["msg"])
	require.Equal(t, []any{"completeness"}, record["fields"])
	require.NotContains(t, output.String(), before.Targets[0].Value)
	require.NotContains(t, output.String(), did.String())
	applyConvergence(t, m, full)
	require.EqualValues(t, 1, m.Stats().Definitions.Repairs)
}

func TestPartialAdmissionLogDescribesEffectiveWindow(t *testing.T) {
	var output bytes.Buffer
	logger.UseFile(&output)
	t.Cleanup(logger.UseStderr)
	task := &InterceptTask{XID: uuid.New(), StartTime: time.Now().Add(-time.Hour), EndTime: time.Now().Add(time.Hour), ImplicitDeactivationAllowed: true}
	task.Definition = authoritativeDefinition(task)
	logPartialDefinitionAdmission(task)
	var record map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.Equal(t, "bounded", record["window"])
	require.Equal(t, false, record["explicit_deactivation_required"])
	output.Reset()
	task.Definition.Completeness = DefinitionCompleteness{}
	task.EndTime = time.Time{}
	task.ImplicitDeactivationAllowed = false
	logPartialDefinitionAdmission(task)
	require.NoError(t, json.Unmarshal(output.Bytes(), &record))
	require.Equal(t, "unknown", record["window"])
	require.Equal(t, true, record["explicit_deactivation_required"])
}

func TestStrictContractPreservesRADIUSRestartAndReadback(t *testing.T) {
	task := radiusTargetTask()
	task.StartTime = time.Now().Add(-time.Hour).UTC()
	task.EndTime = time.Now().Add(time.Hour).UTC()
	task.ImplicitDeactivationAllowed = true
	task.Status = TaskStatusActive
	did := task.DestinationIDs[0]
	path := filepath.Join(t.TempDir(), "state")
	require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "127.0.0.1", Port: 8443, X2Enabled: true, ProtocolType: "X2Only"}}}))
	m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: path, ADMFCompleteTaskContract: true, RADIUSScope: task.RADIUSScope, RADIUSMACProfile: task.RADIUSMACProfile}, nil)
	require.NoError(t, m.Start())
	require.Zero(t, m.TaskCount())
	require.Equal(t, DefinitionStats{}, m.Stats().Definitions)
	require.NoError(t, m.activateStartupTask(task))
	response, err := m.GetTaskDetailsX1(task.XID)
	require.NoError(t, err)
	require.Nil(t, response.DefinitionPresence, "RADIUS keeps its specialized complete serializer semantics")
	require.Equal(t, task.StartTime, response.StartTime)
	require.Equal(t, task.EndTime, response.EndTime)
	require.True(t, response.ImplicitDeactivationAllowed)
	require.Equal(t, DefinitionStats{}, m.Stats().Definitions)
	require.False(t, m.ReplayTaskAuthorized(task.XID, task.ActivationGeneration))
}
