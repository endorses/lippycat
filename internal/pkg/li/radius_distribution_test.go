//go:build li

package li

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	processorfilter "github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type radiusDistributionPusher struct {
	manager    *processorfilter.Manager
	failDelete bool
}

func (p *radiusDistributionPusher) UpdateFilter(f *management.Filter) error {
	_, err := p.manager.Update(f)
	return err
}
func (p *radiusDistributionPusher) DeleteFilter(id string) error {
	if p.failDelete {
		return fmt.Errorf("injected withdrawal failure")
	}
	_, err := p.manager.Delete(id)
	return err
}
func (p *radiusDistributionPusher) ListFilterIDs() []string {
	var ids []string
	for _, f := range p.manager.GetAll() {
		ids = append(ids, f.Id)
	}
	return ids
}

func TestRADIUSRealDistributionLifecycleRevisions(t *testing.T) {
	p := &radiusDistributionPusher{manager: processorfilter.NewManager("", nil, nil, nil, nil)}
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: p}, nil)
	task := radiusTargetTask()
	for _, did := range task.DestinationIDs {
		require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
	}
	require.NoError(t, m.ActivateTask(task))
	first := p.manager.GetAll()
	require.Len(t, first, 1)
	require.Equal(t, uint64(1), first[0].Revision)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf2.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
	destinations := []uuid.UUID{did}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{DestinationIDs: &destinations}))
	second := p.manager.GetAll()
	require.Len(t, second, 1)
	require.Equal(t, uint64(2), second[0].Revision)
	require.Equal(t, uint64(2), second[0].Radius.TaskGeneration)
	require.NoError(t, m.DeactivateTask(task.XID))
	require.Empty(t, p.manager.GetAll())
	task.DestinationIDs = destinations
	require.NoError(t, m.ActivateTask(task))
	third := p.manager.GetAll()
	require.Len(t, third, 1)
	require.Equal(t, uint64(3), third[0].Revision)
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "state.json")
	m.config.StateFile = path
	require.NoError(t, m.persistState())
	restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path, FilterPusher: p}, nil)
	require.NoError(t, restarted.restorePersistedState())
	require.Empty(t, p.manager.GetAll())
	require.NoError(t, restarted.activateStartupTask(current))
	fourth := p.manager.GetAll()
	require.Len(t, fourth, 1)
	require.Equal(t, uint64(4), fourth[0].Revision)
	// A transport-delayed older definition cannot regress installed enforcement.
	require.Error(t, p.UpdateFilter(third[0]))
	require.Equal(t, uint64(4), p.manager.GetAll()[0].Revision)
}

func TestRADIUSFailedMigrationWithdrawalCannotArmRegistry(t *testing.T) {
	task := radiusTargetTask()
	task.Status = TaskStatusActive
	p := &radiusDistributionPusher{manager: processorfilter.NewManager("", nil, nil, nil, nil)}
	legacy := &management.Filter{Id: fmt.Sprintf("li-%s-0", task.XID), Type: management.FilterType_FILTER_SIP_URI, Pattern: "alice@example.test", Enabled: true}
	require.NoError(t, p.UpdateFilter(legacy))
	p.failDelete = true
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}}))
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path, FilterPusher: p}, nil)
	require.Error(t, m.restorePersistedState())
	require.Zero(t, m.TaskCount())
	_, ok := m.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
	require.False(t, ok)
	require.False(t, m.ReplayTaskAuthorized(task.XID, task.ActivationGeneration))
}

func TestRADIUSInvalidReconciliationRevokesBeforeFailedWithdrawal(t *testing.T) {
	p := &radiusDistributionPusher{manager: processorfilter.NewManager("", nil, nil, nil, nil)}
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: p}, nil)
	task := radiusTargetTask()
	for _, did := range task.DestinationIDs {
		require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
	}
	require.NoError(t, m.ActivateTask(task))
	old, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	p.failDelete = true
	replacement := *old
	replacement.DeliveryType = DeliveryX2andX3
	handled, err := m.reconcileRADIUSTask(&replacement)
	require.True(t, handled)
	require.Error(t, err)
	require.NotEmpty(t, p.manager.GetAll(), "remote cleanup remains pending")
	_, ok := m.AcquireTaskAdmission(task.XID, old.ActivationGeneration)
	require.False(t, ok)
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusFailed, current.Status)
}
