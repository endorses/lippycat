//go:build li

package li

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestNewManager(t *testing.T) {
	config := ManagerConfig{
		Enabled:      true,
		X1ListenAddr: "0.0.0.0:8443",
		ADMFEndpoint: "https://admf.example.com:8443",
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)
	assert.Equal(t, config.Enabled, m.IsEnabled())
	assert.Equal(t, config.X1ListenAddr, m.Config().X1ListenAddr)
	assert.Equal(t, config.ADMFEndpoint, m.Config().ADMFEndpoint)
}

func TestManager_StartStop(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	// Start should succeed
	err := m.Start()
	require.NoError(t, err)

	// Stop should not panic
	m.Stop()
}

func TestManager_DisabledMode(t *testing.T) {
	config := ManagerConfig{
		Enabled: false,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// ProcessPacket should return quickly when disabled
	pkt := &types.PacketDisplay{
		SrcIP:   "192.168.1.100",
		DstIP:   "10.0.0.1",
		SrcPort: "5060",
		DstPort: "5060",
	}

	// Should not panic - pass empty filter IDs since no tasks exist
	m.ProcessPacket(pkt, nil)
	m.ProcessPacket(nil, nil)
	m.ProcessPacket(pkt, []string{"some-filter-id"})
}

func TestManager_TaskLifecycle(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	var deactivatedTasks []uuid.UUID
	var mu sync.Mutex

	deactivationCallback := func(task *InterceptTask, reason DeactivationReason) {
		mu.Lock()
		deactivatedTasks = append(deactivatedTasks, task.XID)
		mu.Unlock()
	}

	m := NewManager(config, deactivationCallback)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Create destination first
	destDID := uuid.New()
	dest := &Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
		X3Enabled: true,
	}
	err = m.CreateDestination(dest)
	require.NoError(t, err)

	// Activate a task
	taskXID := uuid.New()
	task := &InterceptTask{
		XID: taskXID,
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2andX3,
	}

	err = m.ActivateTask(task)
	require.NoError(t, err)

	// Verify task was created
	assert.Equal(t, 1, m.TaskCount())
	assert.Equal(t, 1, m.ActiveTaskCount())
	assert.Equal(t, 2, m.FilterCount()) // 2 targets = 2 filters

	// Get task details
	retrieved, err := m.GetTaskDetails(taskXID)
	require.NoError(t, err)
	assert.Equal(t, taskXID, retrieved.XID)
	assert.Equal(t, TaskStatusActive, retrieved.Status)

	// Deactivate the task
	err = m.DeactivateTask(taskXID)
	require.NoError(t, err)

	// Verify task is deactivated
	assert.Equal(t, 1, m.TaskCount()) // Still in registry for audit
	assert.Equal(t, 0, m.ActiveTaskCount())
	assert.Equal(t, 0, m.FilterCount()) // Filters removed

	// Verify callback was called
	mu.Lock()
	assert.Contains(t, deactivatedTasks, taskXID)
	mu.Unlock()
}

func TestManager_ModifyTask(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Create destination
	destDID := uuid.New()
	dest := &Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
	}
	err = m.CreateDestination(dest)
	require.NoError(t, err)

	// Activate a task
	taskXID := uuid.New()
	task := &InterceptTask{
		XID: taskXID,
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2Only,
	}

	err = m.ActivateTask(task)
	require.NoError(t, err)
	assert.Equal(t, 1, m.FilterCount())

	// Modify targets
	newTargets := []TargetIdentity{
		{Type: TargetTypeIPv4Address, Value: "192.168.1.101"},
		{Type: TargetTypeIPv4Address, Value: "192.168.1.102"},
	}

	err = m.ModifyTask(taskXID, &TaskModification{
		Targets: &newTargets,
	})
	require.NoError(t, err)

	// Verify filters updated
	assert.Equal(t, 2, m.FilterCount())

	// Verify task has new targets
	retrieved, err := m.GetTaskDetails(taskXID)
	require.NoError(t, err)
	assert.Equal(t, 2, len(retrieved.Targets))
}

func TestManager_ProcessPacket_WithMatch(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Track matched packets
	var matchedPackets []*types.PacketDisplay
	var matchedTasks []*InterceptTask
	var mu sync.Mutex

	m.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		mu.Lock()
		matchedTasks = append(matchedTasks, task)
		matchedPackets = append(matchedPackets, pkt)
		mu.Unlock()
	})

	// Create destination and task
	destDID := uuid.New()
	err = m.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	taskXID := uuid.New()
	err = m.ActivateTask(&InterceptTask{
		XID: taskXID,
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2Only,
	})
	require.NoError(t, err)

	// Get the filter IDs created for this task
	// (In production, these come from the hunter's filter matching)
	filterIDs := m.filters.GetFiltersForXID(taskXID)
	require.Len(t, filterIDs, 1)

	// Process a packet with the matching filter ID
	// (simulating what the hunter's filter system would return)
	matchingPkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "10.0.0.1",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "UDP",
	}

	m.ProcessPacket(matchingPkt, filterIDs)

	// Verify match was processed
	stats := m.Stats()
	assert.Equal(t, uint64(1), stats.PacketsProcessed)
	assert.Equal(t, uint64(1), stats.PacketsMatched)

	mu.Lock()
	assert.Len(t, matchedPackets, 1)
	assert.Len(t, matchedTasks, 1)
	if len(matchedTasks) > 0 {
		assert.Equal(t, taskXID, matchedTasks[0].XID)
	}
	mu.Unlock()
}

func TestManager_ProcessPacket_NoMatch(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Track matched packets
	var matchCount int
	var mu sync.Mutex

	m.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		mu.Lock()
		matchCount++
		mu.Unlock()
	})

	// Create destination and task
	destDID := uuid.New()
	err = m.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	err = m.ActivateTask(&InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2Only,
	})
	require.NoError(t, err)

	// Process a packet with a non-LI filter ID
	// (simulating a filter match that isn't from an LI task)
	nonMatchingPkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "10.0.0.50",
		DstIP:     "10.0.0.1",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "UDP",
	}

	// Pass a filter ID that doesn't belong to any LI task
	m.ProcessPacket(nonMatchingPkt, []string{"non-li-filter-id"})

	// Verify no match (filter ID doesn't map to any LI task)
	stats := m.Stats()
	assert.Equal(t, uint64(1), stats.PacketsProcessed)
	assert.Equal(t, uint64(0), stats.PacketsMatched)

	mu.Lock()
	assert.Equal(t, 0, matchCount)
	mu.Unlock()
}

func TestManager_ProcessPacket_VoIPMatch(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	require.NotNil(t, m)

	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	var matchCount int
	var mu sync.Mutex

	m.SetPacketProcessor(func(task *InterceptTask, pkt *types.PacketDisplay) {
		mu.Lock()
		matchCount++
		mu.Unlock()
	})

	// Create destination and task with phone number target
	destDID := uuid.New()
	err = m.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
		X3Enabled: true,
	})
	require.NoError(t, err)

	taskXID := uuid.New()
	err = m.ActivateTask(&InterceptTask{
		XID: taskXID,
		Targets: []TargetIdentity{
			{Type: TargetTypeTELURI, Value: "tel:+15551234567"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2andX3,
	})
	require.NoError(t, err)

	// Get the filter IDs for this task
	filterIDs := m.filters.GetFiltersForXID(taskXID)
	require.Len(t, filterIDs, 1)

	// Process a VoIP packet with the matching filter ID
	// (In production, the hunter's PhoneNumberMatcher would match this)
	voipPkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "10.0.0.1",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "UDP",
		VoIPData: &types.VoIPMetadata{
			CallID: "call-123@example.com",
			Method: "INVITE",
			From:   "sip:+15551234567@example.com",
			To:     "sip:bob@example.com",
		},
	}

	m.ProcessPacket(voipPkt, filterIDs)

	stats := m.Stats()
	assert.Equal(t, uint64(1), stats.PacketsProcessed)
	assert.Equal(t, uint64(1), stats.PacketsMatched)

	mu.Lock()
	assert.Equal(t, 1, matchCount)
	mu.Unlock()
}

func TestManager_MarkTaskFailed(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	var failedTasks []uuid.UUID
	var mu sync.Mutex

	deactivationCallback := func(task *InterceptTask, reason DeactivationReason) {
		if reason == DeactivationReasonFault {
			mu.Lock()
			failedTasks = append(failedTasks, task.XID)
			mu.Unlock()
		}
	}

	m := NewManager(config, deactivationCallback)
	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Create destination and task
	destDID := uuid.New()
	err = m.CreateDestination(&Destination{
		DID:       destDID,
		Address:   "mdf.example.com",
		Port:      8443,
		X2Enabled: true,
	})
	require.NoError(t, err)

	taskXID := uuid.New()
	err = m.ActivateTask(&InterceptTask{
		XID: taskXID,
		Targets: []TargetIdentity{
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DestinationIDs: []uuid.UUID{destDID},
		DeliveryType:   DeliveryX2Only,
	})
	require.NoError(t, err)

	// Mark as failed
	err = m.MarkTaskFailed(taskXID, "Connection to MDF failed")
	require.NoError(t, err)

	// Verify status
	task, err := m.GetTaskDetails(taskXID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusFailed, task.Status)
	assert.Equal(t, "Connection to MDF failed", task.LastError)

	// Verify callback
	mu.Lock()
	assert.Contains(t, failedTasks, taskXID)
	mu.Unlock()
}

func TestManager_Destinations(t *testing.T) {
	config := ManagerConfig{
		Enabled: true,
	}

	m := NewManager(config, nil)
	err := m.Start()
	require.NoError(t, err)
	defer m.Stop()

	// Create destination
	destDID := uuid.New()
	dest := &Destination{
		DID:         destDID,
		Address:     "mdf.example.com",
		Port:        8443,
		X2Enabled:   true,
		X3Enabled:   true,
		Description: "Test MDF",
	}

	err = m.CreateDestination(dest)
	require.NoError(t, err)

	// Get destination
	retrieved, err := m.GetDestination(destDID)
	require.NoError(t, err)
	assert.Equal(t, "mdf.example.com", retrieved.Address)
	assert.Equal(t, 8443, retrieved.Port)
	assert.True(t, retrieved.X2Enabled)
	assert.True(t, retrieved.X3Enabled)

	// Remove destination
	err = m.RemoveDestination(destDID)
	require.NoError(t, err)

	// Verify removed
	_, err = m.GetDestination(destDID)
	assert.Error(t, err)
}
