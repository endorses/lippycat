package li

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry(nil)
	require.NotNil(t, r)
	assert.Equal(t, 0, r.TaskCount())
	assert.Equal(t, 0, r.DestinationCount())
}

func TestRegistryActivateTask(t *testing.T) {
	r := NewRegistry(nil)

	// Create a destination first
	dest := &Destination{
		DID:       uuid.New(),
		Address:   "mdf.example.com",
		Port:      5001,
		X2Enabled: true,
	}
	require.NoError(t, r.CreateDestination(dest))

	t.Run("successful activation", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2andX3,
		}

		err := r.ActivateTask(task)
		require.NoError(t, err)

		// Verify task is stored
		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, task.XID, retrieved.XID)
		assert.Equal(t, TaskStatusActive, retrieved.Status)
		assert.False(t, retrieved.ActivatedAt.IsZero())
	})

	t.Run("duplicate XID", func(t *testing.T) {
		xid := uuid.New()
		task := &InterceptTask{
			XID: xid,
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}

		err := r.ActivateTask(task)
		require.NoError(t, err)

		// Try to activate again with same XID
		err = r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTaskAlreadyExists))
	})

	t.Run("invalid task nil", func(t *testing.T) {
		err := r.ActivateTask(nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid task nil XID", func(t *testing.T) {
		task := &InterceptTask{
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:test@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		err := r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid task no targets", func(t *testing.T) {
		task := &InterceptTask{
			XID:            uuid.New(),
			Targets:        []TargetIdentity{},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		err := r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid task empty target value", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: ""},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		err := r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid task no destinations", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:test@example.com"},
			},
			DeliveryType: DeliveryX2Only,
		}
		err := r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid task unknown destination", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:test@example.com"},
			},
			DestinationIDs: []uuid.UUID{uuid.New()}, // Unknown DID
			DeliveryType:   DeliveryX2Only,
		}
		err := r.ActivateTask(task)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDestinationNotFound))
	})

	t.Run("pending task with future start time", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:future@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
			StartTime:      time.Now().Add(time.Hour),
		}

		err := r.ActivateTask(task)
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, TaskStatusPending, retrieved.Status)
	})
}

func TestRegistryModifyTask(t *testing.T) {
	r := NewRegistry(nil)

	// Create destinations
	dest1 := &Destination{DID: uuid.New(), Address: "mdf1.example.com", Port: 5001}
	dest2 := &Destination{DID: uuid.New(), Address: "mdf2.example.com", Port: 5002}
	require.NoError(t, r.CreateDestination(dest1))
	require.NoError(t, r.CreateDestination(dest2))

	// Create a task
	task := &InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
		},
		DestinationIDs: []uuid.UUID{dest1.DID},
		DeliveryType:   DeliveryX2Only,
	}
	require.NoError(t, r.ActivateTask(task))

	t.Run("modify targets", func(t *testing.T) {
		newTargets := []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"},
		}
		err := r.ModifyTask(task.XID, &TaskModification{Targets: &newTargets})
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Len(t, retrieved.Targets, 2)
	})

	t.Run("modify destinations", func(t *testing.T) {
		newDests := []uuid.UUID{dest1.DID, dest2.DID}
		err := r.ModifyTask(task.XID, &TaskModification{DestinationIDs: &newDests})
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Len(t, retrieved.DestinationIDs, 2)
	})

	t.Run("modify delivery type", func(t *testing.T) {
		dt := DeliveryX2andX3
		err := r.ModifyTask(task.XID, &TaskModification{DeliveryType: &dt})
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, DeliveryX2andX3, retrieved.DeliveryType)
	})

	t.Run("modify end time", func(t *testing.T) {
		endTime := time.Now().Add(24 * time.Hour)
		err := r.ModifyTask(task.XID, &TaskModification{EndTime: &endTime})
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, endTime.Unix(), retrieved.EndTime.Unix())
	})

	t.Run("modify implicit deactivation", func(t *testing.T) {
		allowed := true
		err := r.ModifyTask(task.XID, &TaskModification{ImplicitDeactivationAllowed: &allowed})
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.True(t, retrieved.ImplicitDeactivationAllowed)
	})

	t.Run("modify nonexistent task", func(t *testing.T) {
		dt := DeliveryX3Only
		err := r.ModifyTask(uuid.New(), &TaskModification{DeliveryType: &dt})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTaskNotFound))
	})

	t.Run("modify with invalid destination", func(t *testing.T) {
		invalidDest := []uuid.UUID{uuid.New()}
		err := r.ModifyTask(task.XID, &TaskModification{DestinationIDs: &invalidDest})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDestinationNotFound))
	})

	t.Run("modify with empty target value", func(t *testing.T) {
		invalidTargets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: ""}}
		err := r.ModifyTask(task.XID, &TaskModification{Targets: &invalidTargets})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("modify deactivated task fails", func(t *testing.T) {
		deactivatedTask := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:deactivated@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest1.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(deactivatedTask))
		require.NoError(t, r.DeactivateTask(deactivatedTask.XID))

		dt := DeliveryX3Only
		err := r.ModifyTask(deactivatedTask.XID, &TaskModification{DeliveryType: &dt})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrModifyNotAllowed))
	})
}

func TestRegistryDeactivateTask(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	t.Run("successful deactivation", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:test@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))

		err := r.DeactivateTask(task.XID)
		require.NoError(t, err)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, TaskStatusDeactivated, retrieved.Status)
		assert.False(t, retrieved.DeactivatedAt.IsZero())
	})

	t.Run("idempotent deactivation", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:idempotent@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))
		require.NoError(t, r.DeactivateTask(task.XID))

		// Second deactivation should succeed
		err := r.DeactivateTask(task.XID)
		require.NoError(t, err)
	})

	t.Run("deactivate nonexistent task", func(t *testing.T) {
		err := r.DeactivateTask(uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTaskNotFound))
	})
}

func TestRegistryGetTaskDetails(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	task := &InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:alice@example.com"},
			{Type: TargetTypeIPv4Address, Value: "192.168.1.100"},
		},
		DestinationIDs: []uuid.UUID{dest.DID},
		DeliveryType:   DeliveryX2andX3,
	}
	require.NoError(t, r.ActivateTask(task))

	t.Run("returns copy", func(t *testing.T) {
		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)

		// Modify the copy
		retrieved.Targets = append(retrieved.Targets, TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:hacker@evil.com"})

		// Original should be unchanged
		original, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Len(t, original.Targets, 2)
	})

	t.Run("nonexistent task", func(t *testing.T) {
		_, err := r.GetTaskDetails(uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrTaskNotFound))
	})
}

func TestRegistryListTasks(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	// Create multiple tasks
	for i := 0; i < 5; i++ {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:user@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))
	}

	t.Run("iterate all tasks", func(t *testing.T) {
		count := 0
		r.ListTasks(func(task *InterceptTask) bool {
			count++
			return true
		})
		assert.Equal(t, 5, count)
	})

	t.Run("early termination", func(t *testing.T) {
		count := 0
		r.ListTasks(func(task *InterceptTask) bool {
			count++
			return count < 3
		})
		assert.Equal(t, 3, count)
	})
}

func TestRegistryGetActiveTasks(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	// Create 3 active tasks
	for i := 0; i < 3; i++ {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:active@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))
	}

	// Create and deactivate 2 tasks
	for i := 0; i < 2; i++ {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:deactivated@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))
		require.NoError(t, r.DeactivateTask(task.XID))
	}

	active := r.GetActiveTasks()
	assert.Len(t, active, 3)
	assert.Equal(t, 3, r.ActiveTaskCount())
	assert.Equal(t, 5, r.TaskCount())
}

func TestRegistryDestinations(t *testing.T) {
	r := NewRegistry(nil)

	t.Run("create destination", func(t *testing.T) {
		dest := &Destination{
			DID:         uuid.New(),
			Address:     "mdf.example.com",
			Port:        5001,
			X2Enabled:   true,
			X3Enabled:   true,
			Description: "Test MDF",
		}
		err := r.CreateDestination(dest)
		require.NoError(t, err)

		retrieved, err := r.GetDestination(dest.DID)
		require.NoError(t, err)
		assert.Equal(t, dest.DID, retrieved.DID)
		assert.Equal(t, "mdf.example.com", retrieved.Address)
		assert.False(t, retrieved.CreatedAt.IsZero())
	})

	t.Run("duplicate DID", func(t *testing.T) {
		did := uuid.New()
		dest := &Destination{DID: did, Address: "mdf1.example.com", Port: 5001}
		require.NoError(t, r.CreateDestination(dest))

		dup := &Destination{DID: did, Address: "mdf2.example.com", Port: 5002}
		err := r.CreateDestination(dup)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDestinationAlreadyExists))
	})

	t.Run("invalid destination nil", func(t *testing.T) {
		err := r.CreateDestination(nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid destination empty address", func(t *testing.T) {
		dest := &Destination{DID: uuid.New(), Port: 5001}
		err := r.CreateDestination(dest)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))
	})

	t.Run("invalid destination bad port", func(t *testing.T) {
		dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 0}
		err := r.CreateDestination(dest)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTask))

		dest.Port = 70000
		err = r.CreateDestination(dest)
		require.Error(t, err)
	})

	t.Run("remove destination", func(t *testing.T) {
		dest := &Destination{DID: uuid.New(), Address: "remove.example.com", Port: 5001}
		require.NoError(t, r.CreateDestination(dest))

		err := r.RemoveDestination(dest.DID)
		require.NoError(t, err)

		_, err = r.GetDestination(dest.DID)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDestinationNotFound))
	})

	t.Run("remove nonexistent destination", func(t *testing.T) {
		err := r.RemoveDestination(uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrDestinationNotFound))
	})
}

func TestRegistryMarkTaskFailed(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	task := &InterceptTask{
		XID: uuid.New(),
		Targets: []TargetIdentity{
			{Type: TargetTypeSIPURI, Value: "sip:test@example.com"},
		},
		DestinationIDs: []uuid.UUID{dest.DID},
		DeliveryType:   DeliveryX2Only,
	}
	require.NoError(t, r.ActivateTask(task))

	err := r.MarkTaskFailed(task.XID, "connection to MDF lost")
	require.NoError(t, err)

	retrieved, err := r.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusFailed, retrieved.Status)
	assert.Equal(t, "connection to MDF lost", retrieved.LastError)
	assert.False(t, retrieved.DeactivatedAt.IsZero())
}

func TestRegistryPurgeDeactivatedTasks(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	// Create and deactivate tasks
	for i := 0; i < 5; i++ {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:purge@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))
		require.NoError(t, r.DeactivateTask(task.XID))
	}

	assert.Equal(t, 5, r.TaskCount())

	// Purge tasks older than 0 duration (immediate)
	purged := r.PurgeDeactivatedTasks(0)
	assert.Equal(t, 5, purged)
	assert.Equal(t, 0, r.TaskCount())
}

func TestRegistryDeactivationCallback(t *testing.T) {
	var callbackCalled atomic.Int32
	var callbackTask *InterceptTask
	var callbackReason DeactivationReason
	var mu sync.Mutex

	callback := func(task *InterceptTask, reason DeactivationReason) {
		callbackCalled.Add(1)
		mu.Lock()
		callbackTask = task
		callbackReason = reason
		mu.Unlock()
	}

	r := NewRegistry(callback)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	t.Run("callback on deactivate", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:callback@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))

		callbackCalled.Store(0)
		err := r.DeactivateTask(task.XID)
		require.NoError(t, err)

		assert.Equal(t, int32(1), callbackCalled.Load())
		mu.Lock()
		assert.Equal(t, task.XID, callbackTask.XID)
		assert.Equal(t, DeactivationReasonADMF, callbackReason)
		mu.Unlock()
	})

	t.Run("callback on mark failed", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:failed@example.com"},
			},
			DestinationIDs: []uuid.UUID{dest.DID},
			DeliveryType:   DeliveryX2Only,
		}
		require.NoError(t, r.ActivateTask(task))

		callbackCalled.Store(0)
		err := r.MarkTaskFailed(task.XID, "test failure")
		require.NoError(t, err)

		assert.Equal(t, int32(1), callbackCalled.Load())
		mu.Lock()
		assert.Equal(t, task.XID, callbackTask.XID)
		assert.Equal(t, DeactivationReasonFault, callbackReason)
		mu.Unlock()
	})
}

func TestRegistryImplicitDeactivation(t *testing.T) {
	var callbackCalled atomic.Int32
	var mu sync.Mutex
	var callbackReason DeactivationReason

	callback := func(task *InterceptTask, reason DeactivationReason) {
		callbackCalled.Add(1)
		mu.Lock()
		callbackReason = reason
		mu.Unlock()
	}

	r := NewRegistry(callback)
	r.Start()
	defer r.Stop()

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	t.Run("task expires when implicit deactivation allowed", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:expire@example.com"},
			},
			DestinationIDs:              []uuid.UUID{dest.DID},
			DeliveryType:                DeliveryX2Only,
			EndTime:                     time.Now().Add(100 * time.Millisecond),
			ImplicitDeactivationAllowed: true,
		}
		require.NoError(t, r.ActivateTask(task))

		// Wait for expiration check
		time.Sleep(1500 * time.Millisecond)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		assert.Equal(t, TaskStatusDeactivated, retrieved.Status)

		mu.Lock()
		assert.Equal(t, DeactivationReasonExpired, callbackReason)
		mu.Unlock()
	})

	t.Run("task does not expire when implicit deactivation not allowed", func(t *testing.T) {
		task := &InterceptTask{
			XID: uuid.New(),
			Targets: []TargetIdentity{
				{Type: TargetTypeSIPURI, Value: "sip:noexpire@example.com"},
			},
			DestinationIDs:              []uuid.UUID{dest.DID},
			DeliveryType:                DeliveryX2Only,
			EndTime:                     time.Now().Add(100 * time.Millisecond),
			ImplicitDeactivationAllowed: false, // Not allowed
		}
		require.NoError(t, r.ActivateTask(task))

		// Wait past EndTime
		time.Sleep(1500 * time.Millisecond)

		retrieved, err := r.GetTaskDetails(task.XID)
		require.NoError(t, err)
		// Should still be active
		assert.Equal(t, TaskStatusActive, retrieved.Status)
	})
}

func TestRegistryConcurrency(t *testing.T) {
	r := NewRegistry(nil)

	dest := &Destination{DID: uuid.New(), Address: "mdf.example.com", Port: 5001}
	require.NoError(t, r.CreateDestination(dest))

	const goroutines = 10
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()

			for i := 0; i < operationsPerGoroutine; i++ {
				task := &InterceptTask{
					XID: uuid.New(),
					Targets: []TargetIdentity{
						{Type: TargetTypeSIPURI, Value: "sip:concurrent@example.com"},
					},
					DestinationIDs: []uuid.UUID{dest.DID},
					DeliveryType:   DeliveryX2Only,
				}

				if err := r.ActivateTask(task); err != nil {
					t.Errorf("ActivateTask failed: %v", err)
					return
				}

				_, err := r.GetTaskDetails(task.XID)
				if err != nil {
					t.Errorf("GetTaskDetails failed: %v", err)
					return
				}

				newTargets := []TargetIdentity{
					{Type: TargetTypeSIPURI, Value: "sip:modified@example.com"},
				}
				if err := r.ModifyTask(task.XID, &TaskModification{Targets: &newTargets}); err != nil {
					t.Errorf("ModifyTask failed: %v", err)
					return
				}

				if err := r.DeactivateTask(task.XID); err != nil {
					t.Errorf("DeactivateTask failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// All tasks should be created
	assert.Equal(t, goroutines*operationsPerGoroutine, r.TaskCount())
	// All tasks should be deactivated
	assert.Equal(t, 0, r.ActiveTaskCount())
}
