//go:build li

package delivery

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func authorizationTask(xid uuid.UUID, generation uint64, end time.Time) *li.InterceptTask {
	return &li.InterceptTask{XID: xid, ActivationGeneration: generation, Status: li.TaskStatusActive, EndTime: end, ImplicitDeactivationAllowed: true}
}

func TestX3CommittedCutoffAndStaleQueueExpiry(t *testing.T) {
	did, xid := uuid.New(), uuid.New()
	cfg := DefaultClientConfig()
	cfg.AuthoritativeTaskAuthorization = true
	c := NewClient(auditOfflineManager(did), cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	old, extended := time.Now().Add(time.Minute), time.Now().Add(time.Hour)
	c.PublishX3TaskAuthorization(authorizationTask(xid, 1, old))
	m := DeliveryMetadata{TaskGeneration: 1, TaskEndAt: old, Deadline: time.Now().Add(2 * time.Hour)}
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("retained"), m))
	q := c.getOrCreateQueue(did)
	q.mu.Lock()
	item := q.items[1].Front().Value.(*deliveryItem)
	q.mu.Unlock()
	c.SetX3TaskAuthorization(xid, 1, extended)
	require.Equal(t, extended, c.taskDeadline(item))
	require.Equal(t, m.Deadline, item.metadata.Deadline)
	// Emulate a queued expiry index left behind by a fact-only publication.
	q.mu.Lock()
	q.removeExpiryLocked(item)
	item.eligibilityDeadline = time.Now().Add(-time.Second)
	q.observeDeadlineLocked(item)
	q.mu.Unlock()
	c.expireQueued(q)
	require.Equal(t, 1, c.QueueDepth())
	require.True(t, c.itemEligible(did, item, false))
	q.mu.Lock()
	require.Equal(t, extended, item.eligibilityDeadline)
	q.mu.Unlock()
	// An explicit zero committed fact overrides old packet metadata.
	c.SetX3TaskAuthorization(xid, 1, time.Time{})
	c.expireQueued(q)
	require.True(t, c.taskDeadline(item).IsZero())
	require.Equal(t, m.Deadline, item.metadata.Deadline)
}

func TestX3PacketMetadataCannotExtendRememberedAuthorization(t *testing.T) {
	did, xid := uuid.New(), uuid.New()
	c := NewClient(auditOfflineManager(did), DefaultClientConfig())
	require.NoError(t, c.Err())
	defer c.Stop()
	old := time.Now().Add(-time.Second)
	c.rememberX3TaskAuthorization(xid, 1, old)
	c.rememberX3TaskAuthorization(xid, 1, time.Now().Add(time.Hour))
	require.Equal(t, old, c.x3TaskEnd(xid, 1))
	require.Error(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("late"), DeliveryMetadata{TaskGeneration: 1, TaskEndAt: time.Now().Add(time.Hour)}))
}

func TestX3AuthoritativeRetirementRejectsOldPermits(t *testing.T) {
	did, xid := uuid.New(), uuid.New()
	cfg := DefaultClientConfig()
	cfg.AuthoritativeTaskAuthorization = true
	c := NewClient(auditOfflineManager(did), cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	task := authorizationTask(xid, 1, time.Now().Add(time.Hour))
	c.PublishX3TaskAuthorization(task)
	permit, err := c.PrepareX3(xid, did, []byte("old permit"), DeliveryMetadata{TaskGeneration: 1})
	require.NoError(t, err)
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("queued"), DeliveryMetadata{TaskGeneration: 1}))
	task.Status = li.TaskStatusDeactivated
	c.PublishX3TaskAuthorization(task)
	// The manager's terminal publication precedes its cancellation callback.
	// Missing facts must not prevent immediate queue/transport cancellation.
	c.CancelTask(xid, 1)
	require.Zero(t, c.QueueDepth())
	c.SetX3TaskAuthorization(xid, 1, time.Now().Add(2*time.Hour))
	require.Empty(t, c.taskFacts)
	require.Empty(t, c.revokedTasks)
	require.Error(t, c.SendAcceptedX3(permit))
	permit.Release()
	task.Status, task.ActivationGeneration = li.TaskStatusActive, 2
	c.PublishX3TaskAuthorization(task)
	require.Error(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("stale"), DeliveryMetadata{TaskGeneration: 1}))
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("new"), DeliveryMetadata{TaskGeneration: 2}))
	// Expiry is permanent while the same generation remains published.
	c.SetX3TaskAuthorization(xid, 2, time.Now().Add(-time.Second))
	c.PublishX3TaskAuthorization(authorizationTask(xid, 2, time.Now().Add(time.Hour)))
	require.Error(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("revived"), DeliveryMetadata{TaskGeneration: 2}))
}

func TestX3AuthoritativeTaskChurnAndLiveCapacity(t *testing.T) {
	did := uuid.New()
	cfg := DefaultClientConfig()
	cfg.AuthoritativeTaskAuthorization = true
	c := NewClient(auditOfflineManager(did), cfg)
	require.NoError(t, c.Err())
	defer c.Stop()
	stable := authorizationTask(uuid.New(), 1, time.Time{})
	c.PublishX3TaskAuthorization(stable)
	for i := 0; i < maxDeliveryGateIdentities+1; i++ {
		task := authorizationTask(uuid.New(), 1, time.Time{})
		c.PublishX3TaskAuthorization(task)
		c.CancelTask(task.XID, task.ActivationGeneration)
		task.Status = li.TaskStatusDeactivated
		c.PublishX3TaskAuthorization(task)
	}
	require.Len(t, c.taskFacts, 1)
	require.Len(t, c.currentTasks, 1)
	require.Empty(t, c.revokedTasks)
	require.Empty(t, c.expiredTaskControls)
	require.False(t, c.gateFault)
	require.NoError(t, c.SendX3WithMetadata(stable.XID, []uuid.UUID{did}, []byte("still authorized"), DeliveryMetadata{TaskGeneration: 1}))
	for i := 1; i < maxDeliveryGateIdentities; i++ {
		c.PublishX3TaskAuthorization(authorizationTask(uuid.New(), 1, time.Time{}))
	}
	c.PublishX3TaskAuthorization(authorizationTask(uuid.New(), 1, time.Time{}))
	require.True(t, c.gateFault)
	require.Len(t, c.taskFacts, maxDeliveryGateIdentities)
	require.Error(t, c.SendX3WithMetadata(stable.XID, []uuid.UUID{did}, []byte("capacity fault"), DeliveryMetadata{TaskGeneration: 1}))
	// X2 is independent of the X3 authorization gate.
	require.NoError(t, c.SendX2(stable.XID, []uuid.UUID{did}, []byte("IRI")))
}
