//go:build li

package delivery

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func auditOfflineManager(did uuid.UUID) *Manager {
	return &Manager{destinations: map[uuid.UUID]*destinationState{did: {dest: &li.Destination{DID: did, ProtocolType: "X2ANDX3"}}}}
}

// Admission clocks can be out of order because different RTP streams reorder
// independently. A short-lived tail must expire while the head is backing off.
func TestAuditEarlierDeadlineArrivalExpiresDuringBackoff(t *testing.T) {
	did := uuid.New()
	cfg := DefaultClientConfig()
	cfg.X3MaxAge = 2 * time.Second
	cfg.RetryInitialBackoff = time.Second
	cfg.RetryMaxBackoff = time.Second
	cfg.ShutdownTimeout = time.Millisecond
	c := NewClient(auditOfflineManager(did), cfg)
	require.NoError(t, c.Err())
	c.Start()
	defer c.Stop()
	xid := uuid.New()
	require.NoError(t, c.SendX3(xid, []uuid.UUID{did}, []byte("head")))
	require.Eventually(t, func() bool { return c.Stats().Retries > 0 }, time.Second, time.Millisecond)
	require.NoError(t, c.SendX3WithMetadata(xid, []uuid.UUID{did}, []byte("tail"), DeliveryMetadata{AdmittedAt: time.Now().Add(-1950 * time.Millisecond)}))
	require.Eventually(t, func() bool { return c.DestinationStats()[did].X3Expired == 1 }, 300*time.Millisecond, time.Millisecond)
	require.Equal(t, int64(4), c.Stats().QueueBytes)
}

func TestAuditConcurrentAdmissionCancellationAndRemoval(t *testing.T) {
	did := uuid.New()
	cfg := DefaultClientConfig()
	cfg.QueueSize = 32
	cfg.X2QueueBytes = 4096
	cfg.X3QueueBytes = 2048
	c := NewClient(auditOfflineManager(did), cfg)
	require.NoError(t, c.Err())
	const workers = 8
	const sends = 200
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			xid := uuid.New()
			for i := 0; i < sends; i++ {
				payload := make([]byte, 64+(i%8)*64)
				_ = c.SendX3WithMetadata(xid, []uuid.UUID{did}, payload, DeliveryMetadata{CallID: fmt.Sprint(worker), CallGeneration: 1, TaskGeneration: 1})
				if i%3 == 0 {
					c.CancelCall(fmt.Sprint(worker), 1)
				}
				if i%29 == 0 {
					c.RemoveDestination(did)
				}
			}
		}(worker)
	}
	wg.Wait()
	for _, stats := range c.DestinationStats() {
		require.LessOrEqual(t, stats.X3QueueBytes, cfg.X3QueueBytes)
		require.LessOrEqual(t, stats.X3QueueDepth, cfg.QueueSize)
	}
	c.Stop()
	stats := c.Stats()
	require.Zero(t, stats.QueueDepth)
	require.Zero(t, stats.QueueBytes)
	require.Equal(t, uint64(workers*sends), stats.X3Dropped)
}

func TestAuditCaptureClockCannotExtendLocalLifetime(t *testing.T) {
	did := uuid.New()
	cfg := DefaultClientConfig()
	cfg.X3MaxAge = time.Minute
	client := NewClient(auditOfflineManager(did), cfg)
	defer client.Stop()
	admitted := time.Now()
	for _, capture := range []time.Time{admitted.Add(-24 * time.Hour), admitted.Add(24 * time.Hour)} {
		require.NoError(t, client.SendX3WithMetadata(uuid.New(), []uuid.UUID{did}, []byte("x3"), DeliveryMetadata{AdmittedAt: admitted, CapturedAt: capture, Deadline: admitted.Add(time.Hour)}))
	}
	entries := client.getOrCreateQueue(did).peekBatch(2)
	require.Len(t, entries, 2)
	for _, entry := range entries {
		require.Equal(t, admitted.Add(time.Minute), entry.metadata.Deadline)
	}
}
