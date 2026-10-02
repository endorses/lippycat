//go:build (processor || tap || all) && li

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestLISnapshotStatusMapping(t *testing.T) {
	id := uuid.New().String()
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	status := li.SnapshotSyncStatus{Source: "periodic", State: "partial", Attempts: 9, LastAttempt: at,
		TaskFailures: 33, DestinationFailures: 1, TotalFailures: 34, FailuresTruncated: 2,
		TaskOrphanRemovalSuppressed: true, DestinationOrphanRemovalSuppressed: true, WarningsSuppressed: 7,
		Failures: []li.SnapshotFailure{{Kind: "task", Category: "conversion_failed", EntryIndex: 3, UUID: id}, {Kind: "destination", Category: "missing_list", EntryIndex: -1}},
	}
	mapped := mapLISnapshotSyncStats(status)
	require.Equal(t, "periodic", mapped.Source)
	require.Equal(t, "partial", mapped.State)
	require.EqualValues(t, 9, mapped.Attempts)
	require.Equal(t, at.Format(time.RFC3339Nano), mapped.LastAttempt)
	require.EqualValues(t, 33, mapped.TaskFailures)
	require.EqualValues(t, 1, mapped.DestinationFailures)
	require.EqualValues(t, 34, mapped.TotalFailures)
	require.EqualValues(t, 2, mapped.FailuresTruncated)
	require.True(t, mapped.TaskOrphanRemovalSuppressed)
	require.True(t, mapped.DestinationOrphanRemovalSuppressed)
	require.EqualValues(t, 7, mapped.WarningsSuppressed)
	require.Equal(t, id, mapped.Failures[0].Uuid)
	require.Equal(t, "conversion_failed", mapped.Failures[0].Category)
	require.EqualValues(t, -1, mapped.Failures[1].EntryIndex)
	require.Empty(t, mapped.Failures[1].Uuid)
	status.Failures[0].UUID = "changed"
	require.Equal(t, id, mapped.Failures[0].Uuid)
	require.Empty(t, mapLISnapshotSyncStats(li.SnapshotSyncStatus{}).LastAttempt)
	disabled := &management.ProcessorStats{}
	(&Processor{}).populateLIEncodingStats(disabled)
	require.Nil(t, disabled.LiReconciliation)
}
