//go:build (processor || tap || all) && li

package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizedCallIDIsStableAndDoesNotExposeInput(t *testing.T) {
	const callID = "synthetic-sensitive-call-id"
	hash := sanitizedCallID(callID)

	assert.Equal(t, "13f0bac39a1dfc32", hash)
	assert.NotContains(t, hash, callID)
	assert.Len(t, hash, 16)
}

func TestLateX3SuppressionCountsEveryRejectionButRateLimitsWarnings(t *testing.T) {
	before := liX3FinalizedSuppressed.Load()
	oldWarning := liX3LastLateWarning.Swap(0)
	t.Cleanup(func() { liX3LastLateWarning.Store(oldWarning) })

	recordLateX3Suppression("synthetic-call-a", 7, "initial_admission")
	firstWarning := liX3LastLateWarning.Load()
	recordLateX3Suppression("synthetic-call-b", 8, "delayed_send_admission")

	assert.Equal(t, before+2, liX3FinalizedSuppressed.Load())
	assert.Positive(t, firstWarning)
	assert.Equal(t, firstWarning, liX3LastLateWarning.Load())
}

func TestBufferedX3DiscardAccountingIgnoresEmptyDiscard(t *testing.T) {
	before := liX3BufferedDiscarded.Load()

	recordBufferedX3Discard(0)
	recordBufferedX3Discard(1)

	assert.Equal(t, before+1, liX3BufferedDiscarded.Load())
}

func TestPopulateLIEncodingStatsExposesLifecycleCounters(t *testing.T) {
	p := &Processor{liManager: li.NewManager(li.ManagerConfig{Enabled: true}, nil)}
	dst := &management.ProcessorStats{}

	p.populateLIEncodingStats(dst)

	require.NotNil(t, dst.LiEncoding)
	assert.Equal(t, liX3FinalizedSuppressed.Load(), dst.LiEncoding.X3FinalizedOrStaleSuppressed)
	assert.Equal(t, liX3BufferedDiscarded.Load(), dst.LiEncoding.X3BufferedDiscarded)
	assert.Equal(t, p.liManager.Stats().InheritedProvenanceRejected, dst.LiEncoding.InheritedProvenanceRejected)
}
