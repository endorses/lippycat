package detector

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func TestIndependentDefaultDetectorDoesNotShareFlowClassification(t *testing.T) {
	first, second := NewWithDefaultSignatures(), NewWithDefaultSignatures()
	t.Cleanup(first.Shutdown)
	t.Cleanup(second.Shutdown)
	packet := createTestPacket([]byte("unrecognized application payload"))
	flowID := first.BuildContext(packet).FlowID
	first.cache.Set(flowID, &signatures.DetectionResult{Protocol: "SESSION-ONE", CacheStrategy: signatures.CacheFlow})
	require.Equal(t, "SESSION-ONE", first.Detect(packet).Protocol)
	require.NotEqual(t, "SESSION-ONE", second.Detect(packet).Protocol)
	require.Positive(t, first.cache.maxEntries)
	require.Positive(t, first.flows.maxEntries)
	// Closing one replacement must leave the other session usable.
	first.Shutdown()
	require.NotNil(t, second.Detect(packet))
}
