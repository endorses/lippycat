//go:build (processor || tap || all) && li

package processor

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/stretchr/testify/require"
)

func TestLIIdleReorderCleanupPreservesReplacement(t *testing.T) {
	key := "idle-cleanup-replacement"
	replacement := delivery.NewReorderBuffer(func([]byte) {}, time.Hour)
	old := delivery.NewReorderBuffer(func(pdu []byte) {
		if string(pdu) == "buffered" {
			// A task transition removes the old buffer and a new activation
			// installs its owner while the idle sweep flushes the old callback.
			liReorderBuffers.Store(key, replacement)
		}
	}, time.Hour)
	t.Cleanup(func() {
		old.Discard()
		replacement.Discard()
		old.Wait()
		replacement.Wait()
		liReorderBuffers.Delete(key)
	})
	liReorderBuffers.Store(key, old)
	old.DeliverX3(1, 10, []byte("first"))
	old.DeliverX3(1, 12, []byte("buffered"))
	cleanupLIReorderBuffer(key, old, -time.Second)
	actual, present := liReorderBuffers.Load(key)
	require.True(t, present, "idle sweep must retain the new activation's owner")
	require.Same(t, replacement, actual)
}
