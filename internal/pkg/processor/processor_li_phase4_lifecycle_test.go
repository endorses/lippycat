//go:build (processor || tap || all) && li

package processor

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
)

func TestPhase4FinalizeBeforeReorderTimerSuppressesBufferedDelivery(t *testing.T) {
	lifecycle := NewCallLifecycleRegistry(CallLifecycleConfig{})
	var delivered atomic.Uint64
	buffer := delivery.NewCallAwareReorderBuffer(func(entry delivery.ReorderEntry) {
		admission, err := lifecycle.AdmitGeneration(entry.CallID, entry.Generation)
		if err != nil {
			return
		}
		defer admission.Release()
		delivered.Add(1)
	}, 25*time.Millisecond)
	t.Cleanup(buffer.Discard)
	lifecycle.Subscribe(func(event CallFinalizationEvent) {
		buffer.DiscardCall(event.CallID, event.Generation)
	})

	admission, err := lifecycle.Admit("timer-call")
	require.NoError(t, err)
	generation := admission.Generation()
	admission.Release()
	buffer.DeliverCallX3("timer-call", generation, 42, 10, []byte("first"))
	buffer.DeliverCallX3("timer-call", generation, 42, 12, []byte("buffered"))
	require.Equal(t, uint64(1), delivered.Load(), "the stream's first packet is synchronous")

	require.True(t, lifecycle.Finalize("timer-call", CallFinalizationProtocolComplete).Finalized)
	time.Sleep(75 * time.Millisecond)
	assert.Equal(t, uint64(1), delivered.Load(), "the timer must not deliver after finalization")
}

func TestPhase4OldBufferedGenerationCannotAttachToReusedCallID(t *testing.T) {
	lifecycle := NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: 5 * time.Millisecond})
	var delivered atomic.Uint64
	buffer := delivery.NewCallAwareReorderBuffer(func(entry delivery.ReorderEntry) {
		admission, err := lifecycle.AdmitGeneration(entry.CallID, entry.Generation)
		if err != nil {
			return
		}
		defer admission.Release()
		delivered.Add(1)
	}, 40*time.Millisecond)
	t.Cleanup(buffer.Discard)

	old, err := lifecycle.Admit("reused-call")
	require.NoError(t, err)
	oldGeneration := old.Generation()
	old.Release()
	buffer.DeliverCallX3("reused-call", oldGeneration, 77, 10, []byte("first"))
	buffer.DeliverCallX3("reused-call", oldGeneration, 77, 12, []byte("old-buffered"))
	require.Equal(t, uint64(1), delivered.Load())
	require.True(t, lifecycle.Finalize("reused-call", CallFinalizationProtocolComplete).Finalized)

	time.Sleep(10 * time.Millisecond)
	current, err := lifecycle.Admit("reused-call")
	require.NoError(t, err)
	require.NotEqual(t, oldGeneration, current.Generation())
	current.Release()

	time.Sleep(75 * time.Millisecond)
	assert.Equal(t, uint64(1), delivered.Load(), "old callback must fail generation admission")
}

func TestPhase4FinalizationClearsMediaDirectionForOnlyThatCall(t *testing.T) {
	p, xid, _ := newLIProcessor(t, li.DeliveryX3Only)

	liMediaDirection.ObserveSIP(xid, dirTarget, dirSIPPacket(
		"INVITE "+dirRemoteURI+" SIP/2.0", 0, dirTargetURI, dirRemoteURI, "", dirSDP(dirGWAddr, dirGWPort),
	))
	require.Equal(t, 1, liMediaDirection.Stats().CallsTracked)

	admission, err := p.callLifecycle.Admit(dirCallID)
	require.NoError(t, err)
	admission.Release()
	require.True(t, p.callLifecycle.Finalize(dirCallID, CallFinalizationProtocolComplete).Finalized)
	assert.Equal(t, 0, liMediaDirection.Stats().CallsTracked)
}
