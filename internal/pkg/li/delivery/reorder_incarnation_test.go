//go:build li

package delivery

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestReorderIncarnationSurvivesDetachedCallbackAndReuse(t *testing.T) {
	output := make(chan ReorderEntry, 3)
	rb := NewCallAwareReorderBuffer(func(entry ReorderEntry) { output <- entry }, time.Hour)
	defer func() { rb.Stop(); rb.Wait() }()
	oldID, newID := uuid.New(), uuid.New()
	entry := ReorderEntry{CallID: "same-call", Generation: 1, PDU: []byte{1}, Metadata: li.DeliveryMetadata{CallIncarnation: oldID}}
	committed, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		rb.DeliverEntryX3AfterCommit(entry, 1, 1, func() {
			close(committed)
			<-release
		})
	}()
	<-committed
	require.Zero(t, rb.DiscardCall("same-call", 1), "detached batch remains callback-owned")
	secondCommitted, secondFinished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(secondFinished)
		rb.DeliverEntryX3AfterCommit(ReorderEntry{CallID: "same-call", Generation: 2, PDU: []byte{2}, Metadata: li.DeliveryMetadata{CallIncarnation: newID}}, 1, 1, func() { close(secondCommitted) })
	}()
	<-secondCommitted
	close(release)
	<-finished
	<-secondFinished
	old, current := <-output, <-output
	require.Equal(t, oldID, old.Metadata.CallIncarnation)
	require.Equal(t, uint64(1), old.Metadata.CallGeneration)
	require.Equal(t, newID, current.Metadata.CallIncarnation)
	require.Equal(t, uint64(2), current.Metadata.CallGeneration)

	// Legacy/non-call callers still carry a zero identity unchanged in memory.
	rb.DeliverX3(2, 1, []byte{3})
	require.Equal(t, uuid.Nil, (<-output).Metadata.CallIncarnation)
}
