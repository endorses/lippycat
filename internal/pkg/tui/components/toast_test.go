//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToastSupersession_RemovesQueuedToastsWithSameKey(t *testing.T) {
	toast := NewToast()

	// Show first toast with key "a"
	toast.ShowWithKey("First-A", ToastInfo, ToastDurationShort, "key-a")
	assert.True(t, toast.IsActive())
	assert.Equal(t, "First-A", toast.message)
	assert.Equal(t, "key-a", toast.currentKey)

	// Queue toast with key "b"
	toast.ShowWithKey("First-B", ToastInfo, ToastDurationShort, "key-b")
	assert.Equal(t, 1, len(toast.queue))

	// Queue another toast with key "a" - should be queued (current is "a", but we queue anyway)
	toast.ShowWithKey("Second-A", ToastInfo, ToastDurationShort, "key-a")
	// Since current has same key, Second-A replaces First-A immediately
	assert.Equal(t, "Second-A", toast.message)
	assert.Equal(t, 1, len(toast.queue)) // Only First-B in queue

	// Queue toast with key "c"
	toast.ShowWithKey("First-C", ToastInfo, ToastDurationShort, "key-c")
	assert.Equal(t, 2, len(toast.queue)) // First-B and First-C

	// Queue another toast with key "b" - should remove First-B from queue
	toast.ShowWithKey("Second-B", ToastSuccess, ToastDurationShort, "key-b")
	assert.Equal(t, 2, len(toast.queue)) // First-C and Second-B (First-B removed)

	// Verify queue contents
	assert.Equal(t, "key-c", toast.queue[0].supersessionKey)
	assert.Equal(t, "First-C", toast.queue[0].message)
	assert.Equal(t, "key-b", toast.queue[1].supersessionKey)
	assert.Equal(t, "Second-B", toast.queue[1].message)
}

func TestToastSupersession_DismissesCurrentToastWithSameKey(t *testing.T) {
	toast := NewToast()

	// Show first toast with key
	toast.ShowWithKey("Connecting...", ToastInfo, ToastDurationShort, "connection:192.168.1.1")
	assert.True(t, toast.IsActive())
	assert.Equal(t, "Connecting...", toast.message)

	// Show second toast with same key - should dismiss first and show immediately
	toast.ShowWithKey("Connected!", ToastSuccess, ToastDurationShort, "connection:192.168.1.1")
	assert.True(t, toast.IsActive())
	assert.Equal(t, "Connected!", toast.message)
	assert.Equal(t, "connection:192.168.1.1", toast.currentKey)
	assert.Equal(t, 0, len(toast.queue)) // No queue - replaced immediately
}

func TestToastSupersession_DifferentKeysAreIndependent(t *testing.T) {
	toast := NewToast()

	// Show first toast with key "a"
	toast.ShowWithKey("Server A connecting", ToastInfo, ToastDurationShort, "connection:a")
	assert.True(t, toast.IsActive())
	assert.Equal(t, "Server A connecting", toast.message)

	// Queue toast with key "b"
	toast.ShowWithKey("Server B connecting", ToastInfo, ToastDurationShort, "connection:b")
	assert.Equal(t, 1, len(toast.queue))

	// Show "Server A connected" with same key as current - replaces current immediately
	toast.ShowWithKey("Server A connected", ToastSuccess, ToastDurationShort, "connection:a")
	assert.Equal(t, "Server A connected", toast.message) // Current is now this
	assert.Equal(t, 1, len(toast.queue))                 // Still just B connecting

	// Queue "Server B connected" - should replace "Server B connecting" in queue
	toast.ShowWithKey("Server B connected", ToastSuccess, ToastDurationShort, "connection:b")
	assert.Equal(t, 1, len(toast.queue)) // Only "Server B connected" remains

	// Verify the queue has the right message
	assert.Equal(t, "connection:b", toast.queue[0].supersessionKey)
	assert.Equal(t, "Server B connected", toast.queue[0].message)
}

func TestToastSupersession_NoKeyBehavesNormally(t *testing.T) {
	toast := NewToast()

	// Show toast without key
	toast.Show("Message 1", ToastInfo, ToastDurationShort)
	assert.True(t, toast.IsActive())
	assert.Equal(t, "", toast.currentKey)

	// Queue more toasts without keys
	toast.Show("Message 2", ToastInfo, ToastDurationShort)
	toast.Show("Message 3", ToastInfo, ToastDurationShort)

	// All should be queued normally
	assert.Equal(t, 2, len(toast.queue))
	assert.Equal(t, "Message 2", toast.queue[0].message)
	assert.Equal(t, "Message 3", toast.queue[1].message)
}

func TestToastSupersession_MixedKeyedAndUnkeyedToasts(t *testing.T) {
	toast := NewToast()

	// Show keyed toast with key "capture-state"
	toast.ShowWithKey("Paused", ToastInfo, ToastDurationShort, "capture-state")
	assert.True(t, toast.IsActive())
	assert.Equal(t, "Paused", toast.message)

	// Queue unkeyed toast
	toast.Show("Some message", ToastInfo, ToastDurationShort)
	assert.Equal(t, 1, len(toast.queue))

	// Show keyed toast with same key "capture-state" - replaces current immediately
	toast.ShowWithKey("Resumed", ToastSuccess, ToastDurationShort, "capture-state")
	assert.Equal(t, "Resumed", toast.message) // Current is now "Resumed"
	assert.Equal(t, 1, len(toast.queue))      // Unkeyed "Some message" still in queue

	// Verify queue contains the unkeyed message
	assert.Equal(t, "", toast.queue[0].supersessionKey)
	assert.Equal(t, "Some message", toast.queue[0].message)
}

func TestToastSupersession_HideClearsCurrentKey(t *testing.T) {
	toast := NewToast()

	// Show keyed toast
	toast.ShowWithKey("Message", ToastInfo, ToastDurationShort, "test-key")
	assert.Equal(t, "test-key", toast.currentKey)

	// Hide should clear the key
	toast.Hide()
	assert.False(t, toast.IsActive())
	assert.Equal(t, "", toast.currentKey)
}

func TestToastKeyConnection(t *testing.T) {
	// Test the helper function
	key1 := ToastKeyConnection("192.168.1.1:50051")
	key2 := ToastKeyConnection("192.168.1.2:50051")

	assert.Equal(t, "connection:192.168.1.1:50051", key1)
	assert.Equal(t, "connection:192.168.1.2:50051", key2)
	assert.NotEqual(t, key1, key2)
}

func TestToastSupersession_QueueProcessingPreservesKey(t *testing.T) {
	toast := NewToast()

	// Show first toast (will expire)
	toast.ShowWithKey("First", ToastInfo, 0, "key-1")
	assert.True(t, toast.IsActive())

	// Queue second toast with different key
	toast.ShowWithKey("Second", ToastInfo, ToastDurationShort, "key-2")
	assert.Equal(t, 1, len(toast.queue))

	// Simulate tick that causes first toast to expire
	// The Update method will show the next queued toast
	toast.startTime = time.Now().Add(-time.Hour) // Force expiration
	toast.Update(ToastTickMsg{Time: time.Now()})

	// Second toast should now be active with its key
	assert.True(t, toast.IsActive())
	assert.Equal(t, "Second", toast.message)
	assert.Equal(t, "key-2", toast.currentKey)
	assert.Equal(t, 0, len(toast.queue))
}
