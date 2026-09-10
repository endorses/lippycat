//go:build li

package delivery

import (
	"container/heap"
	"time"
)

// expiryHeap holds only deadline-bearing X3 entries, including claimed entries.
// Removing a claim's deadline never releases its queue capacity; its owner does.
type expiryHeap []*deliveryItem

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].metadata.Deadline.Before(h[j].metadata.Deadline) }
func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].expiryIndex = i
	h[j].expiryIndex = j
}
func (h *expiryHeap) Push(value any) {
	item := value.(*deliveryItem)
	item.expiryIndex = len(*h)
	*h = append(*h, item)
}
func (h *expiryHeap) Pop() any {
	old := *h
	item := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	item.expiryIndex = -1
	return item
}
func (q *destinationQueue) refreshExpiryLocked() {
	q.nextExpiry = time.Time{}
	if len(q.expiry) > 0 {
		q.nextExpiry = q.expiry[0].metadata.Deadline
	}
}
func (q *destinationQueue) observeDeadlineLocked(item *deliveryItem) {
	if q.stopped || item.element == nil || item.pduType != PDUTypeX3 || item.metadata.Deadline.IsZero() {
		return
	}
	if item.expiryIndex < 0 {
		heap.Push(&q.expiry, item)
	}
	q.refreshExpiryLocked()
}
func (q *destinationQueue) removeExpiryLocked(item *deliveryItem) {
	if item.expiryIndex >= 0 {
		heap.Remove(&q.expiry, item.expiryIndex)
	}
	q.refreshExpiryLocked()
}
func (q *destinationQueue) takeExpiredLocked(now time.Time) *deliveryItem {
	if len(q.expiry) == 0 || now.Before(q.expiry[0].metadata.Deadline) {
		return nil
	}
	item := heap.Pop(&q.expiry).(*deliveryItem)
	q.refreshExpiryLocked()
	return item
}
