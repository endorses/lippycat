//go:build li

package delivery

import (
	"sync/atomic"
	"time"
)

// DefaultReorderBudgetBytes bounds shared reorder retention when the overall
// delivery memory budget is enabled. Charges include map/timer/object overhead.
const DefaultReorderBudgetBytes int64 = 16 << 20
const reorderStreamCharge int64 = 8192
const reorderBufferCharge int64 = 512
const reorderPacketCharge int64 = 512

type ReorderBudget struct {
	limit int64
	used  atomic.Int64
}

func NewReorderBudget(limit int64) *ReorderBudget { return &ReorderBudget{limit: limit} }
func (b *ReorderBudget) reserve(n int64) bool {
	if b == nil {
		return true
	}
	for {
		old := b.used.Load()
		if n > b.limit-old {
			return false
		}
		if b.used.CompareAndSwap(old, old+n) {
			return true
		}
	}
}
func (b *ReorderBudget) release(n int64) {
	if b != nil {
		b.used.Add(-n)
	}
}
func (b *ReorderBudget) Used() int64 { return b.used.Load() }

// NewBudgetedCallAwareReorderBuffer returns nil if shared object capacity is full.
func NewBudgetedCallAwareReorderBuffer(deliver func(ReorderEntry), delay time.Duration, budget *ReorderBudget, discarded func(int)) *ReorderBuffer {
	if !budget.reserve(reorderBufferCharge) {
		return nil
	}
	config := NewCallAwareReorderBuffer(deliver, delay)
	config.budget = budget
	config.onDiscard = discarded
	config.budgeted = true
	return config
}
