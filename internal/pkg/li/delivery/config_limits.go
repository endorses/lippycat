//go:build li

package delivery

import (
	"fmt"
	"math"
	"time"
)

// ReservedDestinationBytes estimates the isolated payload and owner allocation
// for one destination. Payload budgets include claimed entries. Reserving each
// destination copy separately is conservative even when encoded bytes are shared.
func (c ClientConfig) ReservedDestinationBytes() (int64, error) {
	x2, x3 := c.EffectiveQueueSizes()
	if c.QueueSize < 0 || x2 < 0 || x3 < 0 || c.X2QueueBytes < 0 || c.X3QueueBytes < 0 {
		return 0, fmt.Errorf("LI delivery queue limits must not be negative")
	}
	const overhead = int64(256 * 1024)
	if int64(x2) > (math.MaxInt64-overhead)/1024 || int64(x3) > (math.MaxInt64-overhead)/1024-int64(x2) {
		return 0, fmt.Errorf("LI delivery queue reservation overflows")
	}
	total := (int64(x2)+int64(x3))*1024 + overhead
	for _, capacity := range []int64{c.X2QueueBytes, c.X3QueueBytes} {
		if capacity > math.MaxInt64-total {
			return 0, fmt.Errorf("LI delivery byte reservation overflows")
		}
		total += capacity
	}
	return total, nil
}

// Validate is shared by process and tap through the delivery client boundary.
func (c ClientConfig) Validate() error {
	reserved, err := c.ReservedDestinationBytes()
	if err != nil {
		return err
	}
	if c.X3MaxAge < 0 || c.MemoryBudgetBytes < 0 {
		return fmt.Errorf("LI delivery age and memory budget must not be negative")
	}
	if c.MemoryBudgetBytes > 0 {
		if c.X2QueueBytes == 0 || c.X3QueueBytes == 0 {
			return fmt.Errorf("LI delivery memory budget requires explicit X2 and X3 byte limits")
		}
		global, err := c.ReservedGlobalBytes()
		if err != nil {
			return err
		}
		if reserved > c.MemoryBudgetBytes-global {
			return fmt.Errorf("LI delivery destination reservation %d exceeds memory budget %d", reserved, c.MemoryBudgetBytes)
		}
	}
	if c.X2SpoolReplayPolicy != "" && c.X2SpoolReplayPolicy != "hold" && c.X2SpoolReplayPolicy != "purge" {
		return fmt.Errorf("LI X2 spool replay policy must be hold or purge")
	}
	if c.X2SpoolReplayManifest != "" && (c.X2SpoolDir == "" || c.X2SpoolReplayPolicy == "purge") {
		return fmt.Errorf("LI X2 replay manifest requires enabled spool and hold policy")
	}
	if c.X2SpoolExportManifest != "" && c.X2SpoolDir == "" {
		return fmt.Errorf("LI X2 manifest export requires enabled spool")
	}
	if c.X2SpoolMaxBytes < 0 {
		return fmt.Errorf("LI X2 spool byte limit must not be negative")
	}
	if c.X2SpoolDir == "" {
		if c.X2SpoolMaxBytes != 0 || c.X2SpoolKeyFile != "" {
			return fmt.Errorf("LI X2 spool limit and key require a spool directory")
		}
	} else if c.X2SpoolMaxBytes <= journalFaultReserve || c.X2SpoolKeyFile == "" {
		return fmt.Errorf("LI X2 spool requires a positive byte limit and key file")
	}
	return nil
}

// ReservedGlobalBytes covers the shared RTP reorder stage, journal workers, and
// one incoming payload clone. admissionMu serializes producers, but their clone
// exists before capacity checks can evict or reject against full queues.
func (c ClientConfig) ReservedGlobalBytes() (int64, error) {
	const reorderBytes = int64(16 << 20)
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	journal := c.ReservedJournalBytes()
	if journal > math.MaxInt64-reorderBytes {
		return 0, fmt.Errorf("LI global reservation overflows")
	}
	total := reorderBytes + journal
	admission := max(c.X2QueueBytes, c.X3QueueBytes)
	if admission > math.MaxInt64-total {
		return 0, fmt.Errorf("LI global admission reservation overflows")
	}
	return total + admission, nil
}

// ResourceLimits reports effective configured limits and conservative managed
// reservations. The reservation is not a process RSS measurement.
func (c *Client) ResourceLimits() (maxAge time.Duration, budget, reserved int64) {
	c.queuesMu.RLock()
	count := len(c.queues)
	c.queuesMu.RUnlock()
	per, err := c.config.ReservedDestinationBytes()
	if err != nil {
		return c.config.X3MaxAge, c.config.MemoryBudgetBytes, 0
	}
	global, err := c.config.ReservedGlobalBytes()
	if err != nil || int64(count) > (math.MaxInt64-global)/per {
		return c.config.X3MaxAge, c.config.MemoryBudgetBytes, 0
	}
	return c.config.X3MaxAge, c.config.MemoryBudgetBytes, global + per*int64(count)
}

// EffectiveQueueSizes resolves interface overrides against the legacy PDU cap.
func (c ClientConfig) EffectiveQueueSizes() (int, int) {
	base := c.QueueSize
	if base == 0 {
		base = DefaultQueueSize
	}
	x2, x3 := c.X2QueueSize, c.X3QueueSize
	if x2 == 0 {
		x2 = base
	}
	if x3 == 0 {
		x3 = base
	}
	return x2, x3
}
