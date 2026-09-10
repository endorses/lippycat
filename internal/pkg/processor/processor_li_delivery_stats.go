//go:build (processor || tap || all) && li

package processor

import (
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
)

func (p *Processor) populateLIDeliveryStats(dst *management.ProcessorStats) {
	if dst == nil || !p.isLIEnabled() || liDeliveryClient == nil {
		return
	}
	stats := liDeliveryClient.Stats()
	dst.LiDelivery = &management.LIDeliveryStats{
		X2EnqueueCalls:  stats.X2Queued,
		UncertainWrites: stats.UncertainWrites, UncertainBytes: stats.UncertainBytes,
		X3EnqueueCalls:     stats.X3Queued,
		X2Written:          stats.X2Sent,
		X3Written:          stats.X3Sent,
		X2Dropped:          stats.X2Dropped,
		X3Dropped:          stats.X3Dropped,
		Retries:            stats.Retries,
		QueueDepth:         stats.QueueDepth,
		QueueBytes:         stats.QueueBytes,
		PhysicalQueueBytes: stats.PhysicalQueueBytes,
		DroppedBytes:       stats.DroppedBytes,
		Destinations:       make(map[string]*management.LIDestinationDeliveryStats),
	}
	maxAge, budget, reserved := liDeliveryClient.ResourceLimits()
	dst.LiDelivery.X3MaxAgeMs = maxAge.Milliseconds()
	dst.LiDelivery.MemoryBudgetBytes = budget
	dst.LiDelivery.ReservedMemoryBytes = reserved
	dst.LiDelivery.DroppedByReason = stats.DroppedByReason
	dst.LiDelivery.DroppedBytesByReason = stats.DroppedBytesByReason
	dst.LiDelivery.FirstDroppedUnixMs = deliveryUnixMillis(stats.FirstDroppedAt)
	journal := liDeliveryClient.JournalStats()
	dst.LiDelivery.X2Journal = &management.LIJournalStats{Bytes: journal.Bytes, MaxBytes: journal.MaxBytes, Pending: uint64(journal.Pending), Persisted: uint64(journal.Persisted), Held: uint64(journal.Held), Rejected: journal.Rejected, LastError: journal.LastError, ReplayPending: uint64(journal.ReplayPending), Uncertain: uint64(journal.Uncertain)}
	for did, queue := range liDeliveryClient.DestinationStats() {
		dst.LiDelivery.Destinations[did.String()] = &management.LIDestinationDeliveryStats{
			QueueDepth:      uint64(queue.QueueDepth),
			UncertainWrites: queue.UncertainWrites, UncertainBytes: queue.UncertainBytes,
			X2QueueBytes: queue.X2QueueBytes, X3QueueBytes: queue.X3QueueBytes,
			X2InFlightBytes: queue.X2InFlightBytes, X3InFlightBytes: queue.X3InFlightBytes,
			X2QueueByteCapacity: queue.X2QueueByteCapacity, X3QueueByteCapacity: queue.X3QueueByteCapacity,
			DroppedBytes: queue.DroppedBytes, DroppedBytesByReason: queue.DroppedBytesByReason, X3Expired: queue.X3Expired,
			X2QueueCapacity:   uint64(queue.X2QueueCapacity),
			X3QueueCapacity:   uint64(queue.X3QueueCapacity),
			X2QueueDepth:      uint64(queue.X2QueueDepth),
			X3QueueDepth:      uint64(queue.X3QueueDepth),
			X2Written:         queue.X2Sent,
			X3Written:         queue.X3Sent,
			X2Dropped:         queue.X2Dropped,
			X3Dropped:         queue.X3Dropped,
			Retries:           queue.Retries,
			DroppedByReason:   queue.DroppedByReason,
			OldestQueuedAgeMs: queue.OldestQueuedAge.Milliseconds(),
			X2OldestAgeMs:     queue.X2OldestAge.Milliseconds(),
			X3OldestAgeMs:     queue.X3OldestAge.Milliseconds(),
			LastWriteUnixMs:   deliveryUnixMillis(queue.LastSuccess),
			LastQueueError:    queue.LastError,
			ConnectionState:   "unknown",
		}
	}
	if liDeliveryMgr == nil {
		return
	}
	for did, conn := range liDeliveryMgr.AllStats() {
		destination := dst.LiDelivery.Destinations[did.String()]
		if destination == nil {
			destination = &management.LIDestinationDeliveryStats{}
			dst.LiDelivery.Destinations[did.String()] = destination
		}
		destination.ConnectionState = conn.ConnectionState
		destination.LastConnectionError = conn.LastError
		destination.ConnectAttempts = conn.ConnectAttempts
		destination.ConnectFailures = conn.ConnectFailures
		destination.WriteErrors = conn.WriteErrors
		destination.X2Connections = conn.X2Connections
		destination.X3Connections = conn.X3Connections
		destination.X2Keepalive = deliveryKeepaliveStats(conn.X2Keepalive)
		destination.X3Keepalive = deliveryKeepaliveStats(conn.X3Keepalive)
	}
}

func deliveryUnixMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func deliveryKeepaliveStats(stats delivery.InterfaceKeepaliveStats) *management.LIInterfaceKeepaliveStats {
	return &management.LIInterfaceKeepaliveStats{
		Enabled:         stats.Enabled,
		IntervalMs:      stats.TimeP1.Milliseconds(),
		TimeoutMs:       stats.TimeP2.Milliseconds(),
		LastProbeUnixMs: deliveryUnixMillis(stats.LastSent),
		LastAckUnixMs:   deliveryUnixMillis(stats.LastValidACK),
		AckAgeMs:        stats.ACKAge.Milliseconds(),
		Sent:            stats.Sent,
		Acknowledged:    stats.Acknowledged,
		Timeouts:        stats.Timeouts,
		Disconnected:    stats.Disconnected,
		Reconnected:     stats.Reconnected,
		ReconnectReason: stats.ReconnectReason,
	}
}
