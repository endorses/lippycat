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
		X2EnqueueCalls: stats.X2Queued,
		X3EnqueueCalls: stats.X3Queued,
		X2Written:      stats.X2Sent,
		X3Written:      stats.X3Sent,
		X2Dropped:      stats.X2Dropped,
		X3Dropped:      stats.X3Dropped,
		Retries:        stats.Retries,
		QueueDepth:     stats.QueueDepth,
		Destinations:   make(map[string]*management.LIDestinationDeliveryStats),
	}
	for did, queue := range liDeliveryClient.DestinationStats() {
		dst.LiDelivery.Destinations[did.String()] = &management.LIDestinationDeliveryStats{
			QueueDepth:        uint64(queue.QueueDepth),
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
