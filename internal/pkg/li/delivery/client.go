//go:build li

// Package delivery implements X2/X3 delivery to MDF endpoints per ETSI TS 103 221-2.
package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

const (
	DefaultQueueSize       = 10000
	DefaultWorkers         = 2 // Retained for configuration compatibility.
	DefaultBatchSize       = 100
	DefaultBatchTimeout    = 10 * time.Millisecond
	DefaultSendTimeout     = 5 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
	retryPollInterval      = 100 * time.Millisecond
)

var (
	ErrQueueFull           = errors.New("delivery queue full")
	ErrClientStopped       = errors.New("delivery client stopped")
	ErrNoDestinations      = errors.New("no destinations specified")
	ErrAllDeliveriesFailed = errors.New("all deliveries failed")
)

type PDUType uint8

const (
	PDUTypeX2 PDUType = 1
	PDUTypeX3 PDUType = 2
)

type deliveryItem struct {
	pduType PDUType
	xid     uuid.UUID
	data    []byte
	queued  time.Time
}

type streamKey struct {
	xid uuid.UUID
	did uuid.UUID
}

type ClientConfig struct {
	// QueueSize is the queue capacity for each destination.
	QueueSize int
	// Workers is retained for compatibility. Delivery is serialized per
	// destination to preserve order.
	Workers         int
	BatchSize       int
	BatchTimeout    time.Duration
	SendTimeout     time.Duration
	ShutdownTimeout time.Duration
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		QueueSize:       DefaultQueueSize,
		Workers:         DefaultWorkers,
		BatchSize:       DefaultBatchSize,
		BatchTimeout:    DefaultBatchTimeout,
		SendTimeout:     DefaultSendTimeout,
		ShutdownTimeout: DefaultShutdownTimeout,
	}
}

type ClientStats struct {
	X2Queued   uint64
	X2Sent     uint64
	X2Failed   uint64
	X2Dropped  uint64
	X3Queued   uint64
	X3Sent     uint64
	X3Failed   uint64
	X3Dropped  uint64
	Retries    uint64
	QueueDepth int64
}

type DestinationDeliveryStats struct {
	QueueDepth      int
	QueueCapacity   int
	X2Sent          uint64
	X3Sent          uint64
	Retries         uint64
	QueueOverflows  uint64
	TerminalDrops   uint64
	X2Dropped       uint64
	X3Dropped       uint64
	DroppedByReason map[string]uint64
	OldestQueuedAge time.Duration
	LastSuccess     time.Time
	LastError       string
}

type destinationQueue struct {
	did      uuid.UUID
	capacity int
	notify   chan struct{}
	stop     chan struct{}
	done     chan struct{}

	mu              sync.Mutex
	items           []*deliveryItem
	stopped         bool
	stats           DestinationDeliveryStats
	lastOverflowLog time.Time
}

func newDestinationQueue(did uuid.UUID, capacity int) *destinationQueue {
	return &destinationQueue{
		did:      did,
		capacity: capacity,
		notify:   make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		items:    make([]*deliveryItem, 0, capacity),
		stats: DestinationDeliveryStats{
			QueueCapacity:   capacity,
			DroppedByReason: make(map[string]uint64),
		},
	}
}

func (q *destinationQueue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// enqueue appends item and atomically evicts the oldest item when full.
func (q *destinationQueue) enqueue(item *deliveryItem) (dropped *deliveryItem, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped {
		return nil, false
	}
	if len(q.items) == q.capacity {
		dropped = q.items[0]
		copy(q.items, q.items[1:])
		q.items[len(q.items)-1] = item
		q.stats.QueueOverflows++
	} else {
		q.items = append(q.items, item)
	}
	q.stats.QueueDepth = len(q.items)
	q.signal()
	return dropped, true
}

func (q *destinationQueue) peekBatch(max int) []*deliveryItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	if max > len(q.items) {
		max = len(q.items)
	}
	batch := make([]*deliveryItem, max)
	copy(batch, q.items[:max])
	return batch
}

func (q *destinationQueue) pop(item *deliveryItem) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 || q.items[0] != item {
		return false
	}
	q.items[0] = nil
	q.items = q.items[1:]
	q.stats.QueueDepth = len(q.items)
	return true
}

func (q *destinationQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *destinationQueue) snapshot() DestinationDeliveryStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := q.stats
	stats.DroppedByReason = make(map[string]uint64, len(q.stats.DroppedByReason))
	for reason, count := range q.stats.DroppedByReason {
		stats.DroppedByReason[reason] = count
	}
	stats.QueueDepth = len(q.items)
	if len(q.items) > 0 {
		stats.OldestQueuedAge = time.Since(q.items[0].queued)
	}
	return stats
}

func (q *destinationQueue) stopAndDrain() []*deliveryItem {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		close(q.stop)
	}
	items := q.items
	q.items = nil
	q.stats.QueueDepth = 0
	q.mu.Unlock()
	q.signal()
	return items
}

type Client struct {
	manager *Manager
	config  ClientConfig

	queuesMu sync.RWMutex
	queues   map[uuid.UUID]*destinationQueue

	sequences   map[streamKey]*uint32
	sequencesMu sync.RWMutex
	stats       ClientStats

	started  atomic.Bool
	stopped  atomic.Bool
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewClient(manager *Manager, config ClientConfig) *Client {
	defaults := DefaultClientConfig()
	if config.QueueSize <= 0 {
		config.QueueSize = defaults.QueueSize
	}
	if config.Workers <= 0 {
		config.Workers = defaults.Workers
	}
	if config.BatchSize <= 0 {
		config.BatchSize = defaults.BatchSize
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = defaults.BatchTimeout
	}
	if config.SendTimeout <= 0 {
		config.SendTimeout = defaults.SendTimeout
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = defaults.ShutdownTimeout
	}
	return &Client{
		manager:   manager,
		config:    config,
		queues:    make(map[uuid.UUID]*destinationQueue),
		sequences: make(map[streamKey]*uint32),
	}
}

func (c *Client) Start() {
	if c.stopped.Load() || !c.started.CompareAndSwap(false, true) {
		return
	}
	c.queuesMu.RLock()
	for _, q := range c.queues {
		c.startDispatcher(q)
	}
	c.queuesMu.RUnlock()
	logger.Info("delivery client started",
		"queue_size_per_destination", c.config.QueueSize,
		"batch_size", c.config.BatchSize,
	)
}

func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		c.stopped.Store(true)
		deadline := time.Now().Add(c.config.ShutdownTimeout)
		for time.Now().Before(deadline) {
			if c.QueueDepth() == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		c.queuesMu.Lock()
		for did, q := range c.queues {
			remaining := q.stopAndDrain()
			for _, item := range remaining {
				c.recordTerminalDrop(did, q, item, "shutdown_timeout")
			}
		}
		c.queuesMu.Unlock()
		c.wg.Wait()
		logger.Info("delivery client stopped")
	})
}

func (c *Client) SendX2(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	return c.enqueue(PDUTypeX2, xid, destIDs, data)
}

func (c *Client) SendX3(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	return c.enqueue(PDUTypeX3, xid, destIDs, data)
}

func (c *Client) enqueue(pduType PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}

	// PDUs are immutable after enqueue. Copy once and share between destination
	// queue entries.
	immutableData := append([]byte(nil), data...)
	now := time.Now()
	for _, did := range append([]uuid.UUID(nil), destIDs...) {
		q := c.getOrCreateQueue(did)
		item := &deliveryItem{pduType: pduType, xid: xid, data: immutableData, queued: now}
		dropped, ok := q.enqueue(item)
		if !ok {
			return ErrClientStopped
		}
		atomic.AddInt64(&c.stats.QueueDepth, 1)
		if dropped != nil {
			atomic.AddInt64(&c.stats.QueueDepth, -1)
			c.recordTerminalDrop(did, q, dropped, "queue_overflow")
			c.logOverflow(did, q, dropped)
		}
	}
	if pduType == PDUTypeX2 {
		atomic.AddUint64(&c.stats.X2Queued, 1)
	} else {
		atomic.AddUint64(&c.stats.X3Queued, 1)
	}
	return nil
}

func (c *Client) getOrCreateQueue(did uuid.UUID) *destinationQueue {
	c.queuesMu.RLock()
	q := c.queues[did]
	c.queuesMu.RUnlock()
	if q != nil {
		return q
	}
	c.queuesMu.Lock()
	defer c.queuesMu.Unlock()
	if q = c.queues[did]; q != nil {
		return q
	}
	q = newDestinationQueue(did, c.config.QueueSize)
	c.queues[did] = q
	if c.started.Load() && !c.stopped.Load() {
		c.startDispatcher(q)
	}
	return q
}

func (c *Client) startDispatcher(q *destinationQueue) {
	c.wg.Add(1)
	go c.destinationDispatcher(q)
}

func (c *Client) destinationDispatcher(q *destinationQueue) {
	defer c.wg.Done()
	defer close(q.done)

	for {
		if q.depth() == 0 {
			select {
			case <-q.notify:
			case <-q.stop:
				return
			}
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), c.config.SendTimeout)
		conn, err := c.manager.GetConnection(ctx, q.did)
		cancel()
		if err != nil {
			if errors.Is(err, ErrDestinationNotFound) {
				c.dropDestinationQueue(q, "destination_removed")
				return
			}
			c.recordRetry(q, err)
			if !waitForRetry(q, retryPollInterval) {
				return
			}
			continue
		}

		batch := q.peekBatch(c.config.BatchSize)
		failed := false
		for _, item := range batch {
			if err := c.sendItem(conn, q.did, item); err != nil {
				c.manager.InvalidateConnection(q.did, conn)
				c.recordRetry(q, err)
				failed = true
				break
			}
			if q.pop(item) {
				atomic.AddInt64(&c.stats.QueueDepth, -1)
				c.recordSuccess(q, item)
			}
		}
		if !failed {
			c.manager.ReleaseConnection(q.did, conn)
		}
	}
}

func waitForRetry(q *destinationQueue, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-q.notify:
		return true
	case <-q.stop:
		return false
	}
}

func (c *Client) sendItem(conn *tls.Conn, did uuid.UUID, item *deliveryItem) error {
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.SendTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}
	n, err := conn.Write(item.data)
	if err != nil {
		c.manager.RecordWriteError(did)
		return fmt.Errorf("write failed: %w", err)
	}
	if n != len(item.data) {
		c.manager.RecordWriteError(did)
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(item.data))
	}
	c.manager.RecordBytesSent(did, uint64(n))
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear write deadline: %w", err)
	}
	return nil
}

func (c *Client) recordSuccess(q *destinationQueue, item *deliveryItem) {
	if item.pduType == PDUTypeX2 {
		atomic.AddUint64(&c.stats.X2Sent, 1)
	} else {
		atomic.AddUint64(&c.stats.X3Sent, 1)
	}
	q.mu.Lock()
	if item.pduType == PDUTypeX2 {
		q.stats.X2Sent++
	} else {
		q.stats.X3Sent++
	}
	q.stats.LastSuccess = time.Now()
	q.stats.LastError = ""
	q.mu.Unlock()
}

func (c *Client) recordRetry(q *destinationQueue, err error) {
	atomic.AddUint64(&c.stats.Retries, 1)
	q.mu.Lock()
	q.stats.Retries++
	q.stats.LastError = err.Error()
	q.mu.Unlock()
}

func (c *Client) recordTerminalDrop(_ uuid.UUID, q *destinationQueue, item *deliveryItem, reason string) {
	if item.pduType == PDUTypeX2 {
		atomic.AddUint64(&c.stats.X2Dropped, 1)
		atomic.AddUint64(&c.stats.X2Failed, 1)
	} else {
		atomic.AddUint64(&c.stats.X3Dropped, 1)
		atomic.AddUint64(&c.stats.X3Failed, 1)
	}
	q.mu.Lock()
	q.stats.TerminalDrops++
	if item.pduType == PDUTypeX2 {
		q.stats.X2Dropped++
	} else {
		q.stats.X3Dropped++
	}
	q.stats.DroppedByReason[reason]++
	q.mu.Unlock()
}

func (c *Client) logOverflow(did uuid.UUID, q *destinationQueue, item *deliveryItem) {
	q.mu.Lock()
	if time.Since(q.lastOverflowLog) < time.Second {
		q.mu.Unlock()
		return
	}
	q.lastOverflowLog = time.Now()
	depth := len(q.items)
	drops := q.stats.QueueOverflows
	q.mu.Unlock()
	logger.Warn("LI delivery queue overflow, dropped oldest item",
		"did", did, "xid", item.xid, "pdu_type", item.pduType,
		"reason", "queue_overflow", "queue_depth", depth,
		"queue_capacity", q.capacity, "dropped_total", drops,
	)
}

func (c *Client) dropDestinationQueue(q *destinationQueue, reason string) {
	items := q.stopAndDrain()
	atomic.AddInt64(&c.stats.QueueDepth, -int64(len(items)))
	for _, item := range items {
		c.recordTerminalDrop(q.did, q, item, reason)
	}
	if len(items) > 0 {
		logger.Warn("LI delivery items dropped",
			"did", q.did, "reason", reason, "items", len(items),
		)
	}
}

// RemoveDestination stops and removes delivery state for a deleted destination.
func (c *Client) RemoveDestination(did uuid.UUID) {
	c.queuesMu.Lock()
	q := c.queues[did]
	delete(c.queues, did)
	c.queuesMu.Unlock()
	if q != nil {
		c.dropDestinationQueue(q, "destination_removed")
	}
}

func (c *Client) Stats() ClientStats {
	return ClientStats{
		X2Queued:   atomic.LoadUint64(&c.stats.X2Queued),
		X2Sent:     atomic.LoadUint64(&c.stats.X2Sent),
		X2Failed:   atomic.LoadUint64(&c.stats.X2Failed),
		X2Dropped:  atomic.LoadUint64(&c.stats.X2Dropped),
		X3Queued:   atomic.LoadUint64(&c.stats.X3Queued),
		X3Sent:     atomic.LoadUint64(&c.stats.X3Sent),
		X3Failed:   atomic.LoadUint64(&c.stats.X3Failed),
		X3Dropped:  atomic.LoadUint64(&c.stats.X3Dropped),
		Retries:    atomic.LoadUint64(&c.stats.Retries),
		QueueDepth: atomic.LoadInt64(&c.stats.QueueDepth),
	}
}

func (c *Client) DestinationStats() map[uuid.UUID]DestinationDeliveryStats {
	c.queuesMu.RLock()
	defer c.queuesMu.RUnlock()
	result := make(map[uuid.UUID]DestinationDeliveryStats, len(c.queues))
	for did, q := range c.queues {
		result[did] = q.snapshot()
	}
	return result
}

func (c *Client) QueueDepth() int {
	return int(atomic.LoadInt64(&c.stats.QueueDepth))
}

func (c *Client) NextSequence(xid, did uuid.UUID) uint32 {
	key := streamKey{xid: xid, did: did}
	c.sequencesMu.RLock()
	seq, exists := c.sequences[key]
	c.sequencesMu.RUnlock()
	if exists {
		return atomic.AddUint32(seq, 1)
	}
	c.sequencesMu.Lock()
	if seq, exists = c.sequences[key]; exists {
		c.sequencesMu.Unlock()
		return atomic.AddUint32(seq, 1)
	}
	var initial uint32 = 1
	c.sequences[key] = &initial
	c.sequencesMu.Unlock()
	return 1
}

func (c *Client) ResetSequence(xid uuid.UUID) {
	c.sequencesMu.Lock()
	defer c.sequencesMu.Unlock()
	for key := range c.sequences {
		if key.xid == xid {
			delete(c.sequences, key)
		}
	}
}

func (c *Client) SendX2Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}
	return c.sendSync(ctx, PDUTypeX2, xid, destIDs, data)
}

func (c *Client) SendX3Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}
	return c.sendSync(ctx, PDUTypeX3, xid, destIDs, data)
}

func (c *Client) sendSync(ctx context.Context, pduType PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	successCount := 0
	for _, did := range destIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := c.manager.GetConnection(ctx, did)
		if err != nil {
			continue
		}
		item := &deliveryItem{pduType: pduType, xid: xid, data: data, queued: time.Now()}
		if err := c.sendItem(conn, did, item); err != nil {
			c.manager.InvalidateConnection(did, conn)
			continue
		}
		c.manager.ReleaseConnection(did, conn)
		if pduType == PDUTypeX2 {
			atomic.AddUint64(&c.stats.X2Sent, 1)
		} else {
			atomic.AddUint64(&c.stats.X3Sent, 1)
		}
		successCount++
	}
	if successCount == 0 {
		return ErrAllDeliveriesFailed
	}
	return nil
}
