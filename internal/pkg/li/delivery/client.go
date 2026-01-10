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

// Default client configuration values.
const (
	// DefaultQueueSize is the default size of the delivery queue per destination.
	DefaultQueueSize = 10000

	// DefaultWorkers is the default number of workers per destination.
	DefaultWorkers = 2

	// DefaultBatchSize is the default number of PDUs to send per batch.
	DefaultBatchSize = 100

	// DefaultBatchTimeout is the default timeout for batch accumulation.
	DefaultBatchTimeout = 10 * time.Millisecond

	// DefaultSendTimeout is the default timeout for sending a PDU.
	DefaultSendTimeout = 5 * time.Second
)

// Errors returned by the delivery client.
var (
	// ErrQueueFull indicates the delivery queue is full (backpressure).
	ErrQueueFull = errors.New("delivery queue full")

	// ErrClientStopped indicates the client has been stopped.
	ErrClientStopped = errors.New("delivery client stopped")

	// ErrNoDestinations indicates no destination IDs were provided.
	ErrNoDestinations = errors.New("no destinations specified")

	// ErrAllDeliveriesFailed indicates delivery to all destinations failed.
	ErrAllDeliveriesFailed = errors.New("all deliveries failed")
)

// PDUType identifies the type of PDU for delivery.
type PDUType uint8

const (
	// PDUTypeX2 indicates an X2 (IRI) PDU.
	PDUTypeX2 PDUType = 1
	// PDUTypeX3 indicates an X3 (CC) PDU.
	PDUTypeX3 PDUType = 2
)

// deliveryItem represents a PDU queued for delivery.
type deliveryItem struct {
	pduType PDUType
	xid     uuid.UUID
	data    []byte
	destIDs []uuid.UUID
}

// streamKey uniquely identifies a delivery stream for sequence numbering.
// Sequence numbers are maintained per XID+destination pair.
type streamKey struct {
	xid uuid.UUID
	did uuid.UUID
}

// ClientConfig holds configuration for the delivery client.
type ClientConfig struct {
	// QueueSize is the size of the delivery queue per destination.
	QueueSize int

	// Workers is the number of delivery workers per destination.
	Workers int

	// BatchSize is the maximum number of PDUs to send per batch.
	BatchSize int

	// BatchTimeout is the timeout for batch accumulation.
	BatchTimeout time.Duration

	// SendTimeout is the timeout for sending a PDU.
	SendTimeout time.Duration
}

// DefaultClientConfig returns a ClientConfig with default values.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		QueueSize:    DefaultQueueSize,
		Workers:      DefaultWorkers,
		BatchSize:    DefaultBatchSize,
		BatchTimeout: DefaultBatchTimeout,
		SendTimeout:  DefaultSendTimeout,
	}
}

// ClientStats contains delivery client statistics.
type ClientStats struct {
	// X2Queued is the number of X2 PDUs queued.
	X2Queued uint64
	// X2Sent is the number of X2 PDUs successfully sent.
	X2Sent uint64
	// X2Failed is the number of X2 PDUs that failed to send.
	X2Failed uint64
	// X2Dropped is the number of X2 PDUs dropped due to queue full.
	X2Dropped uint64

	// X3Queued is the number of X3 PDUs queued.
	X3Queued uint64
	// X3Sent is the number of X3 PDUs successfully sent.
	X3Sent uint64
	// X3Failed is the number of X3 PDUs that failed to send.
	X3Failed uint64
	// X3Dropped is the number of X3 PDUs dropped due to queue full.
	X3Dropped uint64

	// QueueDepth is the current queue depth.
	QueueDepth int64
}

// Client handles X2/X3 PDU delivery to MDF endpoints.
//
// The client provides:
//   - Asynchronous delivery with backpressure via bounded queue
//   - Sequence numbering per XID+destination stream
//   - Connection management via the destination Manager
//   - Batch sending for efficiency
//   - Automatic retry on transient errors
type Client struct {
	manager *Manager
	config  ClientConfig

	// queue is the delivery queue for PDUs.
	queue chan *deliveryItem

	// sequences tracks sequence numbers per stream.
	sequences   map[streamKey]*uint32
	sequencesMu sync.RWMutex

	// stats holds delivery statistics.
	stats ClientStats

	// stopChan signals shutdown.
	stopChan chan struct{}

	// wg tracks worker goroutines.
	wg sync.WaitGroup

	// stopped indicates the client has been stopped.
	stopped atomic.Bool
}

// NewClient creates a new delivery client.
func NewClient(manager *Manager, config ClientConfig) *Client {
	if config.QueueSize <= 0 {
		config.QueueSize = DefaultQueueSize
	}
	if config.Workers <= 0 {
		config.Workers = DefaultWorkers
	}
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultBatchSize
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = DefaultBatchTimeout
	}
	if config.SendTimeout <= 0 {
		config.SendTimeout = DefaultSendTimeout
	}

	return &Client{
		manager:   manager,
		config:    config,
		queue:     make(chan *deliveryItem, config.QueueSize),
		sequences: make(map[streamKey]*uint32),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the delivery workers.
func (c *Client) Start() {
	for i := 0; i < c.config.Workers; i++ {
		c.wg.Add(1)
		go c.deliveryWorker(i)
	}
	logger.Info("delivery client started",
		"workers", c.config.Workers,
		"queue_size", c.config.QueueSize,
	)
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	c.stopped.Store(true)
	close(c.stopChan)
	c.wg.Wait()
	logger.Info("delivery client stopped")
}

// SendX2 queues an X2 (IRI) PDU for delivery to the specified destinations.
//
// The data parameter should be the encoded PDU including header.
// The PDU will be delivered to all specified destination IDs.
//
// Returns ErrQueueFull if the queue is full (backpressure).
// Returns ErrClientStopped if the client has been stopped.
// Returns ErrNoDestinations if no destination IDs are provided.
func (c *Client) SendX2(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}

	item := &deliveryItem{
		pduType: PDUTypeX2,
		xid:     xid,
		data:    data,
		destIDs: destIDs,
	}

	select {
	case c.queue <- item:
		atomic.AddUint64(&c.stats.X2Queued, 1)
		atomic.AddInt64(&c.stats.QueueDepth, 1)
		return nil
	default:
		atomic.AddUint64(&c.stats.X2Dropped, 1)
		return ErrQueueFull
	}
}

// SendX3 queues an X3 (CC) PDU for delivery to the specified destinations.
//
// The data parameter should be the encoded PDU including header.
// The PDU will be delivered to all specified destination IDs.
//
// Returns ErrQueueFull if the queue is full (backpressure).
// Returns ErrClientStopped if the client has been stopped.
// Returns ErrNoDestinations if no destination IDs are provided.
func (c *Client) SendX3(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}

	item := &deliveryItem{
		pduType: PDUTypeX3,
		xid:     xid,
		data:    data,
		destIDs: destIDs,
	}

	select {
	case c.queue <- item:
		atomic.AddUint64(&c.stats.X3Queued, 1)
		atomic.AddInt64(&c.stats.QueueDepth, 1)
		return nil
	default:
		atomic.AddUint64(&c.stats.X3Dropped, 1)
		return ErrQueueFull
	}
}

// Stats returns current delivery statistics.
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
		QueueDepth: atomic.LoadInt64(&c.stats.QueueDepth),
	}
}

// QueueDepth returns the current queue depth.
func (c *Client) QueueDepth() int {
	return int(atomic.LoadInt64(&c.stats.QueueDepth))
}

// NextSequence returns and increments the sequence number for the given stream.
func (c *Client) NextSequence(xid, did uuid.UUID) uint32 {
	key := streamKey{xid: xid, did: did}

	c.sequencesMu.RLock()
	seq, exists := c.sequences[key]
	c.sequencesMu.RUnlock()

	if exists {
		return atomic.AddUint32(seq, 1)
	}

	// Need to create new sequence counter.
	c.sequencesMu.Lock()
	// Double-check after acquiring write lock.
	if seq, exists = c.sequences[key]; exists {
		c.sequencesMu.Unlock()
		return atomic.AddUint32(seq, 1)
	}

	var initial uint32 = 1
	c.sequences[key] = &initial
	c.sequencesMu.Unlock()
	return 1
}

// ResetSequence resets the sequence number for the given stream.
// Called when a task is deactivated.
func (c *Client) ResetSequence(xid uuid.UUID) {
	c.sequencesMu.Lock()
	defer c.sequencesMu.Unlock()

	// Remove all sequences for this XID.
	for key := range c.sequences {
		if key.xid == xid {
			delete(c.sequences, key)
		}
	}
}

// deliveryWorker processes items from the queue and delivers them.
func (c *Client) deliveryWorker(workerID int) {
	defer c.wg.Done()

	batch := make([]*deliveryItem, 0, c.config.BatchSize)
	timer := time.NewTimer(c.config.BatchTimeout)
	timer.Stop()

	for {
		select {
		case <-c.stopChan:
			// Drain and deliver remaining items.
			c.drainQueue(batch)
			return

		case item := <-c.queue:
			atomic.AddInt64(&c.stats.QueueDepth, -1)
			batch = append(batch, item)

			if len(batch) >= c.config.BatchSize {
				c.deliverBatch(batch)
				batch = batch[:0]
				timer.Stop()
			} else if len(batch) == 1 {
				timer.Reset(c.config.BatchTimeout)
			}

		case <-timer.C:
			if len(batch) > 0 {
				c.deliverBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// drainQueue processes remaining items in the queue.
func (c *Client) drainQueue(batch []*deliveryItem) {
	for {
		select {
		case item := <-c.queue:
			atomic.AddInt64(&c.stats.QueueDepth, -1)
			batch = append(batch, item)
			if len(batch) >= c.config.BatchSize {
				c.deliverBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				c.deliverBatch(batch)
			}
			return
		}
	}
}

// deliverBatch sends a batch of PDUs to their destinations.
func (c *Client) deliverBatch(batch []*deliveryItem) {
	// Group items by destination for efficient delivery.
	byDest := make(map[uuid.UUID][]*deliveryItem)
	for _, item := range batch {
		for _, did := range item.destIDs {
			byDest[did] = append(byDest[did], item)
		}
	}

	// Deliver to each destination.
	for did, items := range byDest {
		c.deliverToDestination(did, items)
	}
}

// deliverToDestination sends items to a single destination.
func (c *Client) deliverToDestination(did uuid.UUID, items []*deliveryItem) {
	// Use a timeout context for connection establishment in async delivery.
	ctx, cancel := context.WithTimeout(context.Background(), c.config.SendTimeout)
	defer cancel()

	conn, err := c.manager.GetConnection(ctx, did)
	if err != nil {
		// Log warning and record failures.
		logger.Warn("failed to get connection for delivery",
			"did", did,
			"error", err,
			"items", len(items),
		)
		c.recordFailures(items)
		return
	}

	var lastErr error
	successCount := 0

	for _, item := range items {
		if err := c.sendItem(conn, did, item); err != nil {
			lastErr = err
			c.recordFailure(item)
		} else {
			successCount++
			c.recordSuccess(item)
		}
	}

	// Return connection to pool or invalidate on error.
	if lastErr != nil {
		c.manager.InvalidateConnection(did, conn)
	} else {
		c.manager.ReleaseConnection(did, conn)
	}
}

// sendItem sends a single item to the connection.
func (c *Client) sendItem(conn *tls.Conn, did uuid.UUID, item *deliveryItem) error {
	// Set write deadline.
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.SendTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Write the PDU data.
	n, err := conn.Write(item.data)
	if err != nil {
		c.manager.RecordWriteError(did)
		return fmt.Errorf("write failed: %w", err)
	}

	c.manager.RecordBytesSent(did, uint64(n))

	// Clear deadline.
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear write deadline: %w", err)
	}

	return nil
}

// recordSuccess records a successful delivery.
func (c *Client) recordSuccess(item *deliveryItem) {
	switch item.pduType {
	case PDUTypeX2:
		atomic.AddUint64(&c.stats.X2Sent, 1)
	case PDUTypeX3:
		atomic.AddUint64(&c.stats.X3Sent, 1)
	}
}

// recordFailure records a failed delivery.
func (c *Client) recordFailure(item *deliveryItem) {
	switch item.pduType {
	case PDUTypeX2:
		atomic.AddUint64(&c.stats.X2Failed, 1)
	case PDUTypeX3:
		atomic.AddUint64(&c.stats.X3Failed, 1)
	}
}

// recordFailures records multiple failed deliveries.
func (c *Client) recordFailures(items []*deliveryItem) {
	for _, item := range items {
		c.recordFailure(item)
	}
}

// SendX2Sync sends an X2 PDU synchronously to all destinations.
// This is useful for high-priority IRI events that need immediate delivery.
//
// Returns nil if delivery succeeded to at least one destination.
// Returns ErrAllDeliveriesFailed if delivery failed to all destinations.
func (c *Client) SendX2Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}

	return c.sendSync(ctx, PDUTypeX2, xid, destIDs, data)
}

// SendX3Sync sends an X3 PDU synchronously to all destinations.
// Use sparingly as synchronous delivery may impact performance.
//
// Returns nil if delivery succeeded to at least one destination.
// Returns ErrAllDeliveriesFailed if delivery failed to all destinations.
func (c *Client) SendX3Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}

	return c.sendSync(ctx, PDUTypeX3, xid, destIDs, data)
}

// sendSync sends a PDU synchronously to all destinations.
func (c *Client) sendSync(ctx context.Context, pduType PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	var (
		successCount int
		lastErr      error
	)

	for _, did := range destIDs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := c.manager.GetConnection(ctx, did)
		if err != nil {
			lastErr = err
			continue
		}

		item := &deliveryItem{
			pduType: pduType,
			xid:     xid,
			data:    data,
			destIDs: []uuid.UUID{did},
		}

		if err := c.sendItem(conn, did, item); err != nil {
			c.manager.InvalidateConnection(did, conn)
			lastErr = err
			c.recordFailure(item)
			continue
		}

		c.manager.ReleaseConnection(did, conn)
		c.recordSuccess(item)
		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("%w: %v", ErrAllDeliveriesFailed, lastErr)
	}

	return nil
}
