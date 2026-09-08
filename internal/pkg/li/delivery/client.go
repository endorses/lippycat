//go:build li

// Package delivery implements X2/X3 delivery to MDF endpoints per ETSI TS 103 221-2.
package delivery

import (
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

const (
	DefaultQueueSize           = 10000
	DefaultWorkers             = 2 // Retained for configuration compatibility.
	DefaultBatchSize           = 100
	DefaultBatchTimeout        = 10 * time.Millisecond
	DefaultSendTimeout         = 5 * time.Second
	DefaultShutdownTimeout     = 10 * time.Second
	DefaultRetryInitialBackoff = 100 * time.Millisecond
	DefaultRetryMaxBackoff     = 30 * time.Second
	DefaultRetryJitter         = 0.20
)

var (
	ErrQueueFull           = errors.New("delivery queue full")
	ErrExpired             = errors.New("delivery deadline expired")
	ErrClientStopped       = errors.New("delivery client stopped")
	ErrNoDestinations      = errors.New("no destinations specified")
	ErrAllDeliveriesFailed = errors.New("all deliveries failed")
)

type PDUType uint8

const (
	PDUTypeX2 PDUType = 1
	PDUTypeX3 PDUType = 2
)

type DeliveryMetadata = li.DeliveryMetadata

type deliveryItem struct {
	element     *list.Element
	expiryIndex int
	payload     *sharedPayload
	canceled    atomic.Bool
	persisted   atomic.Bool
	journalID   atomic.Uint64
	metadata    DeliveryMetadata
	claimed     bool
	terminal    atomic.Bool
	uncertain   atomic.Bool // any attempt may already have reached the transport
	completion  chan error
	cancel      context.CancelFunc
	conn        *tls.Conn
	pduType     PDUType
	xid         uuid.UUID
	data        []byte
	queued      time.Time
}

type ClientConfig struct {
	X2SpoolDir            string
	X2SpoolKeyFile        string
	X2SpoolMaxBytes       int64
	X2SpoolReplayPolicy   string
	X2SpoolReplayManifest string
	X2SpoolExportManifest string
	// QueueSize is the PDU capacity per destination and interface.
	X2QueueBytes      int64
	X3QueueBytes      int64
	X3MaxAge          time.Duration
	MemoryBudgetBytes int64
	QueueSize         int
	X2QueueSize       int
	X3QueueSize       int
	// Workers is retained for compatibility. Delivery is serialized per
	// destination to preserve order.
	Workers               int
	BatchSize             int
	BatchTimeout          time.Duration
	SendTimeout           time.Duration
	ShutdownTimeout       time.Duration
	RetryInitialBackoff   time.Duration
	RetryMaxBackoff       time.Duration
	RetryJitter           float64
	RetrySuccessThreshold int
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		QueueSize:             DefaultQueueSize,
		Workers:               DefaultWorkers,
		BatchSize:             DefaultBatchSize,
		BatchTimeout:          DefaultBatchTimeout,
		SendTimeout:           DefaultSendTimeout,
		ShutdownTimeout:       DefaultShutdownTimeout,
		RetryInitialBackoff:   DefaultRetryInitialBackoff,
		RetryMaxBackoff:       DefaultRetryMaxBackoff,
		RetryJitter:           DefaultRetryJitter,
		RetrySuccessThreshold: 1,
	}
}

type ClientStats struct {
	PhysicalQueueBytes   int64
	UncertainWrites      uint64
	UncertainBytes       uint64
	DroppedByReason      map[string]uint64
	DroppedBytesByReason map[string]uint64
	FirstDroppedAt       time.Time
	FirstDroppedUnixNano int64
	X2Queued             uint64
	X2Sent               uint64
	X2Failed             uint64
	X2Dropped            uint64
	X3Queued             uint64
	X3Sent               uint64
	X3Failed             uint64
	X3Dropped            uint64
	Retries              uint64
	QueueDepth           int64
	QueueBytes           int64
	DroppedBytes         uint64
}

type DestinationDeliveryStats struct {
	UncertainWrites      uint64
	UncertainBytes       uint64
	FirstDroppedAt       time.Time
	FirstDroppedByReason map[string]time.Time
	X2QueueBytes         int64
	X3QueueBytes         int64
	X2InFlightBytes      int64
	X3InFlightBytes      int64
	X2QueueByteCapacity  int64
	X3QueueByteCapacity  int64
	DroppedBytes         uint64
	DroppedBytesByReason map[string]uint64
	X3Expired            uint64
	QueueDepth           int
	QueueCapacity        int
	X2QueueDepth         int
	X2QueueCapacity      int
	X3QueueDepth         int
	X3QueueCapacity      int
	X2Sent               uint64
	X3Sent               uint64
	Retries              uint64
	QueueOverflows       uint64
	X2Overflows          uint64
	X3Overflows          uint64
	TerminalDrops        uint64
	X2Dropped            uint64
	X3Dropped            uint64
	DroppedByReason      map[string]uint64
	OldestQueuedAge      time.Duration
	X2OldestAge          time.Duration
	X3OldestAge          time.Duration
	LastSuccess          time.Time
	LastError            string
}

type destinationQueue struct {
	expiry          expiryHeap
	nextExpiry      time.Time
	capacities      [2]int
	workers         sync.WaitGroup
	expiryNotify    chan struct{}
	preserveX2      bool
	did             uuid.UUID
	capacity        int
	notify          chan struct{}
	notifyX3        chan struct{}
	stop            chan struct{}
	done            chan struct{}
	mu              sync.Mutex
	items           [2]list.List
	bytes           [2]int64
	limits          [2]int64
	stopped         bool
	stopReason      string
	stats           DestinationDeliveryStats
	lastOverflowLog time.Time
}

func queueIndex(t PDUType) int {
	if t == PDUTypeX2 {
		return 0
	}
	return 1
}
func newDestinationQueue(did uuid.UUID, capacity int) *destinationQueue {
	return &destinationQueue{capacities: [2]int{capacity, capacity}, expiryNotify: make(chan struct{}, 1), did: did, capacity: capacity, notify: make(chan struct{}, 1), notifyX3: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), stats: DestinationDeliveryStats{QueueCapacity: capacity, DroppedByReason: make(map[string]uint64), DroppedBytesByReason: make(map[string]uint64), FirstDroppedByReason: make(map[string]time.Time)}}
}
func (q *destinationQueue) signal() {
	for _, ch := range []chan struct{}{q.notify, q.notifyX3, q.expiryNotify} {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (q *destinationQueue) enqueue(item *deliveryItem) (*deliveryItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped {
		return nil, false
	}
	i := queueIndex(item.pduType)
	l := &q.items[i]
	size := int64(len(item.data))
	if q.limits[i] > 0 && size > q.limits[i] {
		return item, false
	}
	var dropped *deliveryItem
	if l.Len() >= q.capacities[i] || (q.limits[i] > 0 && q.bytes[i]+size > q.limits[i]) {
		// A claimed head remains charged until its owner resolves it. Reject new
		// arrivals if one eviction cannot satisfy the budget.
		if i == 0 && q.preserveX2 {
			return item, false
		}
		head := l.Front()
		if head == nil || head.Value.(*deliveryItem).claimed {
			return item, false
		}
		candidate := head.Value.(*deliveryItem)
		if q.limits[i] > 0 && q.bytes[i]-int64(len(candidate.data))+size > q.limits[i] {
			return item, false
		}
		dropped = candidate
		q.removeExpiryLocked(candidate)
		candidate.element = nil
		l.Remove(head)
		q.bytes[i] -= int64(len(candidate.data))
		q.stats.QueueOverflows++
		if i == 0 {
			q.stats.X2Overflows++
		} else {
			q.stats.X3Overflows++
		}
	}
	item.expiryIndex = -1
	item.element = l.PushBack(item)
	q.observeDeadlineLocked(item)
	q.bytes[i] += size
	q.updateDepthLocked()
	q.signal()
	return dropped, true
}

// peekBatch is retained for diagnostic/tests; dispatch claims a single owned head.
func (q *destinationQueue) peekBatch(max int) []*deliveryItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*deliveryItem
	for i := range q.items {
		for e := q.items[i].Front(); e != nil && len(out) < max; e = e.Next() {
			out = append(out, e.Value.(*deliveryItem))
		}
	}
	return out
}
func (q *destinationQueue) claim(t PDUType) *deliveryItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopped {
		return nil
	}
	e := q.items[queueIndex(t)].Front()
	if e == nil {
		return nil
	}
	item := e.Value.(*deliveryItem)
	item.claimed = true
	return item
}
func (q *destinationQueue) pop(item *deliveryItem) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := queueIndex(item.pduType)
	e := q.items[i].Front()
	if e == nil || e.Value != item {
		return false
	}
	q.items[i].Remove(e)
	q.removeExpiryLocked(item)
	item.element = nil
	q.bytes[i] -= int64(len(item.data))
	q.updateDepthLocked()
	return true
}
func (q *destinationQueue) updateDepthLocked() {
	q.stats.X2QueueDepth = q.items[0].Len()
	q.stats.X3QueueDepth = q.items[1].Len()
	q.stats.QueueDepth = q.stats.X2QueueDepth + q.stats.X3QueueDepth
	q.stats.X2QueueCapacity = q.capacities[0]
	q.stats.X3QueueCapacity = q.capacities[1]
	q.stats.X2QueueBytes = q.bytes[0]
	q.stats.X3QueueBytes = q.bytes[1]
	q.stats.X2QueueByteCapacity = q.limits[0]
	q.stats.X3QueueByteCapacity = q.limits[1]
}
func (q *destinationQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.items[0].Len() + q.items[1].Len()
}
func (q *destinationQueue) snapshot() DestinationDeliveryStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.updateDepthLocked()
	s := q.stats
	s.FirstDroppedByReason = make(map[string]time.Time)
	for k, v := range q.stats.FirstDroppedByReason {
		s.FirstDroppedByReason[k] = v
	}
	s.DroppedByReason = make(map[string]uint64)
	for k, v := range q.stats.DroppedByReason {
		s.DroppedByReason[k] = v
	}
	s.DroppedBytesByReason = make(map[string]uint64)
	for k, v := range q.stats.DroppedBytesByReason {
		s.DroppedBytesByReason[k] = v
	}
	for i := range q.items {
		if e := q.items[i].Front(); e != nil {
			item := e.Value.(*deliveryItem)
			age := time.Since(item.queued)
			s.OldestQueuedAge = max(s.OldestQueuedAge, age)
			if i == 0 {
				s.X2OldestAge = age
				if item.claimed {
					s.X2InFlightBytes = int64(len(item.data))
				}
			} else {
				s.X3OldestAge = age
				if item.claimed {
					s.X3InFlightBytes = int64(len(item.data))
				}
			}
		}
	}
	return s
}
func (q *destinationQueue) stopAndDrain(reason string) []*deliveryItem {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		close(q.stop)
	}
	if q.stopReason == "" {
		q.stopReason = reason
	}
	var out []*deliveryItem
	var cancels []context.CancelFunc
	for i := range q.items {
		for e := q.items[i].Front(); e != nil; {
			next := e.Next()
			item := e.Value.(*deliveryItem)
			if item.cancel != nil {
				cancels = append(cancels, item.cancel)
			}
			if !item.claimed && !(q.preserveX2 && item.pduType == PDUTypeX2 && !item.persisted.Load()) {
				q.removeExpiryLocked(item)
				q.items[i].Remove(e)
				q.bytes[i] -= int64(len(item.data))
				item.element = nil
				out = append(out, item)
			}
			e = next
		}
	}
	q.updateDepthLocked()
	q.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	q.signal()
	return out
}

type Client struct {
	admissionMu  sync.Mutex
	outcomesMu   sync.Mutex
	outcomes     map[string]uint64
	outcomeBytes map[string]uint64
	journal      *Journal
	initErr      error
	manager      *Manager
	config       ClientConfig

	queuesMu sync.RWMutex
	queues   map[uuid.UUID]*destinationQueue

	stats ClientStats

	started  atomic.Bool
	stopped  atomic.Bool
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewClient(manager *Manager, config ClientConfig) *Client {
	defaults := DefaultClientConfig()
	if config.QueueSize == 0 {
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
	if config.RetryInitialBackoff <= 0 {
		config.RetryInitialBackoff = defaults.RetryInitialBackoff
	}
	if config.RetryMaxBackoff <= 0 {
		config.RetryMaxBackoff = defaults.RetryMaxBackoff
	}
	if config.RetryMaxBackoff < config.RetryInitialBackoff {
		config.RetryMaxBackoff = config.RetryInitialBackoff
	}
	if config.RetryJitter <= 0 || config.RetryJitter > 1 {
		config.RetryJitter = defaults.RetryJitter
	}
	if config.RetrySuccessThreshold <= 0 {
		config.RetrySuccessThreshold = defaults.RetrySuccessThreshold
	}
	c := &Client{outcomes: make(map[string]uint64), outcomeBytes: make(map[string]uint64),
		manager: manager,
		config:  config,
		queues:  make(map[uuid.UUID]*destinationQueue),
	}
	c.initErr = config.Validate()
	if c.initErr == nil {
		c.initJournal()
	}
	return c
}
func (c *Client) Err() error { return c.initErr }

func (c *Client) Start() {
	c.queuesMu.Lock()
	defer c.queuesMu.Unlock()
	if c.initErr != nil || c.stopped.Load() || !c.started.CompareAndSwap(false, true) {
		return
	}
	for _, q := range c.queues {
		c.startDispatcher(q)
	}
	logger.Info("delivery client started",
		"queue_size_per_destination", c.config.QueueSize,
		"batch_size", c.config.BatchSize,
	)
}

func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		c.admissionMu.Lock()
		c.stopped.Store(true)
		c.admissionMu.Unlock()
		deadline := time.Now().Add(c.config.ShutdownTimeout)
		for c.started.Load() && c.QueueDepth() > 0 && time.Now().Before(deadline) {
			time.Sleep(min(5*time.Millisecond, max(time.Until(deadline), 0)))
		}
		if c.journal != nil {
			if err := c.journal.Flush(); err != nil {
				logger.Error("flush X2 journal", "error", err)
			}
		}
		c.queuesMu.Lock()
		queues := make([]*destinationQueue, 0, len(c.queues))
		for _, q := range c.queues {
			queues = append(queues, q)
		}
		c.queuesMu.Unlock()
		for _, q := range queues {
			c.dropDestinationQueue(q, "shutdown_timeout")
		}
		c.wg.Wait()
		if c.journal != nil {
			if err := c.journal.Close(); err != nil {
				logger.Error("close X2 journal", "error", err)
			}
		}
		logger.Info("delivery client stopped")
	})
}
func (c *Client) SendX2(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	return c.enqueue(PDUTypeX2, xid, destIDs, data)
}
func (c *Client) SendX3(xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	return c.enqueue(PDUTypeX3, xid, destIDs, data)
}
func (c *Client) SendX2WithMetadata(xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata) error {
	_, err := c.enqueueWithMetadata(PDUTypeX2, xid, destIDs, data, metadata, false)
	return err
}
func (c *Client) SendX3WithMetadata(xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata) error {
	_, err := c.enqueueWithMetadata(PDUTypeX3, xid, destIDs, data, metadata, false)
	return err
}
func (c *Client) enqueue(t PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	_, err := c.enqueueWithMetadata(t, xid, destIDs, data, DeliveryMetadata{}, false)
	return err
}
func (c *Client) enqueueWithMetadata(t PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata, synchronous bool) ([]chan error, error) {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.initErr != nil {
		return nil, c.initErr
	}
	if c.stopped.Load() {
		return nil, ErrClientStopped
	}
	if len(destIDs) == 0 {
		return nil, ErrNoDestinations
	}
	if len(metadata.CallID) > 128 {
		return nil, fmt.Errorf("delivery call ID exceeds 128 bytes")
	}
	metadata.CallID = strings.Clone(metadata.CallID)
	now := time.Now()
	if metadata.AdmittedAt.IsZero() || metadata.AdmittedAt.After(now) {
		metadata.AdmittedAt = now
	}
	if t == PDUTypeX3 && c.config.X3MaxAge > 0 {
		deadline := metadata.AdmittedAt.Add(c.config.X3MaxAge)
		if metadata.Deadline.IsZero() || deadline.Before(metadata.Deadline) {
			metadata.Deadline = deadline
		}
	}
	if t == PDUTypeX2 {
		metadata.Deadline = time.Time{}
	}
	limit := c.config.X3QueueBytes
	if t == PDUTypeX2 {
		limit = c.config.X2QueueBytes
	}
	if limit > 0 && int64(len(data)) > limit {
		for _, did := range destIDs {
			c.recordTerminalDrop(did, nil, &deliveryItem{pduType: t, xid: xid, data: data, queued: metadata.AdmittedAt}, "oversized")
		}
		return nil, ErrQueueFull
	}
	if t == PDUTypeX3 && !metadata.Deadline.IsZero() && !time.Now().Before(metadata.Deadline) {
		for _, did := range destIDs {
			c.recordTerminalDrop(did, nil, &deliveryItem{pduType: t, xid: xid, data: data, queued: metadata.AdmittedAt}, "expired")
		}
		return nil, ErrExpired
	}
	immutable := append([]byte(nil), data...)
	payload := c.newPayload(int64(len(immutable)))
	defer payload.release()
	var completions []chan error
	var failure error
	for _, did := range destIDs {
		dest, err := c.manager.GetDestination(did)
		if err != nil {
			c.recordTerminalDrop(did, nil, &deliveryItem{pduType: t, xid: xid, data: data, queued: metadata.AdmittedAt}, "destination_removed")
			failure = err
			continue
		}
		if err == nil && !destinationAcceptsPDU(dest, t) {
			continue
		}
		destinationMetadata := metadata
		if err == nil {
			generation := li.DestinationDeliveryGeneration(dest)
			if destinationMetadata.DestinationGeneration != 0 && destinationMetadata.DestinationGeneration != generation {
				c.recordTerminalDrop(did, nil, &deliveryItem{pduType: t, xid: xid, data: data, queued: metadata.AdmittedAt}, "lifecycle_suppressed")
				failure = ErrAllDeliveriesFailed
				continue
			}
			destinationMetadata.DestinationGeneration = generation
		}
		q := c.getOrCreateQueue(did)
		if q == nil {
			c.recordTerminalDrop(did, nil, &deliveryItem{pduType: t, xid: xid, data: data, queued: metadata.AdmittedAt}, "capacity_rejected")
			failure = ErrQueueFull
			continue
		}
		payload.refs.Add(1)
		item := &deliveryItem{payload: payload, pduType: t, xid: xid, data: immutable, queued: metadata.AdmittedAt, metadata: destinationMetadata}
		if synchronous {
			item.completion = make(chan error, 1)
		}
		// Charge before publishing to the dispatcher so completions cannot make gauges negative.
		atomic.AddInt64(&c.stats.QueueDepth, 1)
		atomic.AddInt64(&c.stats.QueueBytes, int64(len(data)))
		dropped, ok := q.enqueue(item)
		if !ok {
			atomic.AddInt64(&c.stats.QueueDepth, -1)
			atomic.AddInt64(&c.stats.QueueBytes, -int64(len(data)))
			reason := "capacity_rejected"
			failure = ErrQueueFull
			if dropped == nil {
				reason = "shutdown_timeout"
				failure = ErrClientStopped
			}
			c.recordTerminalDrop(did, q, item, reason)
			continue
		}
		if t == PDUTypeX2 && c.journal != nil {
			if err := c.persistItem(q, item); err != nil {
				c.removeItem(q, item, "journal_rejected")
				failure = err
				continue
			}
		} else {
			item.persisted.Store(true)
			q.signal()
		}
		if item.completion != nil {
			completions = append(completions, item.completion)
		}
		if dropped != nil {
			c.resolveDrop(q, dropped, "queue_overflow")
			c.logOverflow(did, q, dropped)
		}
	}
	if !synchronous && failure == nil {
		if t == PDUTypeX2 {
			atomic.AddUint64(&c.stats.X2Queued, 1)
		} else {
			atomic.AddUint64(&c.stats.X3Queued, 1)
		}
	}
	return completions, failure
}

func destinationAcceptsPDU(dest *li.Destination, pduType PDUType) bool {
	switch strings.ToUpper(strings.TrimSpace(dest.ProtocolType)) {
	case "X2", "X2ONLY":
		return pduType == PDUTypeX2
	case "X3", "X3ONLY":
		return pduType == PDUTypeX3
	case "X2ANDX3":
		return pduType == PDUTypeX2 || pduType == PDUTypeX3
	case "HI3":
		return false
	default:
		return true
	}
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
	if c.stopped.Load() {
		return nil
	}
	if q = c.queues[did]; q != nil {
		return q
	}
	if c.config.MemoryBudgetBytes > 0 {
		reserve, _ := c.config.ReservedDestinationBytes()
		global, _ := c.config.ReservedGlobalBytes()
		if int64(len(c.queues)+1) > (c.config.MemoryBudgetBytes-global)/reserve {
			return nil
		}
	}
	q = newDestinationQueue(did, c.config.QueueSize)
	x2Size, x3Size := c.config.EffectiveQueueSizes()
	q.capacities = [2]int{x2Size, x3Size}
	q.limits = [2]int64{c.config.X2QueueBytes, c.config.X3QueueBytes}
	q.preserveX2 = c.journal != nil
	c.queues[did] = q
	if c.started.Load() && !c.stopped.Load() {
		c.startDispatcher(q)
	}
	return q
}

func (c *Client) startDispatcher(q *destinationQueue) {
	c.wg.Add(3)
	q.workers.Add(3)
	go c.destinationDispatcher(q, PDUTypeX2)
	go c.destinationDispatcher(q, PDUTypeX3)
	go c.expiryDispatcher(q)
}
func (c *Client) destinationDispatcher(q *destinationQueue, t PDUType) {
	defer c.wg.Done()
	defer q.workers.Done()
	defer c.finishStoppedClaim(q, t)
	backoff := c.config.RetryInitialBackoff
	notify := q.notify
	if t == PDUTypeX3 {
		notify = q.notifyX3
	}
	for {
		if t == PDUTypeX3 {
			c.expireQueued(q)
		}
		item := q.claim(t)
		if item != nil && !item.persisted.Load() {
			q.mu.Lock()
			if q.stopped {
				q.mu.Unlock()
				return
			}
			item.claimed = false
			q.mu.Unlock()
			item = nil
		}
		if item == nil {
			select {
			case <-notify:
				continue
			case <-q.stop:
				return
			}
		}
		deadline := time.Now().Add(c.config.SendTimeout)
		if !item.metadata.Deadline.IsZero() && item.metadata.Deadline.Before(deadline) {
			deadline = item.metadata.Deadline
		}
		if !time.Now().Before(deadline) {
			if q.pop(item) {
				c.resolveDrop(q, item, "expired")
			}
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		q.mu.Lock()
		item.cancel = cancel
		stopped := q.stopped || item.canceled.Load() || item.terminal.Load()
		q.mu.Unlock()
		if stopped {
			cancel()
			if item.canceled.Load() {
				if q.pop(item) {
					c.resolveDrop(q, item, "lifecycle_suppressed")
				}
				continue
			}
			if item.terminal.Load() {
				continue
			}
			return
		}
		conn, err := c.manager.GetConnectionForInterface(ctx, q.did, t)
		if err == nil {
			q.mu.Lock()
			item.conn = conn
			stopped = q.stopped || item.canceled.Load() || item.terminal.Load()
			q.mu.Unlock()
			if stopped {
				cancel()
				c.manager.InvalidateConnection(q.did, conn)
				if item.canceled.Load() {
					if q.pop(item) {
						c.resolveDrop(q, item, "lifecycle_suppressed")
					}
				}
				continue
			}
			current, generationErr := c.manager.GetDestination(q.did)
			if generationErr != nil || (item.metadata.DestinationGeneration != 0 && li.DestinationDeliveryGeneration(current) != item.metadata.DestinationGeneration) {
				item.canceled.Store(true)
				cancel()
			}
			err = c.manager.WritePDUContext(ctx, conn, item.data, deadline)
			if err == nil {
				c.manager.RecordBytesSent(q.did, uint64(len(item.data)))
				c.manager.ReleaseConnection(q.did, conn)
			} else {
				c.manager.RecordWriteError(q.did)
				c.manager.InvalidateConnection(q.did, conn)
			}
		}
		cancel()
		if errors.Is(err, ErrUncertainWrite) {
			item.uncertain.Store(true)
			atomic.AddUint64(&c.stats.UncertainWrites, 1)
			atomic.AddUint64(&c.stats.UncertainBytes, uint64(len(item.data)))
			q.mu.Lock()
			q.stats.UncertainWrites++
			q.stats.UncertainBytes += uint64(len(item.data))
			q.mu.Unlock()
		}
		q.mu.Lock()
		item.cancel = nil
		item.conn = nil
		q.mu.Unlock()
		if item.canceled.Load() {
			if q.pop(item) {
				reason := "lifecycle_suppressed"
				if errors.Is(err, ErrUncertainWrite) {
					reason = "uncertain_write"
				}
				c.resolveDrop(q, item, reason)
			}
			continue
		}
		if err == nil {
			if q.pop(item) {
				atomic.AddInt64(&c.stats.QueueDepth, -1)
				atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
				c.recordSuccess(q, item)
			}
			backoff = c.config.RetryInitialBackoff
			continue
		}
		if errors.Is(err, ErrDestinationNotFound) {
			c.dropDestinationQueue(q, "destination_removed")
			return
		}
		if !item.metadata.Deadline.IsZero() && !time.Now().Before(item.metadata.Deadline) {
			if q.pop(item) {
				reason := "expired"
				if errors.Is(err, ErrUncertainWrite) {
					reason = "uncertain_write"
				}
				c.resolveDrop(q, item, reason)
			}
			continue
		}
		q.mu.Lock()
		if q.stopped {
			q.mu.Unlock()
			return
		}
		item.claimed = false
		q.observeDeadlineLocked(item)
		q.mu.Unlock()
		c.recordRetry(q, err)
		delay := jitterDuration(backoff, c.config.RetryJitter)
		if !item.metadata.Deadline.IsZero() {
			delay = min(delay, max(time.Until(item.metadata.Deadline), 0))
		}

		if !waitForRetry(q, delay) {
			return
		}
		backoff = min(backoff*2, c.config.RetryMaxBackoff)
	}
}
func (c *Client) resolveDrop(q *destinationQueue, item *deliveryItem, reason string) {
	atomic.AddInt64(&c.stats.QueueDepth, -1)
	atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
	c.recordTerminalDrop(q.did, q, item, reason)
}

func waitForRetry(q *destinationQueue, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-q.stop:
		return false
	}
}

func jitterDuration(delay time.Duration, fraction float64) time.Duration {
	if fraction <= 0 {
		return delay
	}
	factor := 1 - fraction + rand.Float64()*(2*fraction)
	return time.Duration(float64(delay) * factor)
}

func (c *Client) recordSuccess(q *destinationQueue, item *deliveryItem) {
	if !item.terminal.CompareAndSwap(false, true) {
		return
	}
	defer item.payload.release()
	if item.journalID.Load() != 0 && c.journal != nil {
		if err := c.journal.Complete(item.journalID.Load()); err != nil {
			logger.Error("checkpoint X2 journal", "error", err)
		}
	}
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
	if item.completion != nil {
		item.completion <- nil
	}
}

func (c *Client) recordRetry(q *destinationQueue, err error) {
	atomic.AddUint64(&c.stats.Retries, 1)
	q.mu.Lock()
	q.stats.Retries++
	q.stats.LastError = err.Error()
	q.mu.Unlock()
}

func (c *Client) recordTerminalDrop(did uuid.UUID, q *destinationQueue, item *deliveryItem, reason string) {
	if item.uncertain.Load() {
		reason = "uncertain_write"
	}
	if !item.terminal.CompareAndSwap(false, true) {
		return
	}
	defer item.payload.release()
	if item.completion != nil {
		item.completion <- fmt.Errorf("delivery discarded: %s", reason)
	}
	c.outcomesMu.Lock()
	c.outcomes[reason]++
	c.outcomeBytes[reason] += uint64(len(item.data))
	c.outcomesMu.Unlock()
	atomic.AddUint64(&c.stats.DroppedBytes, uint64(len(item.data)))
	affected := item.queued
	if affected.IsZero() {
		affected = time.Now()
	}
	atomic.CompareAndSwapInt64(&c.stats.FirstDroppedUnixNano, 0, affected.UnixNano())
	if item.pduType == PDUTypeX2 {
		atomic.AddUint64(&c.stats.X2Dropped, 1)
		atomic.AddUint64(&c.stats.X2Failed, 1)
	} else {
		atomic.AddUint64(&c.stats.X3Dropped, 1)
		atomic.AddUint64(&c.stats.X3Failed, 1)
	}
	if q == nil {
		return
	}
	q.mu.Lock()
	if q.stats.FirstDroppedAt.IsZero() {
		q.stats.FirstDroppedAt = affected
	}
	if q.stats.FirstDroppedByReason[reason].IsZero() {
		q.stats.FirstDroppedByReason[reason] = affected
	}
	q.stats.TerminalDrops++
	q.stats.DroppedBytes += uint64(len(item.data))
	q.stats.DroppedBytesByReason[reason] += uint64(len(item.data))
	if reason == "expired" {
		q.stats.X3Expired++
	}
	if item.pduType == PDUTypeX2 {
		q.stats.X2Dropped++
	} else {
		q.stats.X3Dropped++
	}
	q.stats.DroppedByReason[reason]++
	q.mu.Unlock()
	if item.pduType == PDUTypeX2 {
		q.mu.Lock()
		logNow := time.Since(q.lastOverflowLog) >= time.Second
		if logNow {
			q.lastOverflowLog = time.Now()
		}
		q.mu.Unlock()
		if logNow {
			logger.Error("LI X2 terminal drop", "xid", item.xid, "did", did, "reason", reason)
		}
	}
}

func (c *Client) logOverflow(did uuid.UUID, q *destinationQueue, item *deliveryItem) {
	q.mu.Lock()
	if time.Since(q.lastOverflowLog) < time.Second {
		q.mu.Unlock()
		return
	}
	q.lastOverflowLog = time.Now()
	depth := q.items[0].Len() + q.items[1].Len()
	drops := q.stats.QueueOverflows
	q.mu.Unlock()
	logger.Warn("LI delivery queue overflow, dropped oldest item",
		"did", did, "xid", item.xid, "pdu_type", item.pduType,
		"reason", "queue_overflow", "queue_depth", depth,
		"queue_capacity", q.capacity, "dropped_total", drops,
	)
}

func (c *Client) dropDestinationQueue(q *destinationQueue, reason string) {
	items := q.stopAndDrain(reason)
	q.mu.Lock()
	reason = q.stopReason
	q.mu.Unlock()
	atomic.AddInt64(&c.stats.QueueDepth, -int64(len(items)))
	for _, item := range items {
		atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
	}
	retained := 0
	for _, item := range items {
		if item.pduType == PDUTypeX2 && item.journalID.Load() != 0 && c.journal != nil {
			retained++
			c.journal.Hold(item.journalID.Load())
			if item.terminal.CompareAndSwap(false, true) {
				item.payload.release()
				if item.completion != nil {
					item.completion <- ErrClientStopped
				}
			}
			continue
		}
		c.recordTerminalDrop(q.did, q, item, reason)
	}
	if retained > 0 {
		logger.Info("LI delivery X2 retained on disk", "did", q.did, "items", retained)
	}
	if len(items) > retained {
		logger.Warn("LI delivery items dropped",
			"did", q.did, "reason", reason, "items", len(items)-retained,
		)
	}
}

// finishStoppedClaim resolves capacity only after the transport owner has exited.
// Shutdown/removal cannot classify an active write as a known unsent drop.
func (c *Client) finishStoppedClaim(q *destinationQueue, t PDUType) {
	q.mu.Lock()
	e := q.items[queueIndex(t)].Front()
	if !q.stopped || e == nil || !e.Value.(*deliveryItem).claimed {
		q.mu.Unlock()
		return
	}
	item := e.Value.(*deliveryItem)
	if q.preserveX2 && item.pduType == PDUTypeX2 && !item.persisted.Load() {
		item.claimed = false
		q.mu.Unlock()
		return
	}
	reason := q.stopReason
	if reason == "" {
		reason = "destination_removed"
	}
	q.mu.Unlock()
	if !q.pop(item) {
		return
	}
	atomic.AddInt64(&c.stats.QueueDepth, -1)
	atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
	if item.pduType == PDUTypeX2 && item.journalID.Load() != 0 && c.journal != nil {
		c.journal.Hold(item.journalID.Load())
		if item.terminal.CompareAndSwap(false, true) {
			item.payload.release()
			if item.completion != nil {
				item.completion <- ErrClientStopped
			}
		}
		return
	}
	if item.uncertain.Load() {
		reason = "uncertain_write"
	}
	c.recordTerminalDrop(q.did, q, item, reason)
}

// RemoveDestination stops and removes delivery state for a deleted destination.
func (c *Client) RemoveDestination(did uuid.UUID) {
	c.admissionMu.Lock()
	c.queuesMu.RLock()
	q := c.queues[did]
	c.queuesMu.RUnlock()
	if q == nil {
		c.admissionMu.Unlock()
		return
	}
	// Prevent admissions before releasing the packet-path admission lock. Disk
	// checkpointing and transport joins run without that lock.
	q.mu.Lock()
	if q.stopReason == "" {
		q.stopReason = "destination_removed"
	}
	if !q.stopped {
		q.stopped = true
		close(q.stop)
	}
	q.mu.Unlock()
	q.signal()
	c.admissionMu.Unlock()
	if c.journal != nil {
		if err := c.journal.Flush(); err != nil {
			logger.Error("flush removed destination journal", "error", err)
		}
	}
	c.dropDestinationQueue(q, "destination_removed")
	q.workers.Wait()
	c.queuesMu.Lock()
	if c.queues[did] == q {
		delete(c.queues, did)
	}
	c.queuesMu.Unlock()
}

func (c *Client) Stats() ClientStats {
	c.outcomesMu.Lock()
	counts := make(map[string]uint64)
	bytes := make(map[string]uint64)
	for k, v := range c.outcomes {
		counts[k] = v
	}
	for k, v := range c.outcomeBytes {
		bytes[k] = v
	}
	c.outcomesMu.Unlock()
	first := time.Time{}
	if n := atomic.LoadInt64(&c.stats.FirstDroppedUnixNano); n != 0 {
		first = time.Unix(0, n)
	}
	return ClientStats{PhysicalQueueBytes: atomic.LoadInt64(&c.stats.PhysicalQueueBytes), UncertainWrites: atomic.LoadUint64(&c.stats.UncertainWrites), UncertainBytes: atomic.LoadUint64(&c.stats.UncertainBytes), DroppedByReason: counts, DroppedBytesByReason: bytes, FirstDroppedAt: first, FirstDroppedUnixNano: atomic.LoadInt64(&c.stats.FirstDroppedUnixNano),
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
		QueueBytes: atomic.LoadInt64(&c.stats.QueueBytes), DroppedBytes: atomic.LoadUint64(&c.stats.DroppedBytes),
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

func (c *Client) SendX2Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}
	return c.sendSync(ctx, PDUTypeX2, xid, destIDs, data, DeliveryMetadata{})
}

func (c *Client) SendX3Sync(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte) error {
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if len(destIDs) == 0 {
		return ErrNoDestinations
	}
	return c.sendSync(ctx, PDUTypeX3, xid, destIDs, data, DeliveryMetadata{})
}

func (c *Client) sendSync(ctx context.Context, t PDUType, xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	originalContext := ctx
	ctx, cancel := context.WithTimeout(ctx, c.config.SendTimeout)
	defer cancel()
	completions, err := c.enqueueWithMetadata(t, xid, destIDs, data, metadata, true)
	if err != nil {
		return err
	}
	success := false
	for _, completion := range completions {
		select {
		case err := <-completion:
			if err == nil {
				success = true
			}
		case <-ctx.Done():
			if err := originalContext.Err(); err != nil {
				return err
			}
			return ErrAllDeliveriesFailed
		}
	}
	if !success {
		return ErrAllDeliveriesFailed
	}
	return nil
}

// CancelTask and CancelCall suppress matching X3 generations; X2 is retained.
func (c *Client) CancelTask(xid uuid.UUID, generation uint64) {
	c.cancelMatching(func(item *deliveryItem) bool { return item.xid == xid && item.metadata.TaskGeneration == generation })
}
func (c *Client) CancelCall(callID string, generation uint64) {
	c.cancelMatching(func(item *deliveryItem) bool {
		return item.metadata.CallID == callID && item.metadata.CallGeneration == generation
	})
}
func (c *Client) cancelMatching(match func(*deliveryItem) bool) {
	c.queuesMu.RLock()
	defer c.queuesMu.RUnlock()
	for _, q := range c.queues {
		var removed []*deliveryItem
		var cancels []context.CancelFunc
		q.mu.Lock()
		for e := q.items[1].Front(); e != nil; {
			next := e.Next()
			item := e.Value.(*deliveryItem)
			if match(item) {
				item.canceled.Store(true)
				if item.cancel != nil {
					cancels = append(cancels, item.cancel)
				}
				if !item.claimed {
					q.items[1].Remove(e)
					q.removeExpiryLocked(item)
					item.element = nil
					q.bytes[1] -= int64(len(item.data))
					removed = append(removed, item)
				}
			}
			e = next
		}
		q.updateDepthLocked()
		q.mu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		for _, item := range removed {
			c.resolveDrop(q, item, "lifecycle_suppressed")
		}
		q.signal()
	}
}

func (c *Client) removeItem(q *destinationQueue, item *deliveryItem, reason string) {
	q.mu.Lock()
	i := queueIndex(item.pduType)
	found := false
	for e := q.items[i].Front(); e != nil; e = e.Next() {
		if e.Value == item {
			q.items[i].Remove(e)
			q.removeExpiryLocked(item)
			item.element = nil
			q.bytes[i] -= int64(len(item.data))
			found = true
			break
		}
	}
	q.updateDepthLocked()
	q.mu.Unlock()
	if found {
		c.resolveDrop(q, item, reason)
	}
	q.signal()
}

func (c *Client) expireQueued(q *destinationQueue) {
	var expired []*deliveryItem
	now := time.Now()
	q.mu.Lock()
	for {
		item := q.takeExpiredLocked(now)
		if item == nil {
			break
		}
		if !item.claimed && item.element != nil {
			q.items[1].Remove(item.element)
			item.element = nil
			q.bytes[1] -= int64(len(item.data))
			expired = append(expired, item)
		}
	}
	q.updateDepthLocked()
	q.mu.Unlock()
	for _, item := range expired {
		c.resolveDrop(q, item, "expired")
	}
}

// An independent bounded timer owner expires queued X3 even while the interface
// owner is dialing or writing an earlier entry with a later admission deadline.
func (c *Client) expiryDispatcher(q *destinationQueue) {
	defer c.wg.Done()
	defer q.workers.Done()
	for {
		c.expireQueued(q)
		q.mu.Lock()
		deadline := q.nextExpiry
		q.mu.Unlock()
		if deadline.IsZero() {
			select {
			case <-q.stop:
				return
			case <-q.expiryNotify:
				continue
			}
		}
		timer := time.NewTimer(max(time.Until(deadline), 0))
		select {
		case <-q.stop:
			timer.Stop()
			return
		case <-q.expiryNotify:
			timer.Stop()
		case <-timer.C:
		}
	}
}

type sharedPayload struct {
	refs   atomic.Int64
	client *Client
	size   int64
}

func (c *Client) newPayload(size int64) *sharedPayload {
	p := &sharedPayload{client: c, size: size}
	p.refs.Store(1)
	atomic.AddInt64(&c.stats.PhysicalQueueBytes, size)
	return p
}
func (p *sharedPayload) release() {
	if p != nil && p.refs.Add(-1) == 0 {
		atomic.AddInt64(&p.client.stats.PhysicalQueueBytes, -p.size)
	}
}
func (c *Client) attachPayload(item *deliveryItem) {
	item.payload = c.newPayload(int64(len(item.data)))
}

// ReserveDestination validates the isolated reservation before enabling capture.
func (c *Client) ReserveDestination(did uuid.UUID) error {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.initErr != nil {
		return c.initErr
	}
	if c.stopped.Load() {
		return ErrClientStopped
	}
	if c.getOrCreateQueue(did) == nil {
		return ErrQueueFull
	}
	return nil
}
func (c *Client) SendX2SyncWithMetadata(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata) error {
	return c.sendSync(ctx, PDUTypeX2, xid, destIDs, data, metadata)
}
func (c *Client) SendX3SyncWithMetadata(ctx context.Context, xid uuid.UUID, destIDs []uuid.UUID, data []byte, metadata DeliveryMetadata) error {
	return c.sendSync(ctx, PDUTypeX3, xid, destIDs, data, metadata)
}
