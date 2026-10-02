//go:build li

package delivery

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const maxDeliveryGateIdentities = 65536

type x3TaskIdentity struct {
	XID        uuid.UUID
	Generation uint64
}

// Capture the admission cutoff once when an embedding has not installed a
// committed task fact yet. Later packet metadata cannot extend that cutoff;
// only the committed control-plane publication updates an existing fact.
func (c *Client) rememberX3TaskAuthorization(xid uuid.UUID, generation uint64, end time.Time) {
	if c.config.AuthoritativeTaskAuthorization || end.IsZero() {
		return
	}
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	key := x3TaskIdentity{xid, generation}
	if _, exists := c.taskFacts[key]; exists {
		return
	}
	if len(c.taskFacts) >= maxDeliveryGateIdentities {
		c.gateFault = true
		return
	}
	c.taskFacts[key] = end
}

func (c *Client) SetX3TaskAuthorization(xid uuid.UUID, generation uint64, end time.Time) {
	c.gateMu.Lock()
	key := x3TaskIdentity{xid, generation}
	if c.config.AuthoritativeTaskAuthorization {
		if _, known := c.taskFacts[key]; !known {
			c.gateMu.Unlock()
			return
		}
	}
	if len(c.taskFacts) >= maxDeliveryGateIdentities {
		if _, exists := c.taskFacts[key]; !exists {
			c.gateFault = true
			c.gateMu.Unlock()
			return
		}
	}
	previous, known := c.taskFacts[key]
	if !end.IsZero() && !time.Now().Before(end) || known && !previous.IsZero() && !time.Now().Before(previous) {
		if len(c.revokedTasks) >= maxDeliveryGateIdentities && !c.revokedTasks[key] {
			c.gateFault = true
		} else {
			c.revokedTasks[key] = true
		}
	}
	c.taskFacts[key] = end
	blocked := c.revokedTasks[key]
	c.taskAuthorizationChanged()
	c.gateMu.Unlock()
	if c.config.AuthoritativeTaskAuthorization {
		return
	}
	var cancels []context.CancelFunc
	c.queuesMu.RLock()
	for _, q := range c.queues {
		q.mu.Lock()
		for e := q.items[1].Front(); e != nil; e = e.Next() {
			item := e.Value.(*deliveryItem)
			if item.xid != xid || item.metadata.TaskGeneration != generation {
				continue
			}
			q.removeExpiryLocked(item)
			expiry := item.metadata.Deadline
			if !end.IsZero() && (expiry.IsZero() || end.Before(expiry)) {
				expiry = end
			}
			if blocked {
				expiry = time.Now()
			}
			item.eligibilityDeadline = expiry
			q.observeDeadlineLocked(item)
			if item.cancel != nil {
				cancels = append(cancels, item.cancel)
			}
		}
		q.mu.Unlock()
		q.signal()
	}
	c.queuesMu.RUnlock()
	for _, cancel := range cancels {
		cancel()
	}
}
func (c *Client) x3TaskEnd(xid uuid.UUID, generation uint64) time.Time {
	c.gateMu.RLock()
	defer c.gateMu.RUnlock()
	return c.taskFacts[x3TaskIdentity{xid, generation}]
}

// Task cutoffs are independent of packet arrival, MDF availability, replay
// approval and the bounded transport queue. One durable scoped control covers
// the task's retained products without materializing their payloads.
func (c *Client) sweepTaskCutoffs() {
	defer c.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !c.stopped.Load() {
		c.gateMu.Lock()
		var expired []x3TaskIdentity
		for key, end := range c.taskFacts {
			if !c.expiredTaskControls[key] && (c.revokedTasks[key] || !end.IsZero() && !time.Now().Before(end)) {
				if len(c.revokedTasks) >= maxDeliveryGateIdentities && !c.revokedTasks[key] {
					c.gateFault = true
				} else {
					c.revokedTasks[key] = true
				}
				expired = append(expired, key)
				if len(expired) == 32 {
					break
				}
			}
		}
		c.gateMu.Unlock()
		for _, key := range expired {
			if c.stopped.Load() {
				return
			}
			c.CancelTask(key.XID, key.Generation)
			operation := uuid.New()
			controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: operation, StateIncarnation: c.config.StateIncarnation, Task: &li.InterceptTask{XID: key.XID, ActivationGeneration: key.Generation}})
			if err == nil {
				_, err = c.DurableRevoker().Commit(controls)
			}
			if err != nil {
				c.x3Journal.fault(err)
				return
			}
			c.gateMu.Lock()
			if _, retained := c.taskFacts[key]; retained {
				c.expiredTaskControls[key] = true
			}
			c.gateMu.Unlock()
		}
		<-ticker.C
	}
}

// AcceptedX3 owns one bounded reservation between authorized producer admission
// and reorder emission. It is never authorization for a different product.
type AcceptedX3 struct {
	client      *Client
	queue       *destinationQueue
	item        *deliveryItem
	used        atomic.Bool
	reservation *JournalAdmission
}

func (a *AcceptedX3) Release() {
	if a == nil || !a.used.CompareAndSwap(false, true) {
		return
	}
	a.queue.mu.Lock()
	a.queue.reserved[1]--
	a.queue.reservedBytes[1] -= int64(len(a.item.data))
	a.queue.mu.Unlock()
	a.reservation.Release()
	a.client.releasePreparedCall(a.item, false)
	a.item.payload.release()
}

func deliveryCall(xid uuid.UUID, m DeliveryMetadata) li.DeliveryCallIdentity {
	return li.DeliveryCallIdentity{StateIncarnation: m.StateIncarnation, CallIncarnation: m.CallIncarnation, XID: xid, TaskGeneration: m.TaskGeneration, CallGeneration: m.CallGeneration, CallID: m.CallID}
}

func (c *Client) itemEligible(did uuid.UUID, item *deliveryItem, newAdmission bool) bool {
	c.gateMu.RLock()
	conflictBlocked := c.conflictGateFault || (c.conflictGenerations[item.xid] != 0 && item.metadata.TaskGeneration <= c.conflictGenerations[item.xid])
	c.gateMu.RUnlock()
	if conflictBlocked || item.canceled.Load() {
		return false
	}
	if item.pduType != PDUTypeX3 {
		c.gateMu.RLock()
		defer c.gateMu.RUnlock()
		for _, control := range c.revoked {
			if c.productControlMatches(control, did, item) {
				return false
			}
		}
		return true
	}
	m := item.metadata
	now := time.Now()
	if !m.Deadline.IsZero() && !now.Before(m.Deadline) {
		return false
	}
	if c.x3Journal != nil && (m.StateIncarnation == uuid.Nil || m.StateIncarnation != c.config.StateIncarnation) {
		return false
	}
	c.gateMu.RLock()
	defer c.gateMu.RUnlock()
	if c.gateFault || c.revokedTasks[x3TaskIdentity{item.xid, m.TaskGeneration}] {
		return false
	}
	end, ok := c.taskFacts[x3TaskIdentity{item.xid, m.TaskGeneration}]
	if !ok && c.config.AuthoritativeTaskAuthorization {
		return false
	}
	if !ok {
		end = m.TaskEndAt
	}
	if !end.IsZero() && !now.Before(end) {
		return false
	}
	if newAdmission && c.closedCalls[deliveryCall(item.xid, m)] {
		return false
	}
	for _, control := range c.revoked {
		if c.productControlMatches(control, did, item) {
			return false
		}
	}
	return !item.canceled.Load()
}

func (c *Client) taskDeadline(item *deliveryItem) time.Time {
	c.gateMu.RLock()
	end, ok := c.taskFacts[x3TaskIdentity{item.xid, item.metadata.TaskGeneration}]
	c.gateMu.RUnlock()
	if !ok {
		return item.metadata.TaskEndAt
	}
	return end
}

func (c *Client) effectiveExpiry(item *deliveryItem) time.Time {
	expiry := item.metadata.Deadline
	if item.pduType == PDUTypeX3 {
		end := c.taskDeadline(item)
		if !end.IsZero() && (expiry.IsZero() || end.Before(expiry)) {
			expiry = end
		}
	}
	return expiry
}

func controlMatches(control *li.StateRevocation, did uuid.UUID, item *deliveryItem) bool {
	m := item.metadata
	if control.StateIncarnation != m.StateIncarnation {
		return false
	}
	switch control.Scope {
	case li.StateRevokeTask:
		return control.XID != nil && *control.XID == item.xid && control.TaskGeneration != nil && *control.TaskGeneration == m.TaskGeneration
	case li.StateRevokeDestination:
		return control.DID != nil && *control.DID == did && control.DestinationGeneration != nil && *control.DestinationGeneration == m.DestinationGeneration
	case li.StateRevokeCall:
		return control.XID != nil && *control.XID == item.xid && control.TaskGeneration != nil && *control.TaskGeneration == m.TaskGeneration && control.DID != nil && *control.DID == did && control.DestinationGeneration != nil && *control.DestinationGeneration == m.DestinationGeneration && control.CallIncarnation != nil && *control.CallIncarnation == m.CallIncarnation && control.CallGeneration != nil && *control.CallGeneration == m.CallGeneration
	}
	return false
}

func (c *Client) PrepareX3(xid, did uuid.UUID, data []byte, m DeliveryMetadata) (*AcceptedX3, error) {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.initErr != nil {
		return nil, c.initErr
	}
	if c.stopped.Load() {
		return nil, ErrClientStopped
	}
	dest, err := c.manager.GetDestination(did)
	if err != nil {
		return nil, err
	}
	if !destinationAcceptsPDU(dest, PDUTypeX3) {
		return nil, ErrNoDestinations
	}
	generation := li.DestinationDeliveryGeneration(dest)
	if m.DestinationGeneration != 0 && m.DestinationGeneration != generation {
		return nil, ErrAllDeliveriesFailed
	}
	m.DestinationGeneration = generation
	now := time.Now()
	if m.AdmittedAt.IsZero() || m.AdmittedAt.After(now) {
		m.AdmittedAt = now
	}
	if c.config.X3MaxAge > 0 {
		deadline := m.AdmittedAt.Add(c.config.X3MaxAge)
		if m.Deadline.IsZero() || deadline.Before(m.Deadline) {
			m.Deadline = deadline
		}
	}
	item := &deliveryItem{journal: c.x3Journal, pduType: PDUTypeX3, xid: xid, metadata: m, queued: m.AdmittedAt}
	c.rememberX3TaskAuthorization(xid, m.TaskGeneration, m.TaskEndAt)
	if !c.itemEligible(did, item, true) {
		return nil, ErrExpired
	}
	q := c.getOrCreateQueue(did)
	if q == nil {
		return nil, ErrQueueFull
	}
	q.mu.Lock()
	queued, queuedBytes := q.items[1].Len(), q.bytes[1]
	if c.x3Journal != nil && c.x3Journal.segments != nil {
		queued, queuedBytes = 0, 0
	}
	if q.stopped || queued+q.reserved[1] >= q.capacities[1] || q.limits[1] > 0 && int64(len(data)) > q.limits[1]-queuedBytes-q.reservedBytes[1] {
		q.mu.Unlock()
		return nil, ErrQueueFull
	}
	q.reserved[1]++
	q.reservedBytes[1] += int64(len(data))
	q.mu.Unlock()
	var reservation *JournalAdmission
	if c.x3Journal != nil {
		if _, err := journalPDUCheckpoint(data, PDUTypeX3, xid, true); err != nil {
			q.mu.Lock()
			q.reserved[1]--
			q.reservedBytes[1] -= int64(len(data))
			q.mu.Unlock()
			return nil, err
		}
		record := JournalRecord{ID: 1, Interface: PDUTypeX3, JournalUUID: c.x3Journal.UUID(), StateIncarnation: m.StateIncarnation, XID: xid, DID: did, TaskGeneration: m.TaskGeneration, DestinationGeneration: m.DestinationGeneration, AdmittedAt: m.AdmittedAt, CapturedAt: m.CapturedAt, Deadline: m.Deadline, Provenance: m.Provenance}
		prefix, err := recordPrefix(record, uint64(len(data)))
		if err != nil {
			q.mu.Lock()
			q.reserved[1]--
			q.reservedBytes[1] -= int64(len(data))
			q.mu.Unlock()
			return nil, err
		}
		reservation, err = c.x3Journal.ReserveAdmissionWithMetadata(int64(len(data)), int64(len(prefix)+32))
		if err != nil {
			q.mu.Lock()
			q.reserved[1]--
			q.reservedBytes[1] -= int64(len(data))
			q.mu.Unlock()
			return nil, err
		}
	}
	if m.CallIncarnation != uuid.Nil {
		c.gateMu.Lock()
		identity := deliveryCall(xid, m)
		if !c.acceptedCalls[identity] && c.preparedCalls[identity] == 0 && len(c.acceptedCalls)+len(c.closedCalls)+len(c.preparedCalls) >= maxDeliveryGateIdentities {
			c.gateMu.Unlock()
			q.mu.Lock()
			q.reserved[1]--
			q.reservedBytes[1] -= int64(len(data))
			q.mu.Unlock()
			reservation.Release()
			return nil, ErrQueueFull
		}
		c.preparedCalls[identity]++
		c.gateMu.Unlock()
	}
	item.data = append([]byte(nil), data...)
	item.payload = c.newPayload(int64(len(data)))
	return &AcceptedX3{client: c, queue: q, item: item, reservation: reservation}, nil
}

// SendAcceptedX3 performs no manager/call authorization lookup. All input facts
// were captured by PrepareX3; the monotonic gate can only withdraw eligibility.
func (c *Client) SendAcceptedX3(a *AcceptedX3) (result error) {
	if a == nil || a.client != c || !a.used.CompareAndSwap(false, true) {
		return fmt.Errorf("invalid or consumed X3 admission")
	}
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	defer func() { c.releasePreparedCall(a.item, result == nil) }()
	q, item := a.queue, a.item
	item.journalAdmission = a.reservation
	q.mu.Lock()
	q.reserved[1]--
	q.reservedBytes[1] -= int64(len(item.data))
	q.mu.Unlock()
	if c.stopped.Load() || !c.itemEligible(q.did, item, false) {
		a.reservation.Release()
		item.payload.release()
		return ErrClientStopped
	}
	if c.x3Journal != nil && c.x3Journal.segments != nil {
		item.detached = true
		if err := c.persistItem(q, item); err != nil {
			a.reservation.Release()
			c.recordTerminalDrop(q.did, q, item, "journal_rejected")
			return err
		}
		atomic.AddUint64(&c.stats.X3Queued, 1)
		return nil
	}
	atomic.AddInt64(&c.stats.QueueDepth, 1)
	atomic.AddInt64(&c.stats.QueueBytes, int64(len(item.data)))
	item.eligibilityDeadline = c.effectiveExpiry(item)
	dropped, ok := q.enqueue(item)
	if !ok {
		atomic.AddInt64(&c.stats.QueueDepth, -1)
		atomic.AddInt64(&c.stats.QueueBytes, -int64(len(item.data)))
		a.reservation.Release()
		item.payload.release()
		return ErrQueueFull
	}
	if dropped != nil {
		c.resolveDrop(q, dropped, "queue_overflow")
	}
	if c.x3Journal != nil {
		if err := c.persistItem(q, item); err != nil {
			a.reservation.Release()
			c.removeItem(q, item, "journal_rejected")
			return err
		}
	} else {
		item.persisted.Store(true)
		q.signal()
	}
	atomic.AddUint64(&c.stats.X3Queued, 1)
	return nil
}

func (c *Client) releasePreparedCall(item *deliveryItem, accepted bool) {
	if item.metadata.CallIncarnation == uuid.Nil {
		return
	}
	identity := deliveryCall(item.xid, item.metadata)
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	if count := c.preparedCalls[identity]; count <= 1 {
		delete(c.preparedCalls, identity)
	} else {
		c.preparedCalls[identity] = count - 1
	}
	if accepted {
		c.acceptedCalls[identity] = true
	}
}

type clientDurableRevoker struct{ client *Client }

func (c *Client) DurableRevoker() li.DurableRevoker { return &clientDurableRevoker{c} }
func (d *clientDurableRevoker) Prepare(req li.RevocationRequest) ([]*li.StateRevocation, error) {
	c := d.client
	if c.initErr != nil {
		return nil, c.initErr
	}
	if (req.StateIncarnation == uuid.Nil && c.x3Journal != nil) || req.StateIncarnation != c.config.StateIncarnation {
		return nil, fmt.Errorf("revocation state incarnation mismatch")
	}
	if req.OperationID == uuid.Nil || (req.Task == nil) == (req.Destination == nil) {
		return nil, fmt.Errorf("invalid revocation subject")
	}
	var controls []*li.StateRevocation
	for _, owner := range c.journals() {
		if owner == c.x2Journal && !req.IncludeX2 {
			continue
		}
		record, admission := owner.Highwaters()
		journal := owner.UUID()
		control := &li.StateRevocation{Version: 1, ControlID: uuid.NewSHA1(req.OperationID, journal[:]), JournalUUID: journal, StateIncarnation: req.StateIncarnation, CoveredRecordHighwater: record, CoveredAdmissionHighwater: admission, RevokedAt: li.NewStateTimestamp(time.Now())}
		if req.Task != nil {
			xid, gen := req.Task.XID, req.Task.ActivationGeneration
			control.Scope, control.XID, control.TaskGeneration = li.StateRevokeTask, &xid, &gen
		} else {
			did, gen := req.Destination.DID, req.DestinationGeneration
			control.Scope, control.DID, control.DestinationGeneration = li.StateRevokeDestination, &did, &gen
		}
		controls = append(controls, control)
	}
	return controls, nil
}
func (d *clientDurableRevoker) Commit(controls []*li.StateRevocation) (outcome securestore.Outcome, resultErr error) {
	c := d.client
	if len(controls) == 0 {
		return securestore.Committed, nil
	}
	c.gateMu.Lock()
	newControls := make(map[uuid.UUID]bool, len(controls))
	for _, control := range controls {
		if control == nil || c.revocationJournal(control.JournalUUID) == nil || control.StateIncarnation != c.config.StateIncarnation || control.ControlID == uuid.Nil || !validDeliveryControl(control) {
			c.gateMu.Unlock()
			return securestore.NotCommitted, fmt.Errorf("revocation journal binding mismatch")
		}
		if _, exists := c.revoked[control.ControlID]; !exists {
			newControls[control.ControlID] = true
		}
		if len(c.revoked)+len(newControls) > maxDeliveryGateIdentities {
			c.gateMu.Unlock()
			return securestore.NotCommitted, ErrQueueFull
		}
		if previous := c.revoked[control.ControlID]; previous != nil && !reflect.DeepEqual(previous, control) {
			c.gateMu.Unlock()
			return securestore.NotCommitted, fmt.Errorf("revocation control identity cannot change")
		}
	}
	for _, control := range controls {
		c.revoked[control.ControlID] = copyDeliveryControl(control)
		if c.config.AuthoritativeTaskAuthorization && control.Scope == li.StateRevokeTask {
			key := x3TaskIdentity{*control.XID, *control.TaskGeneration}
			if _, known := c.taskFacts[key]; known {
				c.revokedTasks[key] = true
			}
			c.taskAuthorizationChanged()
		}
	}
	c.gateMu.Unlock()
	// Block memory and pending callbacks before any filesystem operation. A failed
	// or uncertain control never reopens the gate.
	claims := c.cancelRevokedTransport(controls)
	defer func() {
		// Joining cannot roll back a durable control. Preserve its actual outcome
		// while reporting an unresolved owner as an unsuccessful boundary.
		resultErr = errors.Join(resultErr, joinRevokedTransport(claims, c.config.SendTimeout))
	}()
	c.cancelMatchingProducts(func(item *deliveryItem) bool {
		for _, control := range controls {
			if control.Scope != li.StateRevokeTask {
				continue
			}
			if c.productControlMatches(control, uuid.Nil, item) {
				return true
			}
		}
		return false
	}, true)
	for _, control := range controls {
		if control.Scope == li.StateRevokeDestination && control.DID != nil {
			c.cancelDestinationGeneration(*control.DID, *control.DestinationGeneration)
		} else if control.Scope == li.StateRevokeCall {
			c.cancelDestinationMatching(*control.DID, func(item *deliveryItem) bool { return controlMatches(control, *control.DID, item) })
		}
	}
	for n, control := range controls {
		current, err := c.revocationJournal(control.JournalUUID).Revoke(control)
		if err != nil || current != securestore.Committed {
			outcome := securestore.NotCommitted
			if current == securestore.Committed && n == len(controls)-1 {
				outcome = securestore.Committed
			} else if n > 0 || current != securestore.NotCommitted {
				outcome = securestore.Uncertain
			}
			return outcome, errors.Join(err, fmt.Errorf("revocation control did not fully commit"))
		}
	}
	// Authoritative task facts (or their absence) reject every old generation.
	// The journal owns durable controls until disk/pending obligations drain;
	// the client need not retain a second lifetime copy after commit succeeds.
	if c.config.AuthoritativeTaskAuthorization {
		c.gateMu.Lock()
		for _, control := range controls {
			if control.Scope == li.StateRevokeTask && c.revocationJournal(control.JournalUUID) == c.x3Journal {
				delete(c.revoked, control.ControlID)
			}
		}
		c.gateMu.Unlock()
	}
	return securestore.Committed, nil
}

// Match controls only to their bound product journal. Ordinary X3 revocation
// must never suppress retained X2, even when their task generations match.
func (c *Client) productControlMatches(control *li.StateRevocation, did uuid.UUID, item *deliveryItem) bool {
	owner := c.journalFor(item.pduType)
	return owner != nil && owner.UUID() == control.JournalUUID && controlMatches(control, did, item)
}

func (c *Client) revocationJournal(id uuid.UUID) *Journal {
	for _, owner := range c.journals() {
		if owner.UUID() == id {
			return owner
		}
	}
	return nil
}

// CancelTaskProducts is reserved for conservative authorization conflicts. It
// blocks new admission, discards both products and joins existing transport
// owners. Historical writes already completed cannot be recalled.
func (c *Client) CancelTaskProducts(xid uuid.UUID, generation uint64) error {
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	c.gateMu.Lock()
	var gateErr error
	if _, exists := c.conflictGenerations[xid]; !exists && len(c.conflictGenerations) >= maxDeliveryGateIdentities {
		c.conflictGateFault = true
		gateErr = ErrQueueFull
	} else {
		c.conflictGenerations[xid] = max(c.conflictGenerations[xid], generation)
	}
	allBlocked := c.conflictGateFault
	c.gateMu.Unlock()
	match := func(_ uuid.UUID, item *deliveryItem) bool {
		return allBlocked || item.xid == xid && item.metadata.TaskGeneration <= generation
	}
	claims := c.cancelTransportMatching(match)
	c.cancelMatchingProducts(func(item *deliveryItem) bool { return match(uuid.Nil, item) }, true)
	// X2-only journaling also supports deployments without administrative state.
	// No manager intent exists in that mode, so finish the durable backlog boundary
	// here. With persistent state the manager records its complete control plan.
	var durableErr error
	if c.config.StateIncarnation == uuid.Nil && c.x2Journal != nil {
		controls, err := c.DurableRevoker().Prepare(li.RevocationRequest{OperationID: uuid.New(), IncludeX2: true, Task: &li.InterceptTask{XID: xid, ActivationGeneration: generation}})
		durableErr = err
		if err == nil {
			_, durableErr = c.DurableRevoker().Commit(controls)
		}
	}
	return errors.Join(gateErr, durableErr, joinRevokedTransport(claims, c.config.SendTimeout))
}

func (c *Client) cancelRevokedTransport(controls []*li.StateRevocation) []<-chan struct{} {
	return c.cancelTransportMatching(func(did uuid.UUID, item *deliveryItem) bool {
		for _, control := range controls {
			if c.productControlMatches(control, did, item) {
				return true
			}
		}
		return false
	})
}

func (c *Client) cancelTransportMatching(match func(uuid.UUID, *deliveryItem) bool) []<-chan struct{} {
	var claims []<-chan struct{}
	var cancels []context.CancelFunc
	c.queuesMu.RLock()
	for _, q := range c.queues {
		q.mu.Lock()
		for _, claim := range q.claims {
			if claim != nil && match(q.did, claim.item) {
				claim.item.canceled.Store(true)
				claims = append(claims, claim.done)
				if claim.item.cancel != nil {
					cancels = append(cancels, claim.item.cancel)
				}
			}
		}
		q.mu.Unlock()
	}
	c.queuesMu.RUnlock()
	for _, cancel := range cancels {
		cancel()
	}
	return claims
}

func joinRevokedTransport(claims []<-chan struct{}, timeout time.Duration) error {
	if len(claims) == 0 {
		return nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, done := range claims {
		// Prefer an already completed owner even if the shared deadline elapsed
		// while a previous owner was being joined.
		select {
		case <-done:
			continue
		default:
		}
		select {
		case <-done:
		case <-timer.C:
			return fmt.Errorf("revocation transport owner did not resolve: %w", context.DeadlineExceeded)
		}
	}
	return nil
}
func validDeliveryControl(control *li.StateRevocation) bool {
	if control.Version != 1 {
		return false
	}
	switch control.Scope {
	case li.StateRevokeTask:
		return control.XID != nil && *control.XID != uuid.Nil && control.TaskGeneration != nil && *control.TaskGeneration > 0
	case li.StateRevokeDestination:
		return control.DID != nil && *control.DID != uuid.Nil && control.DestinationGeneration != nil && *control.DestinationGeneration > 0
	case li.StateRevokeCall:
		return control.XID != nil && *control.XID != uuid.Nil && control.TaskGeneration != nil && *control.TaskGeneration > 0 && control.DID != nil && *control.DID != uuid.Nil && control.DestinationGeneration != nil && *control.DestinationGeneration > 0 && control.CallIncarnation != nil && *control.CallIncarnation != uuid.Nil && control.CallGeneration != nil && *control.CallGeneration > 0
	}
	return false
}
func copyDeliveryControl(control *li.StateRevocation) *li.StateRevocation {
	copy := *control
	if control.XID != nil {
		v := *control.XID
		copy.XID = &v
	}
	if control.DID != nil {
		v := *control.DID
		copy.DID = &v
	}
	if control.TaskGeneration != nil {
		v := *control.TaskGeneration
		copy.TaskGeneration = &v
	}
	if control.DestinationGeneration != nil {
		v := *control.DestinationGeneration
		copy.DestinationGeneration = &v
	}
	if control.CallIncarnation != nil {
		v := *control.CallIncarnation
		copy.CallIncarnation = &v
	}
	if control.CallGeneration != nil {
		v := *control.CallGeneration
		copy.CallGeneration = &v
	}
	return &copy
}

func (c *Client) cancelDestinationGeneration(did uuid.UUID, generation uint64) {
	c.cancelDestinationMatching(did, func(item *deliveryItem) bool { return item.metadata.DestinationGeneration == generation })
}
func (c *Client) cancelDestinationMatching(did uuid.UUID, match func(*deliveryItem) bool) {
	c.queuesMu.RLock()
	q := c.queues[did]
	c.queuesMu.RUnlock()
	if q == nil {
		return
	}
	var cancels []context.CancelFunc
	q.mu.Lock()
	for e := q.items[1].Front(); e != nil; e = e.Next() {
		item := e.Value.(*deliveryItem)
		if match(item) {
			item.canceled.Store(true)
			if item.cancel != nil {
				cancels = append(cancels, item.cancel)
			}
		}
	}
	q.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	q.signal()
}

func (c *Client) CloseCall(ctx context.Context, identity li.DeliveryCallIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.gateMu.Lock()
	if !c.acceptedCalls[identity] {
		c.gateMu.Unlock()
		return nil
	}
	c.closedCalls[identity] = true
	c.gateMu.Unlock()
	if c.x3Journal == nil {
		c.gateMu.Lock()
		delete(c.acceptedCalls, identity)
		c.gateMu.Unlock()
		return nil
	}
	if err := c.x3Journal.Flush(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	out, err := c.x3Journal.CloseCall(identity)
	if err != nil {
		return err
	}
	if out != securestore.Committed {
		return fmt.Errorf("call closure is not durable")
	}
	c.gateMu.Lock()
	delete(c.acceptedCalls, identity)
	c.gateMu.Unlock()
	return ctx.Err()
}
func (c *Client) CloseCapture(ctx context.Context, callID string, generation uint64, incarnation uuid.UUID) error {
	c.gateMu.RLock()
	var identities []li.DeliveryCallIdentity
	for identity := range c.acceptedCalls {
		if identity.CallID == callID && identity.CallGeneration == generation && identity.CallIncarnation == incarnation {
			identities = append(identities, identity)
		}
	}
	c.gateMu.RUnlock()
	for _, identity := range identities {
		if err := c.CloseCall(ctx, identity); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) CloseAllCaptures(ctx context.Context) error {
	c.gateMu.RLock()
	identities := make([]li.DeliveryCallIdentity, 0, len(c.acceptedCalls))
	for identity := range c.acceptedCalls {
		identities = append(identities, identity)
	}
	c.gateMu.RUnlock()
	for _, identity := range identities {
		if err := c.CloseCall(ctx, identity); err != nil {
			return err
		}
	}
	return nil
}
