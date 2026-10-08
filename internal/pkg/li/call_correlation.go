//go:build li

package li

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

const correlationMaxValue = 4096

// CallCorrelationTask identifies an admitted task incarnation, not a target.
// Grouping is never evidence of authorization.
type CallCorrelationTask struct {
	StateIncarnation uuid.UUID `json:"state_incarnation"`
	XID              uuid.UUID `json:"xid"`
	Generation       uint64    `json:"generation"`
}

// CallCorrelationDecision is immutable once reserved. Publication updates
// accounting and activity only; even a failed dispatch cannot select another ID.
type CallCorrelationDecision struct {
	CallID        string
	CorrelationID uint64
	Rule          string
	Reason        string
	token         uint64
}

type CallCorrelationPersistence interface {
	Load() ([]StoredCallCorrelation, error)
	Save([]StoredCallCorrelation) (securestore.Outcome, error)
	Close() error
}

type correlationRecord struct {
	decision  CallCorrelationDecision
	last      time.Time
	terminal  time.Time
	published bool
	group     *correlationGroup
	ready     chan struct{}
	deferred  []correlationDeferred
}
type correlationDeferred struct {
	ctx    context.Context
	fn     func(CallCorrelationDecision)
	bytes  int
	queued bool
}

type correlationGroup struct {
	id      uint64
	tasks   map[CallCorrelationTask]bool
	members int
	pending bool
}
type correlationCandidate struct {
	transaction, callID, source, destination, calling, called string
	started, expires                                          time.Time
	group                                                     *correlationGroup
	headers                                                   map[string]string
	final                                                     bool
	finalAt                                                   time.Time
	originKeys                                                []sdpOriginHistoryKey
	originGenerations                                         map[sdpOriginHistoryKey]uint64
	origin                                                    *sdpOrigin
	role                                                      sdpOriginRole
}
type correlationTransaction struct {
	expires      time.Time
	candidate    *correlationCandidate
	offer        bool
	requestSeen  bool
	delayedOffer bool
}

// CallCorrelationStats contains aggregate observations only.
type CallCorrelationStats struct {
	Adopted                                                      map[string]uint64
	Standalone                                                   map[string]uint64
	SDP                                                          map[string]uint64
	Records, Candidates, Transactions, Origins, SuspendedOrigins int
	GroupsTwo, GroupsThree, GroupsFourOrMore                     int
	MaxRecords, MaxCandidates, MaxOrigins                        int
	Blind                                                        bool
	BlindCause                                                   string
	BlindRemaining                                               time.Duration
	Persistence                                                  bool
	UncertainWrites, UnresolvedWrites                            uint64
	UnrecordedDecisions                                          uint64
	SDPDisabled                                                  bool
	DeferredPackets, DeferredBytes                               int
	DeferredRejected                                             uint64
}

// CallCorrelator serializes decisions, indexes and group intersections under one
// lock. It never invokes registry/admission APIs while holding this lock.
type CallCorrelator struct {
	mu                             sync.Mutex
	writeMu                        sync.Mutex
	revision                       uint64
	persistedDigest                [32]byte
	stop                           chan struct{}
	stopOnce                       sync.Once
	asyncWG                        sync.WaitGroup
	deferredPackets, deferredBytes int
	config                         CallCorrelationConfig
	lifetime                       time.Duration
	now                            func() time.Time
	store                          CallCorrelationPersistence
	records                        map[string]*correlationRecord
	groups                         map[uint64]*correlationGroup
	candidates                     map[string]*correlationCandidate
	transactions                   map[string]correlationTransaction
	headerIndex                    map[string]map[string]*correlationCandidate
	addressIndex                   map[string]map[string]*correlationCandidate
	numberIndex                    map[string]map[string]*correlationCandidate
	originIndex                    map[sdpOriginHistoryKey]map[string]*correlationCandidate
	aliases                        map[string]string
	history                        *sdpOriginHistory
	blindUntil                     time.Time
	blindCause                     string
	serial                         uint64
	dirty, uncertain, closed       bool
	closing                        bool
	lastStorageWarning             time.Time
	stats                          CallCorrelationStats
}

func NewCallCorrelator(config CallCorrelationConfig, lifetime time.Duration, store CallCorrelationPersistence) (*CallCorrelator, error) {
	config = config.Normalized()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if lifetime <= 0 {
		return nil, errors.New("LI call correlation requires a positive call lifetime")
	}
	c := &CallCorrelator{config: config, lifetime: lifetime, now: time.Now, store: store,
		groups: map[uint64]*correlationGroup{}, records: map[string]*correlationRecord{}, candidates: map[string]*correlationCandidate{}, transactions: map[string]correlationTransaction{},
		headerIndex: map[string]map[string]*correlationCandidate{}, addressIndex: map[string]map[string]*correlationCandidate{}, numberIndex: map[string]map[string]*correlationCandidate{}, originIndex: map[sdpOriginHistoryKey]map[string]*correlationCandidate{}, aliases: map[string]string{}, history: newSDPOriginHistory(config),
		stop: make(chan struct{}), stats: CallCorrelationStats{Adopted: map[string]uint64{}, Standalone: map[string]uint64{}, SDP: map[string]uint64{}}}
	for i, set := range config.NodeAliases {
		for _, value := range set {
			addr, _ := netip.ParseAddr(value)
			c.aliases[addr.Unmap().String()] = fmt.Sprintf("alias:%d", i)
		}
	}
	c.blindUntil = c.now().Add(config.DecisionHorizon)
	c.blindCause = "start"
	if store != nil {
		entries, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("restore LI correlation decisions: %w", err)
		}
		c.persistedDigest = correlationSnapshotDigest(entries)
		groups := c.groups
		now := c.now()
		for _, e := range entries {
			if !e.TerminalUntil.IsZero() && !now.Before(e.TerminalUntil) || now.Sub(e.LastActivity) >= lifetime {
				c.markDirty()
				continue
			}
			g := groups[e.GroupID]
			if g == nil {
				g = &correlationGroup{id: e.GroupID, tasks: taskSet(e.CommonTasks)}
				groups[e.GroupID] = g
			} else {
				g.tasks = intersectCorrelationTasks(g.tasks, taskSet(e.CommonTasks))
			}
			c.serial++
			g.members++
			c.records[e.CallID] = &correlationRecord{decision: CallCorrelationDecision{CallID: e.CallID, CorrelationID: e.GroupID, Rule: "restored", token: c.serial}, last: e.LastActivity, terminal: e.TerminalUntil, published: true, group: g}
		}
	}
	return c, nil
}

func taskSet(tasks []CallCorrelationTask) map[CallCorrelationTask]bool {
	out := map[CallCorrelationTask]bool{}
	if len(tasks) > maxCallCorrelationStoredTasks {
		return out
	}
	for _, t := range tasks {
		if t.XID != uuid.Nil && t.Generation != 0 {
			out[t] = true
		}
	}
	return out
}
func intersectCorrelationTasks(a, b map[CallCorrelationTask]bool) map[CallCorrelationTask]bool {
	out := map[CallCorrelationTask]bool{}
	for t := range a {
		if b[t] {
			out[t] = true
		}
	}
	return out
}
func hashCorrelationCallID(callID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(callID))
	return h.Sum64()
}
func (c *CallCorrelator) address(value string) string {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Zone() != "" {
		return ""
	}
	value = a.Unmap().String()
	if alias := c.aliases[value]; alias != "" {
		return alias
	}
	return value
}

// correlationIdentity compares the complete extracted identity, preserving its
// user/number and folding only the DNS host. It never uses phone suffixes or
// operator-specific number rewrites.
func correlationIdentity(header string) string {
	if len(header) > correlationMaxValue {
		return ""
	}
	value := extractHeaderURI(header)
	if strings.ContainsAny(value, " \t\r\n\x00") {
		return ""
	}
	if user, host, ok := strings.Cut(value, "@"); ok {
		if user == "" || host == "" {
			return ""
		}
		value = user + "@" + strings.ToLower(host)
	}
	return value
}

func indexCandidate(index map[string]map[string]*correlationCandidate, key string, v *correlationCandidate) {
	if key == "" {
		return
	}
	if index[key] == nil {
		index[key] = map[string]*correlationCandidate{}
	}
	index[key][v.transaction] = v
}
func removeCandidateIndex(index map[string]map[string]*correlationCandidate, key, tx string) {
	delete(index[key], tx)
	if len(index[key]) == 0 {
		delete(index, key)
	}
}
func headerCorrelationKey(name, value string) string { return name + "\x00" + value }
func numberCorrelationKey(from, to string) string {
	if from == "" || to == "" {
		return ""
	}
	return from + "\x00" + to
}

func (c *CallCorrelator) addCandidate(v *correlationCandidate) {
	if old := c.candidates[v.transaction]; old != nil {
		c.removeCandidate(old)
	}
	c.candidates[v.transaction] = v
	for n, k := range v.headers {
		indexCandidate(c.headerIndex, headerCorrelationKey(n, k), v)
	}
	if v.source != "" && v.destination != "" {
		indexCandidate(c.addressIndex, v.destination, v)
		indexCandidate(c.addressIndex, v.source, v)
	}
	indexCandidate(c.numberIndex, numberCorrelationKey(v.calling, v.called), v)
	if v.origin != nil && v.role != sdpOriginUnknown {
		key := sdpOriginHistoryKey{Origin: *v.origin, Role: v.role}
		if c.originIndex[key] == nil {
			c.originIndex[key] = map[string]*correlationCandidate{}
		}
		c.originIndex[key][v.transaction] = v
		v.originKeys = append(v.originKeys, key)
	}
}
func (c *CallCorrelator) removeCandidate(v *correlationCandidate) {
	delete(c.candidates, v.transaction)
	for n, k := range v.headers {
		removeCandidateIndex(c.headerIndex, headerCorrelationKey(n, k), v.transaction)
	}
	removeCandidateIndex(c.addressIndex, v.destination, v.transaction)
	removeCandidateIndex(c.addressIndex, v.source, v.transaction)
	removeCandidateIndex(c.numberIndex, numberCorrelationKey(v.calling, v.called), v.transaction)
	for _, key := range v.originKeys {
		delete(c.originIndex[key], v.transaction)
		if len(c.originIndex[key]) == 0 {
			delete(c.originIndex, key)
		}
	}
}

func (c *CallCorrelator) expire(now time.Time) {
	for _, v := range c.candidates {
		if !c.candidateLive(v, now) {
			c.removeCandidate(v)
		}
	}
	for k, v := range c.transactions {
		if !now.Before(v.expires) {
			delete(c.transactions, k)
		}
	}
	for k := range c.records {
		c.expireRecord(k, now)
	}
	c.history.Expire(now)
}

func correlationTx(pkt *types.PacketDisplay) (string, bool) {
	v := pkt.VoIPData
	if v == nil || v.IsRTP || v.ViaBranch == "" || len(v.ViaBranch) > correlationMaxValue || len(v.FromTag) > correlationMaxValue {
		return "", false
	}
	number, method, valid := correlationCSeq(pkt)
	if !valid || method != "INVITE" {
		return "", false
	}
	if v.Status == 0 && v.Method == "INVITE" && v.ToTag == "" || v.Status > 0 {
		return fmt.Sprintf("%s\x00%s\x00%s\x00%d", v.CallID, v.FromTag, v.ViaBranch, number), true
	}
	return "", false
}

// Resolve conservatively reserves an immutable decision before encoding. The
// returned value is packet-scoped and can be shared safely across task fan-out.
func (c *CallCorrelator) Resolve(pkt *types.PacketDisplay, tasks []CallCorrelationTask) CallCorrelationDecision {
	d, err := c.ResolveContext(context.Background(), pkt, tasks)
	if err != nil {
		return CallCorrelationDecision{Reason: "closed"}
	}
	return d
}

// ResolveContext allows a waiting packet to be canceled without changing the
// reserved decision. Store ownership remains serialized until its write returns.
func (c *CallCorrelator) ResolveContext(ctx context.Context, pkt *types.PacketDisplay, tasks []CallCorrelationTask) (CallCorrelationDecision, error) {
	for {
		select {
		case <-ctx.Done():
			return CallCorrelationDecision{}, ctx.Err()
		case <-c.stop:
			return CallCorrelationDecision{}, errors.New("LI correlation closed")
		default:
		}
		c.mu.Lock()
		if c.closing {
			c.mu.Unlock()
			return CallCorrelationDecision{}, errors.New("LI correlation closed")
		}
		if pkt != nil && pkt.VoIPData != nil {
			if r := c.records[pkt.VoIPData.CallID]; r != nil && r.ready != nil {
				ready := r.ready
				c.mu.Unlock()
				select {
				case <-ready:
					continue
				case <-ctx.Done():
					return CallCorrelationDecision{}, ctx.Err()
				case <-c.stop:
					return CallCorrelationDecision{}, errors.New("LI correlation closed")
				}
			}
		}
		decision := c.resolveLocked(pkt, tasks, nil)
		if err := ctx.Err(); err != nil {
			return CallCorrelationDecision{}, err
		}
		return decision, nil
	}
}

// ResolveAsync keeps a storage reservation off the packet pipeline. Pending
// packets are bounded by candidate count and the existing snapshot byte bound.
// Callers must supply immutable packet/task snapshots to the completion callback.
func (c *CallCorrelator) ResolveAsync(ctx context.Context, pkt *types.PacketDisplay, tasks []CallCorrelationTask, bytes int, fn func(CallCorrelationDecision)) error {
	if fn == nil || bytes < 0 {
		return errors.New("invalid LI correlation deferred packet")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return errors.New("LI correlation closed")
	}

	deferred := correlationDeferred{ctx: ctx, fn: fn, bytes: bytes}
	if pkt != nil && pkt.VoIPData != nil {
		if r := c.records[pkt.VoIPData.CallID]; r != nil && r.ready != nil {
			// Retain signaling evidence at arrival even when publication waits or
			// the bounded delivery handoff rejects this packet. Never reselect ID.
			c.observeKnown(pkt, r, c.now())
			if !c.deferredCapacity(bytes) {
				c.stats.DeferredRejected++
				c.mu.Unlock()
				return errors.New("LI correlation deferred packet capacity exhausted")
			}
			c.enqueueDeferred(r, deferred)
			c.mu.Unlock()
			return nil
		}
	}
	decision := c.resolveLocked(pkt, tasks, &deferred)
	if !deferred.queued && ctx.Err() == nil {
		fn(decision)
	}
	return nil
}
func (c *CallCorrelator) deferredCapacity(bytes int) bool {
	return bytes <= maxCallCorrelationStoreBytes && c.deferredPackets < c.config.MaxCandidates && c.deferredBytes <= maxCallCorrelationStoreBytes-bytes
}
func (c *CallCorrelator) enqueueDeferred(r *correlationRecord, packet correlationDeferred) {
	r.deferred = append(r.deferred, packet)
	c.deferredPackets++
	c.deferredBytes += packet.bytes
}
func (c *CallCorrelator) drainDeferred(r *correlationRecord) {
	for {
		c.mu.Lock()
		if len(r.deferred) == 0 {
			close(r.ready)
			r.ready = nil
			c.mu.Unlock()
			return
		}
		packet := r.deferred[0]
		r.deferred[0] = correlationDeferred{}
		r.deferred = r.deferred[1:]
		decision, closing := r.decision, c.closing
		c.mu.Unlock()
		if !closing && packet.ctx.Err() == nil {
			packet.fn(decision)
		}
		c.mu.Lock()
		c.deferredPackets--
		c.deferredBytes -= packet.bytes
		c.mu.Unlock()
	}
}

// resolveLocked always releases mu, including across storage I/O.
func (c *CallCorrelator) resolveLocked(pkt *types.PacketDisplay, tasks []CallCorrelationTask, deferred *correlationDeferred) CallCorrelationDecision {
	defer c.mu.Unlock()
	if pkt == nil || pkt.VoIPData == nil || pkt.VoIPData.CallID == "" {
		return CallCorrelationDecision{}
	}
	callID := pkt.VoIPData.CallID
	own := hashCorrelationCallID(callID)
	now := c.now()
	c.expireRecord(callID, now)
	if r := c.records[callID]; r != nil {
		c.observeKnown(pkt, r, now)
		return r.decision
	}
	result := CallCorrelationDecision{CallID: callID, CorrelationID: own, Reason: "no_candidate"}
	if c.closed || len(callID) > correlationMaxValue || !validCorrelationParentID(callID) {
		result.Reason = "invalid"
		return result
	}
	if len(c.records) >= c.config.MaxRecords {
		c.blindUntil = now.Add(c.config.DecisionHorizon)
		c.blindCause = "record_limit"
		result.Reason = "record_limit"
		c.stats.UnrecordedDecisions++
		return result
	}
	tx, eligible := correlationTx(pkt)
	if pkt.VoIPData.Status > 0 {
		t, known := c.transactions[tx]
		eligible = eligible && known && t.requestSeen && now.Before(t.expires)
	}
	if t, known := c.transactions[tx]; known && now.Before(t.expires) {
		eligible = false
	}
	if len(c.transactions) >= c.config.MaxCandidates {
		eligible = false
		result.Reason = "candidate_limit"
	}
	headers, invalid := correlationSessionKeys(pkt, c.config.SessionHeaders)
	incoming := taskSet(tasks)
	source, destination := c.address(pkt.SrcIP), c.address(pkt.DstIP)
	if pkt.VoIPData.Status > 0 {
		source, destination = destination, source
	}
	started := pkt.Timestamp
	if started.IsZero() {
		started = now
	}
	candidateTTL := max(c.config.AddressWindow, c.config.NumberWindow)
	if len(c.config.SessionHeaders) > 0 || c.config.SDPOriginMatching {
		candidateTTL = c.lifetime
	}
	v := &correlationCandidate{transaction: tx, callID: callID, source: source, destination: destination, calling: correlationIdentity(pkt.VoIPData.From), called: correlationIdentity(pkt.VoIPData.To), started: started, expires: now.Add(candidateTTL), headers: headers, final: pkt.VoIPData.Status >= 200}
	if v.final {
		v.finalAt = started
	}
	if eligible && c.config.SDPOriginMatching {
		c.observeOrigin(pkt, v, now)
	}
	var group *correlationGroup
	if !now.Before(c.blindUntil) && eligible && len(incoming) > 0 {
		if invalid {
			result.Reason = "conflicting_exact"
		} else {
			group, result.Rule, result.Reason = c.match(pkt, v, incoming, now)
		}
	} else if now.Before(c.blindUntil) {
		result.Reason = "blind_period"
	} else if !eligible && result.Reason != "candidate_limit" {
		result.Reason = "not_eligible"
	}
	var oldTasks map[CallCorrelationTask]bool
	var persist bool
	if group != nil {
		if c.store != nil && deferred != nil && !c.deferredCapacity(deferred.bytes) {
			group = nil
			result.Rule = ""
			result.Reason = "deferred_limit"
		} else if c.store != nil && !c.writeMu.TryLock() {
			group = nil
			result.Rule = ""
			result.Reason = "persistence_busy"
		} else {
			persist = c.store != nil
			result.CorrelationID = group.id
			oldTasks = group.tasks
			group.tasks = intersectCorrelationTasks(group.tasks, incoming)
			group.pending = persist
			c.markDirty()
		}
	}

	if group == nil {
		group = c.groups[own]
		if group == nil {
			group = &correlationGroup{id: own, tasks: incoming}
			c.groups[own] = group
		} else {
			// A restored child retains its original root's ID. Seeing that root
			// again must not create a broader, independent task context for the
			// same communication. Empty intersections retain IDs but admit nobody.
			group.tasks = intersectCorrelationTasks(group.tasks, incoming)
			c.markDirty()
		}
		result.Rule = ""
	} else {
		result.Reason = ""
	}
	c.serial++
	result.token = c.serial
	r := &correlationRecord{decision: result, last: now, group: group}
	group.members++
	c.records[callID] = r
	if eligible && len(c.candidates) < c.config.MaxCandidates {
		v.group = group
		c.addCandidate(v)
		c.transactions[tx] = correlationTransaction{expires: now.Add(c.config.DecisionHorizon), candidate: v, offer: v.role == sdpOriginOffer, requestSeen: pkt.VoIPData.Status == 0}
	}
	if persist {
		r.ready = make(chan struct{})
		c.markDirty()
		snapshot, revision, uncertain := c.stored(), c.revision, c.uncertain
		write := func() CallCorrelationDecision {
			out, err := securestore.NotCommitted, error(nil)
			if uncertain {
				if owner, ok := c.store.(interface{ Reconcile() error }); ok {
					err = owner.Reconcile()
				}
			}
			if err == nil {
				out, err = c.store.Save(snapshot)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if out == securestore.NotCommitted {
				group.tasks = intersectCorrelationTasks(oldTasks, group.tasks)
				group.members--
				if group.members == 0 {
					delete(c.groups, group.id)
				}
				standalone := c.groups[own]
				if standalone == nil {
					standalone = &correlationGroup{id: own, tasks: incoming}
					c.groups[own] = standalone
				}
				standalone.members++
				r.group = standalone
				result.CorrelationID, result.Rule, result.Reason = own, "", "persistence_not_committed"
				r.decision = result
				v.group = standalone
				c.markDirty()
			} else if out == securestore.Uncertain || err != nil {
				c.uncertain = true
				c.markDirty()
				c.stats.UncertainWrites++
			} else {
				c.persistedDigest = correlationSnapshotDigest(snapshot)
				if revision == c.revision {
					c.dirty = false
				}
				c.uncertain = false
			}
			group.pending = false
			r.last = c.now()
			if r.decision.CorrelationID != own {
				c.markDirty()
			}
			if deferred == nil {
				close(r.ready)
				r.ready = nil
			}
			c.writeMu.Unlock()
			if err != nil || out != securestore.Committed {
				if c.lastStorageWarning.IsZero() || now.Sub(c.lastStorageWarning) >= time.Minute {
					logger.Warn("LI call correlation adopted decision persistence failed", "outcome", securestore.OutcomeName(out))
					c.lastStorageWarning = now
				}
			}
			return result
		}
		if deferred != nil {
			deferred.queued = true
			c.enqueueDeferred(r, *deferred)
			c.asyncWG.Add(1)
			go func() {
				defer c.asyncWG.Done()
				c.mu.Lock()
				c.mu.Unlock()
				// The reservation snapshot was captured before the decision mutex releases.
				write()
				c.drainDeferred(r)
			}()
			return result
		}
		c.mu.Unlock()
		result = write()
		c.mu.Lock()

	}

	return result
}

func correlationTaskSlice(m map[CallCorrelationTask]bool) []CallCorrelationTask {
	out := make([]CallCorrelationTask, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StateIncarnation != out[j].StateIncarnation {
			return out[i].StateIncarnation.String() < out[j].StateIncarnation.String()
		}
		if out[i].XID == out[j].XID {
			return out[i].Generation < out[j].Generation
		}
		return out[i].XID.String() < out[j].XID.String()
	})
	return out
}
func (c *CallCorrelator) stored() []StoredCallCorrelation {
	out := []StoredCallCorrelation{}
	for id, r := range c.records {
		if r.decision.CorrelationID != hashCorrelationCallID(id) {
			out = append(out, StoredCallCorrelation{CallID: id, GroupID: r.group.id, LastActivity: r.last, TerminalUntil: r.terminal, CommonTasks: correlationTaskSlice(r.group.tasks)})
		}
	}
	return out
}

// Canonical order makes equivalent snapshots comparable without retaining a
// second full copy of content-bearing state. Length framing prevents collisions
// between fields; timestamps retain their full seconds and nanoseconds.
func correlationSnapshotDigest(records []StoredCallCorrelation) [32]byte {
	sort.Slice(records, func(i, j int) bool { return records[i].CallID < records[j].CallID })
	digest := sha256.New()
	var encoded [8]byte
	number := func(value uint64) { binary.BigEndian.PutUint64(encoded[:], value); _, _ = digest.Write(encoded[:]) }
	timestamp := func(value time.Time) { number(uint64(value.Unix())); number(uint64(value.Nanosecond())) }
	for _, record := range records {
		number(uint64(len(record.CallID)))
		_, _ = digest.Write([]byte(record.CallID))
		number(record.GroupID)
		timestamp(record.LastActivity)
		timestamp(record.TerminalUntil)
		tasks := correlationTaskSlice(taskSet(record.CommonTasks))
		number(uint64(len(tasks)))
		for _, task := range tasks {
			_, _ = digest.Write(task.StateIncarnation[:])
			_, _ = digest.Write(task.XID[:])
			number(task.Generation)
		}
	}
	var sum [32]byte
	copy(sum[:], digest.Sum(nil))
	return sum
}

func (c *CallCorrelator) observeOrigin(pkt *types.PacketDisplay, v *correlationCandidate, now time.Time) {
	body, hasSDP := correlationSDPBody(pkt)
	if hasSDP && pkt.VoIPData.Status == 0 && pkt.VoIPData.Method == "INVITE" {
		v.role = sdpOriginOffer
	} else {
		v.role = sdpOriginUnknown
	}
	parsed, ok := parseCorrelationSDPOrigin(body)
	if !hasSDP || !ok {
		c.stats.SDP["no_or_invalid_origin"]++
		return
	}
	v.origin = &parsed.Identity
	if !c.history.Observe(parsed.Identity, v.role, v.transaction, v.started, now, v.headers) {
		c.stats.SDP["unusable"]++
	}
	key := sdpOriginHistoryKey{Origin: parsed.Identity, Role: v.role}
	v.originGenerations = map[sdpOriginHistoryKey]uint64{key: c.history.Generation(parsed.Identity, v.role, now)}
}
func (c *CallCorrelator) observeKnown(pkt *types.PacketDisplay, r *correlationRecord, now time.Time) {
	tx, eligible := correlationTx(pkt)
	if !eligible {
		if c.config.SDPOriginMatching {
			if _, t, known := c.delayedAnswerTransaction(pkt); known {
				if body, hasSDP := correlationSDPBody(pkt); hasSDP {
					if parsed, valid := parseCorrelationSDPOrigin(body); valid {
						c.observeRoleOrigin(t.candidate, parsed.Identity, sdpOriginAnswer, now)
					}
				}
			}
		}
		return
	}
	t, known := c.transactions[tx]
	known = known && now.Before(t.expires)
	if known && t.candidate != nil && pkt.VoIPData.Status >= 200 {
		t.candidate.final = true
		if t.candidate.finalAt.IsZero() {
			t.candidate.finalAt = pkt.Timestamp
			if t.candidate.finalAt.IsZero() {
				t.candidate.finalAt = now
			}
		}
	}
	if c.config.SDPOriginMatching && known && t.candidate != nil {
		body, hasSDP := correlationSDPBody(pkt)
		request := pkt.VoIPData.Status == 0 && pkt.VoIPData.Method == "INVITE" && pkt.VoIPData.ToTag == ""
		if request {
			t.requestSeen = true
		}
		// Only an observed initial request establishes whether a response carries
		// the answer or a delayed offer. Response-only captures stay unknown.
		role := sdpOriginUnknown
		if hasSDP && request {
			role = sdpOriginOffer
			t.offer = true
			t.delayedOffer = false
		} else if hasSDP && pkt.VoIPData.Status > 0 && t.requestSeen {
			if t.offer {
				role = sdpOriginAnswer
			} else {
				role = sdpOriginOffer
				t.delayedOffer = pkt.VoIPData.Status >= 200 && pkt.VoIPData.Status < 300
			}
		}
		c.transactions[tx] = t
		if hasSDP {
			if parsed, valid := parseCorrelationSDPOrigin(body); valid {
				c.observeRoleOrigin(t.candidate, parsed.Identity, role, now)
			}
		}
	}
	if !known && pkt.VoIPData.Status == 0 && pkt.VoIPData.Method == "INVITE" && pkt.VoIPData.ToTag == "" && len(c.transactions) < c.config.MaxCandidates {
		v := &correlationCandidate{transaction: tx, started: pkt.Timestamp, headers: map[string]string{}}
		v.headers, _ = correlationSessionKeys(pkt, c.config.SessionHeaders)
		if v.started.IsZero() {
			v.started = now
		}
		if c.config.SDPOriginMatching {
			c.observeOrigin(pkt, v, now)
		}
		c.transactions[tx] = correlationTransaction{expires: now.Add(c.config.DecisionHorizon), requestSeen: true, offer: v.role == sdpOriginOffer}
	}
}

func (c *CallCorrelator) match(pkt *types.PacketDisplay, v *correlationCandidate, tasks map[CallCorrelationTask]bool, now time.Time) (*correlationGroup, string, string) {
	trusted := map[*correlationGroup]bool{}
	for n, k := range v.headers {
		for _, candidate := range c.headerIndex[headerCorrelationKey(n, k)] {
			if c.candidateLive(candidate, now) && candidate.callID != v.callID && candidate.group != nil {
				if candidate.group.pending {
					return nil, "", "persistence_busy"
				}
				if len(intersectCorrelationTasks(candidate.group.tasks, tasks)) == 0 {
					return nil, "", "ineligible_exact"
				}
				if correlationHeaderConflict(candidate.headers, v.headers) {
					return nil, "", "conflicting_exact"
				}
				trusted[candidate.group] = true
			}
		}
	}
	parent, hasParent, parentInvalid := correlationParent(pkt, c.config.ParentCallIDHeaders)
	if parentInvalid || parent == v.callID {
		return nil, "", "invalid_parent"
	}
	if hasParent {
		r := c.records[parent]
		if r == nil || !c.recordLive(r, now) {
			return nil, "", "unresolved_parent"
		}
		if r.group.pending {
			return nil, "", "persistence_busy"
		}
		if len(intersectCorrelationTasks(r.group.tasks, tasks)) == 0 {
			return nil, "", "ineligible_parent"
		}
		for _, p := range c.candidates {
			if p.group == r.group && correlationHeaderConflict(p.headers, v.headers) {
				return nil, "", "conflicting_exact"
			}
		}
		trusted[r.group] = true
	}
	if len(trusted) > 1 {
		return nil, "", "conflicting_exact"
	}
	for g := range trusted {
		if hasParent {
			return g, "P", ""
		}
		return g, "H", ""
	}
	if c.config.SDPOriginMatching && v.origin != nil && c.history.Usable(*v.origin, v.role, now) {
		groups := map[*correlationGroup]bool{}
		key := sdpOriginHistoryKey{Origin: *v.origin, Role: v.role}
		for _, candidate := range c.originIndex[key] {
			if v.originGenerations[key] != 0 && candidate.originGenerations[key] == v.originGenerations[key] && c.allowed(candidate, v, tasks) {
				groups[candidate.group] = true
			}
		}
		if len(groups) == 1 {
			for g := range groups {
				c.stats.SDP["match"]++
				return g, "S", ""
			}
		}
		if len(groups) > 1 {
			c.stats.SDP["ambiguous"]++
		} else {
			c.stats.SDP["miss"]++
		}
	}
	addressCandidates := map[string]*correlationCandidate{}
	for _, key := range []string{v.source, v.destination} {
		for tx, p := range c.addressIndex[key] {
			if !c.allowed(p, v, tasks) {
				continue
			}
			adjacent := p.destination == v.source && v.started.Sub(p.started) >= 0 && v.started.Sub(p.started) <= c.config.AddressWindow || v.destination == p.source && p.started.Sub(v.started) >= 0 && p.started.Sub(v.started) <= c.config.AddressWindow
			if adjacent && correlationSetupOverlaps(p, v) {
				addressCandidates[tx] = p
			}
		}
	}
	matching := map[*correlationGroup]bool{}
	for _, p := range addressCandidates {
		if v.called != "" && p.called == v.called {
			matching[p.group] = true
		}
	}
	if c.config.AddressChaining && len(matching) > 0 {
		if len(matching) > 1 {
			return nil, "", "ambiguous"
		}
		for g := range matching {
			return g, "R1", ""
		}
	}
	if c.config.NumberChaining && len(addressCandidates) == 0 {
		groups := map[*correlationGroup]bool{}
		for _, p := range c.numberIndex[numberCorrelationKey(v.calling, v.called)] {
			if c.allowed(p, v, tasks) && absCorrelationDuration(v.started.Sub(p.started)) <= c.config.NumberWindow {
				groups[p.group] = true
			}
		}
		if len(groups) > 1 {
			return nil, "", "ambiguous"
		}
		for g := range groups {
			return g, "R2", ""
		}
	}
	if c.config.AddressChainingRewritten && len(matching) == 0 {
		if len(addressCandidates) > 1 {
			return nil, "", "ambiguous"
		}
		for _, p := range addressCandidates {
			return p.group, "R1_rewritten", ""
		}
	}
	return nil, "", "no_candidate"
}

func correlationSetupOverlaps(a, b *correlationCandidate) bool {
	// Compare capture time, not observation arrival: a final response received
	// before a late capture batch must not invalidate a hop that started earlier.
	if a.started.Before(b.started) || a.started.Equal(b.started) {
		return a.finalAt.IsZero() || b.started.Before(a.finalAt)
	}
	return b.finalAt.IsZero() || a.started.Before(b.finalAt)
}

func absCorrelationDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
func correlationHeaderConflict(a, b map[string]string) bool {
	for k, v := range a {
		if other, ok := b[k]; ok && other != v {
			return true
		}
	}
	return false
}
func (c *CallCorrelator) allowed(p, v *correlationCandidate, tasks map[CallCorrelationTask]bool) bool {
	return c.candidateLive(p, c.now()) && p.callID != v.callID && p.group != nil && !p.group.pending && len(intersectCorrelationTasks(p.group.tasks, tasks)) > 0 && !correlationHeaderConflict(p.headers, v.headers)
}

// Published records entry into any deliverable queue/reorder/spool. A rejected
// later destination does not undo the first destination's publication.
func (c *CallCorrelator) Published(d CallCorrelationDecision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.records[d.CallID]
	if r == nil || r.decision.token != d.token {
		return
	}
	r.last = c.now()
	if !r.published {
		r.published = true
		if d.Rule != "" {
			c.stats.Adopted[d.Rule]++
		} else {
			c.stats.Standalone[d.Reason]++
		}
	}
	if d.CorrelationID != hashCorrelationCallID(d.CallID) {
		c.markDirty()
	}
}
func (c *CallCorrelator) Finalize(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.records[callID]; r != nil {
		if r.terminal.IsZero() {
			r.terminal = c.now().Add(c.config.TerminalGrace)
		}
		if r.decision.CorrelationID != hashCorrelationCallID(callID) {
			c.markDirty()
		}
	}
}
func (c *CallCorrelator) Maintain() error {
	if !c.writeMu.TryLock() {
		return nil
	}
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.expire(c.now())
	if c.store == nil || !c.dirty {
		c.mu.Unlock()
		return nil
	}
	snapshot, revision, uncertain := c.stored(), c.revision, c.uncertain
	if !uncertain && correlationSnapshotDigest(snapshot) == c.persistedDigest {
		c.dirty = false
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if uncertain {
		if owner, ok := c.store.(interface{ Reconcile() error }); ok {
			if err := owner.Reconcile(); err != nil {
				return fmt.Errorf("reconcile LI correlation storage: %w", err)
			}
		}
	}
	out, err := c.store.Save(snapshot)
	c.mu.Lock()
	defer c.mu.Unlock()
	if out == securestore.Committed && err == nil {
		c.persistedDigest = correlationSnapshotDigest(snapshot)
		if revision == c.revision {
			c.dirty = false
		}
		c.uncertain = false
		return nil
	}
	if out == securestore.Uncertain {
		c.uncertain = true
		c.stats.UncertainWrites++
	}
	return fmt.Errorf("persist LI correlation maintenance: %w", errors.Join(err, errors.New("correlation state not confirmed committed")))
}
func (c *CallCorrelator) Close() error {
	c.stopOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		close(c.stop)
		c.mu.Unlock()
	})
	// Wait only for the storage owner, never with the decision mutex held.
	c.writeMu.Lock()
	c.writeMu.Unlock()
	c.asyncWG.Wait()
	err := c.Maintain()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	if c.store != nil {
		return errors.Join(err, c.store.Close())
	}
	return err
}
func (c *CallCorrelator) markDirty() { c.revision++; c.dirty = true }
func (c *CallCorrelator) recordLive(r *correlationRecord, now time.Time) bool {
	return r.ready != nil || ((r.terminal.IsZero() || now.Before(r.terminal)) && now.Sub(r.last) < c.lifetime)
}
func (c *CallCorrelator) candidateLive(v *correlationCandidate, now time.Time) bool {
	r := c.records[v.callID]
	return now.Before(v.expires) && r != nil && c.recordLive(r, now)
}
func (c *CallCorrelator) expireRecord(id string, now time.Time) {
	r := c.records[id]
	if r == nil || c.recordLive(r, now) {
		return
	}
	delete(c.records, id)
	r.group.members--
	if r.group.members == 0 {
		delete(c.groups, r.group.id)
	}
	if r.decision.CorrelationID != hashCorrelationCallID(id) {
		c.markDirty()
	}
}

func copyCorrelationCounts(m map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
func (c *CallCorrelator) Stats() CallCorrelationStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.expire(now)
	s := c.stats
	s.Adopted = copyCorrelationCounts(s.Adopted)
	s.Standalone = copyCorrelationCounts(s.Standalone)
	s.SDP = copyCorrelationCounts(s.SDP)
	s.Records = len(c.records)
	s.Candidates = len(c.candidates)
	s.Transactions = len(c.transactions)
	hs := c.history.Stats(now)
	s.Origins = hs.Tracked
	s.SuspendedOrigins = hs.Suspended
	s.SDPDisabled = hs.Disabled
	s.MaxRecords = c.config.MaxRecords
	s.MaxCandidates = c.config.MaxCandidates
	s.MaxOrigins = c.config.SDPOriginMaxTracked
	s.Blind = now.Before(c.blindUntil)
	if s.Blind {
		s.BlindCause = c.blindCause
		s.BlindRemaining = c.blindUntil.Sub(now)
	}
	s.Persistence = c.store != nil
	s.DeferredPackets, s.DeferredBytes = c.deferredPackets, c.deferredBytes
	if c.uncertain {
		s.UnresolvedWrites = 1
	}
	groups := map[*correlationGroup]bool{}
	for _, r := range c.records {
		groups[r.group] = true
	}
	for g := range groups {
		if g.pending {
			s.UnresolvedWrites++
		}
		switch g.members {
		case 2:
			s.GroupsTwo++
		case 3:
			s.GroupsThree++
		default:
			if g.members >= 4 {
				s.GroupsFourOrMore++
			}
		}
	}
	return s
}
