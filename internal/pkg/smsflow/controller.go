// Package smsflow joins decoded SMS with capture selection. Protocol decoding
// and multipart assembly remain in sms; this adapter owns pending output only.
package smsflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sms"
)

// Config bounds assembly content and, only when keywords are configured,
// retained output. These are resource defaults, not performance requirements.
type Config struct {
	Keywords           []string
	Assembly           sms.Config
	MaxPendingMessages int
	MaxPendingBytes    int
}

// Entry has already passed baseline capture selection. Current revalidates that
// authority at release. Exactly one of Deliver or Discard is called per entry.
// Callbacks execute synchronously and must not reenter this controller.
// Size accounts for packet/envelope storage captured by the callbacks; the
// controller additionally charges its retained SIP and SMS result metadata.
type Entry struct {
	Result  pipeline.SIPResult
	Size    int
	Current func() bool
	Deliver func(pipeline.SIPResult) error
	Discard func()
}

type queuedEntry struct {
	Entry
	sequence uint64
}
type decision struct {
	start                    time.Time
	fingerprint              [32]byte
	known, allowed, rejected bool
	group, reference         string
	entries                  []queuedEntry
	responseFingerprint      [32]byte
	responseSeen             bool
}
type referenceDecision struct {
	start       time.Time
	transaction string
	ambiguous   bool
}

// Stats contains only counters and resource accounting, never message text.
type Stats struct {
	PendingMessages, PendingBytes, Transactions    int
	Rejected, Expired, ResourceLimited, Duplicates uint64
}

// Controller serializes bounded keyword decisions and output release. In
// disabled mode it assembles text but never buffers or suppresses output.
type Controller struct {
	mu           sync.Mutex
	config       Config
	matcher      *sms.Matcher
	assembler    *sms.Assembler
	transactions map[string]*decision
	references   map[string]referenceDecision
	controls     map[string][]string
	stats        Stats
	sequence     uint64
	closed       bool
	done         chan struct{}
}

// New constructs a controller. Empty keywords allocate no transaction cache.
func New(config Config) (*Controller, error) {
	matcher, err := sms.NewMatcher(config.Keywords)
	if err != nil {
		return nil, err
	}
	if config.MaxPendingMessages <= 0 {
		config.MaxPendingMessages = 4096
	}
	if config.MaxPendingBytes <= 0 {
		config.MaxPendingBytes = 16 << 20
	}
	if config.Assembly.Lifetime <= 0 {
		config.Assembly.Lifetime = 5 * time.Minute
	}
	c := &Controller{config: config, matcher: matcher, assembler: sms.NewAssembler(config.Assembly), done: make(chan struct{})}
	if matcher.Enabled() {
		c.transactions = make(map[string]*decision)
		c.references = make(map[string]referenceDecision)
		c.controls = make(map[string][]string)
	}
	return c, nil
}

// Enabled reports whether SMS keyword selection is configured.
func (c *Controller) Enabled() bool { return c != nil && c.matcher.Enabled() }

func hashStrings(fields ...string) string {
	var encoded []byte
	for _, field := range fields {
		encoded = strconv.AppendQuote(encoded, field)
		encoded = append(encoded, '|')
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Scope binds assembly and decision state to the producer/capture and SIP
// subscriber pair. It deliberately excludes Call-ID and transport endpoints.
func Scope(r pipeline.SIPResult) string {
	var source pipeline.SourceProvenance
	if r.Packet != nil {
		source = r.Packet.Source
	}
	parties := []string{sharedsip.URI(r.From), sharedsip.URI(r.To)}
	if r.FromURI != "" {
		parties[0] = r.FromURI
	}
	if r.ToURI != "" {
		parties[1] = r.ToURI
	}
	sort.Strings(parties)
	iface := source.InterfaceName
	input := source.InputFile
	interfaceIndex, argumentIndex := source.InterfaceIndex, source.ArgumentIndex
	if source.ObservationDomainKnown {
		iface = ""
		input = ""
		interfaceIndex, argumentIndex = 0, 0
	}
	return hashStrings(source.NodeID, source.ProducerSessionID, source.CaptureEpoch, iface, input, strconv.FormatUint(uint64(interfaceIndex), 10), strconv.FormatUint(uint64(argumentIndex), 10), strconv.FormatUint(uint64(source.ObservationDomain), 10), strconv.FormatBool(source.ObservationDomainKnown), strconv.FormatUint(source.CapturePolicyGeneration, 10), parties[0], parties[1])
}

// The TPDU contains the other SMS party only. A shared service centre and a
// short concatenation reference cannot identify an otherwise unknown mobile
// subscriber. Missing subscriber routing identity therefore prevents joining.
func assemblyScope(scope string, r pipeline.SIPResult) string {
	if r.SMS == nil {
		return scope
	}
	from, to := r.FromURI, r.ToURI
	if from == "" {
		from = sharedsip.URI(r.From)
	}
	if to == "" {
		to = sharedsip.URI(r.To)
	}
	if r.SMS.Direction == sms.DirectionMO && from == "" {
		return ""
	}
	if r.SMS.Direction == sms.DirectionMT && to == "" {
		return ""
	}
	if r.SMS.Direction != sms.DirectionMO && r.SMS.Direction != sms.DirectionMT {
		return ""
	}
	return scope
}

func transaction(scope string, r pipeline.SIPResult) string {
	from := r.FromURI
	if from == "" {
		from = sharedsip.URI(r.From)
	}
	return hashStrings(scope, r.CallID, strconv.FormatUint(r.CSeqNumber, 10), r.ViaBranch, from, r.FromTag)
}

func reference(scope string, m *sms.Message, control bool) string {
	direction := m.Direction
	if control {
		switch m.RPType {
		case 2, 4:
			direction = sms.DirectionMT
		case 3, 5:
			direction = sms.DirectionMO
		default:
			return "" // Status reports and SMMA are not acknowledgements of text.
		}
	}
	return hashStrings(scope, string(direction), strconv.Itoa(int(m.Reference)))
}

// contentFingerprint excludes assembly progress, which may legitimately change
// between upstream observations of the same original SIP transaction.
func contentFingerprint(r pipeline.SIPResult) [32]byte {
	if len(r.Body) > 0 {
		return sha256.Sum256(r.Body)
	}
	if r.SMS == nil {
		return sha256.Sum256([]byte(r.ContentType))
	}
	m := r.SMS
	fields := []string{m.Text, string(m.Status), string(m.Encoding), string(m.Direction), strconv.Itoa(int(m.RPType)), strconv.Itoa(int(m.TPType)), strconv.Itoa(int(m.Reference)), strconv.Itoa(int(m.DCS)), strconv.Itoa(int(m.PID)), m.From, m.To, string(m.Header)}
	if m.Concat != nil {
		fields = append(fields, "concat", strconv.Itoa(int(m.Concat.Reference)), strconv.Itoa(int(m.Concat.ReferenceBits)), strconv.Itoa(int(m.Concat.Total)), strconv.Itoa(int(m.Concat.Part)))
	}
	return sha256.Sum256([]byte(hashStrings(fields...)))
}

// Process returns true if at least one output was delivered now. Pending and
// rejected SMS return false without an error; counters distinguish those cases.
func (c *Controller) Process(entry Entry) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		discard(entry)
		return false, nil
	}
	r := entry.Result
	now := r.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	c.expire(now)
	if r.Method == "MESSAGE" && r.SMS == nil && sms.IsSMS(r.ContentType) {
		decoded, err := sms.Decode(r.Body)
		if err != nil && decoded == nil {
			decoded = &sms.Message{Status: sms.StatusMalformed}
		}
		r.SMS = decoded
	}
	scope := Scope(r)
	if !c.matcher.Enabled() {
		if r.SMS != nil {
			r.SMS = c.assembler.Add(assemblyScope(scope, r), r.SMS, now)
		}
		entry.Result = r
		return deliver(entry)
	}
	if r.Method != "MESSAGE" && r.CSeqMethod != "MESSAGE" {
		return deliver(entry)
	}
	key := transaction(scope, r)
	d := c.transactions[key]
	// Pager-mode requests are outside the predicate, including when the decision
	// cache is full. They still resolve an already retained response-first entry.
	if r.Method == "MESSAGE" && r.SMS == nil {
		if d == nil {
			d = c.newDecision(key, now)
		}
		if d == nil {
			return deliver(entry)
		}
		if d.known && d.fingerprint != contentFingerprint(r) {
			c.rejectGroup(d)
			discard(entry)
			return false, nil
		}
		d.known, d.allowed, d.fingerprint = true, true, contentFingerprint(r)
		forwarded, err := c.release([]*decision{d}, nil)
		ok, next := deliver(entry)
		return forwarded || ok, errors.Join(err, next)
	}
	if d == nil {
		d = c.newDecision(key, now)
		if d == nil {
			c.stats.ResourceLimited++
			discard(entry)
			return false, nil
		}
	}
	if r.Method != "MESSAGE" {
		entry.Result = r
		return c.response(d, entry)
	}
	if d.rejected {
		discard(entry)
		return false, nil
	}
	fingerprint := contentFingerprint(r)
	if d.known {
		if d.fingerprint != fingerprint {
			c.rejectGroup(d)
			discard(entry)
			return false, nil
		}
		c.stats.Duplicates++
		discard(entry)
		return false, nil
	}
	d.known, d.fingerprint = true, fingerprint
	// A supplied full assembly cannot prove that this capture policy admitted all
	// contributors. Enabled filtering assembles only locally eligible messages.
	suppliedStatus := r.SMS.Assembly.Status
	r.SMS = sms.Clone(r.SMS)
	r.SMS.Assembly = sms.AssemblyInfo{}
	r.SMS = c.assembler.Add(assemblyScope(scope, r), r.SMS, now)
	if suppliedStatus == sms.AssemblyConflict || suppliedStatus == sms.AssemblyExpired || suppliedStatus == sms.AssemblyResourceLimited {
		r.SMS.Assembly.Status = suppliedStatus
	}
	d.group = r.SMS.Assembly.ID
	entry.Result = r
	if !c.retain(d, entry) {
		c.rejectGroup(d)
		return false, nil
	}
	if r.SMS.Status == sms.StatusControl {
		return c.control(scope, key, d, r.SMS)
	}
	if r.SMS.Status != sms.StatusDecoded {
		c.rejectGroup(d)
		return false, nil
	}
	d.reference = reference(scope, r.SMS, false)
	c.registerReference(d.reference, key, now)
	if r.SMS.Concat != nil && r.SMS.Assembly.Status == sms.AssemblyPending {
		return false, nil
	}
	group := c.group(d)
	allowed := c.matcher.Match(r.SMS)
	for _, candidate := range group {
		if candidate.rejected {
			allowed = false
		}
	}
	if !allowed {
		for _, candidate := range group {
			c.reject(candidate)
		}
		c.rejectControls(group)
		return false, nil
	}
	// Collect associated controls before authority validation or any delivery.
	all := append([]*decision(nil), group...)
	for _, candidate := range group {
		all = append(all, c.associatedControls(candidate)...)
	}
	if !c.current(all) {
		for _, candidate := range all {
			c.reject(candidate)
		}
		return false, nil
	}
	for _, candidate := range all {
		candidate.allowed = true
	}
	return c.release(all, &r.SMS.Assembly)
}

func (c *Controller) newDecision(key string, now time.Time) *decision {
	if len(c.transactions) >= c.config.MaxPendingMessages {
		return nil
	}
	d := &decision{start: now}
	c.transactions[key] = d
	return d
}

func (c *Controller) group(d *decision) []*decision {
	if d.group == "" {
		return []*decision{d}
	}
	var group []*decision
	for _, candidate := range c.transactions {
		if candidate.group == d.group {
			group = append(group, candidate)
		}
	}
	return group
}
func (c *Controller) rejectGroup(d *decision) {
	group := c.group(d)
	for _, candidate := range group {
		c.reject(candidate)
	}
	c.rejectControls(group)
}

func (c *Controller) registerReference(rk, key string, now time.Time) {
	old, exists := c.references[rk]
	if !exists {
		c.references[rk] = referenceDecision{start: now, transaction: key}
		return
	}
	if old.transaction == key && !old.ambiguous {
		return
	}
	old.ambiguous = true
	c.references[rk] = old
	for _, controlKey := range c.controls[rk] {
		if control := c.transactions[controlKey]; control != nil {
			c.reject(control)
		}
	}
	delete(c.controls, rk)
}

func (c *Controller) associatedControls(d *decision) []*decision {
	if d.reference == "" {
		return nil
	}
	ref, ok := c.references[d.reference]
	if !ok || ref.ambiguous {
		return nil
	}
	var controls []*decision
	for _, key := range c.controls[d.reference] {
		if control := c.transactions[key]; control != nil && !control.rejected {
			controls = append(controls, control)
		}
	}
	delete(c.controls, d.reference)
	return controls
}
func (c *Controller) rejectControls(group []*decision) {
	for _, d := range group {
		for _, control := range c.associatedControls(d) {
			c.reject(control)
		}
	}
}

func (c *Controller) control(scope, key string, d *decision, m *sms.Message) (bool, error) {
	rk := reference(scope, m, true)
	if rk == "" {
		c.reject(d)
		return false, nil
	}
	d.reference = rk
	if ref, ok := c.references[rk]; ok {
		if ref.ambiguous {
			c.reject(d)
			return false, nil
		}
		if parent := c.transactions[ref.transaction]; parent != nil {
			if parent.rejected {
				c.reject(d)
				return false, nil
			}
			if parent.allowed {
				d.allowed = true
				return c.release([]*decision{d}, nil)
			}
		}
	}
	c.controls[rk] = append(c.controls[rk], key)
	return false, nil
}

func (c *Controller) response(d *decision, e Entry) (bool, error) {
	if d.rejected {
		discard(e)
		return false, nil
	}
	fingerprint := sha256.Sum256([]byte(hashStrings(strconv.Itoa(e.Result.ResponseCode), string(e.Result.Body))))
	if d.responseSeen && d.responseFingerprint == fingerprint {
		c.stats.Duplicates++
		discard(e)
		return false, nil
	}
	// Also deduplicate interleaved provisional/final retransmissions still pending.
	for _, pending := range d.entries {
		if pending.Result.Method != "MESSAGE" && pending.Result.ResponseCode == e.Result.ResponseCode && string(pending.Result.Body) == string(e.Result.Body) {
			c.stats.Duplicates++
			discard(e)
			return false, nil
		}
	}
	d.responseSeen, d.responseFingerprint = true, fingerprint
	if d.allowed {
		return deliver(e)
	}
	if !c.retain(d, e) {
		c.rejectGroup(d)
	}
	return false, nil
}

func resultBytes(r pipeline.SIPResult) int {
	// All variable-size fields retained by the controller are charged as well as
	// fixed result/map/slice storage. Packet bytes are charged by Entry.Size.
	size := 512 + len(r.Body) + len(r.SDP)
	for _, s := range []string{r.CallID, r.Method, r.CSeqMethod, r.ViaBranch, r.From, r.To, r.FromUser, r.ToUser, r.FromURI, r.ToURI, r.FromTag, r.ToTag, r.PAssertedIdentity, r.ContentType, r.SourceIP, r.DestinationIP} {
		size += len(s)
	}
	for key, value := range r.Headers {
		size += 64 + len(key) + len(value)
	}
	for _, id := range r.MatchedFilterIDs {
		size += 16 + len(id)
	}
	for _, observation := range r.Lifecycle {
		size += 64 + len(observation.Reason)
	}
	if r.SMS != nil {
		m := r.SMS
		size += 256 + len(m.Text) + len(m.Header) + len(m.From) + len(m.To) + len(m.Status) + len(m.Encoding) + len(m.Direction) + len(m.Assembly.ID) + len(m.Assembly.Status) + len(m.Assembly.Text) + len(m.Assembly.Received) + len(m.Assembly.Missing)
	}
	return size
}

func (c *Controller) retain(d *decision, e Entry) bool {
	if e.Size < 0 {
		e.Size = 0
	}
	metadata := resultBytes(e.Result)
	if c.stats.PendingMessages >= c.config.MaxPendingMessages || metadata > c.config.MaxPendingBytes-c.stats.PendingBytes || e.Size > c.config.MaxPendingBytes-c.stats.PendingBytes-metadata {
		c.stats.ResourceLimited++
		c.reject(d)
		discard(e)
		return false
	}
	e.Size += metadata
	// Envelopes/callbacks are already owned by adapters; clone the additional
	// mutable result fields so later metadata enrichment cannot alter a decision.
	e.Result.Body = append([]byte(nil), e.Result.Body...)
	e.Result.SDP = append([]byte(nil), e.Result.SDP...)
	e.Result.SMS = sms.Clone(e.Result.SMS)
	if e.Result.Headers != nil {
		headers := make(map[string]string, len(e.Result.Headers))
		for k, v := range e.Result.Headers {
			headers[k] = v
		}
		e.Result.Headers = headers
	}
	e.Result.MatchedFilterIDs = append([]string(nil), e.Result.MatchedFilterIDs...)
	e.Result.Lifecycle = append([]pipeline.CallLifecycleObservation(nil), e.Result.Lifecycle...)
	c.sequence++
	d.entries = append(d.entries, queuedEntry{Entry: e, sequence: c.sequence})
	c.stats.PendingMessages++
	c.stats.PendingBytes += e.Size
	return true
}

func (c *Controller) current(decisions []*decision) bool {
	for _, d := range decisions {
		if d.rejected {
			return false
		}
		for _, e := range d.entries {
			if e.Current != nil && !e.Current() {
				return false
			}
		}
	}
	return true
}

func (c *Controller) release(decisions []*decision, assembly *sms.AssemblyInfo) (bool, error) {
	if !c.current(decisions) {
		for _, d := range decisions {
			c.reject(d)
		}
		return false, nil
	}
	var entries []queuedEntry
	for _, d := range decisions {
		entries = append(entries, d.entries...)
		d.entries = nil
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Result.Timestamp.Equal(b.Result.Timestamp) {
			return a.sequence < b.sequence
		}
		return a.Result.Timestamp.Before(b.Result.Timestamp)
	})
	var err error
	forwarded := false
	for _, e := range entries {
		c.account(e.Entry)
		if assembly != nil && e.Result.SMS != nil && e.Result.SMS.Status == sms.StatusDecoded {
			e.Result.SMS = sms.Clone(e.Result.SMS)
			e.Result.SMS.Assembly = *assembly
			e.Result.SMS.Assembly.Received = append([]uint8(nil), assembly.Received...)
			e.Result.SMS.Assembly.Missing = append([]uint8(nil), assembly.Missing...)
		}
		ok, next := deliver(e.Entry)
		forwarded = forwarded || ok
		err = errors.Join(err, next)
	}
	return forwarded, err
}
func (c *Controller) account(e Entry) { c.stats.PendingMessages--; c.stats.PendingBytes -= e.Size }
func (c *Controller) reject(d *decision) {
	if !d.rejected {
		c.stats.Rejected++
	}
	d.rejected = true
	d.allowed = false
	for _, e := range d.entries {
		c.account(e.Entry)
		discard(e.Entry)
	}
	d.entries = nil
}
func deliver(e Entry) (bool, error) {
	if e.Current != nil && !e.Current() {
		discard(e)
		return false, nil
	}
	if e.Deliver == nil {
		discard(e)
		return false, fmt.Errorf("SMS output callback missing")
	}
	return true, e.Deliver(e.Result)
}
func discard(e Entry) {
	if e.Discard != nil {
		e.Discard()
	}
}

func (c *Controller) expire(now time.Time) {
	c.assembler.Expire(now)
	for key, d := range c.transactions {
		if now.Before(d.start.Add(c.config.Assembly.Lifetime)) {
			continue
		}
		c.rejectGroup(d)
		if d.group != "" {
			c.assembler.Forget(d.group)
		}
		delete(c.transactions, key)
		c.stats.Expired++
	}
	for key, ref := range c.references {
		if !now.Before(ref.start.Add(c.config.Assembly.Lifetime)) {
			delete(c.references, key)
		}
	}
	for key, txs := range c.controls {
		live := txs[:0]
		for _, tx := range txs {
			if c.transactions[tx] != nil {
				live = append(live, tx)
			}
		}
		if len(live) == 0 {
			delete(c.controls, key)
		} else {
			c.controls[key] = live
		}
	}
}

// Expire drops retained output and decisions using the supplied observation clock.
func (c *Controller) Expire(now time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.expire(now) }

// Stats returns a content-free snapshot.
func (c *Controller) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Transactions = len(c.transactions)
	return s
}

// Close releases pending output and prevents later processing.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.done)
	c.clear()
	c.assembler.Close()
}
func (c *Controller) clear() {
	for key, d := range c.transactions {
		c.reject(d)
		delete(c.transactions, key)
	}
	clear(c.references)
	clear(c.controls)
}

// Reset drops pending output and assembly state at capture replacement or policy
// generation change. It does not reopen a closed controller.
func (c *Controller) Reset() { c.mu.Lock(); defer c.mu.Unlock(); c.clear(); c.assembler.Reset() }

// Run expires idle live-capture state. Offline callers supply their capture clock
// through Process and Expire instead. Close also stops Run when the runtime
// finishes before its caller's context is canceled.
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case now := <-ticker.C:
			c.Expire(now)
		}
	}
}
