// Package callselection composes the existing VoIP processor and SDP admission
// proof machinery for centrally selected calls across authenticated sources.
package callselection

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip/admission"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
)

var (
	ErrSource   = errors.New("untrusted or unmapped call-selection source")
	ErrDialog   = errors.New("SIP observation does not prove the selected dialog transaction")
	ErrCapacity = errors.New("central call-selection metadata capacity exceeded")
	ErrClosed   = errors.New("central call selection closed")
)

// Source is supplied by the authenticated ingress owner, never decoded from a
// hunter's packet metadata. Local explicitly identifies the tap-local boundary.
type Source struct {
	NodeID, InterfaceName string
	Domain                mediaadmission.DomainID
	Local                 bool
}

type Selection struct {
	Selected  bool
	FilterIDs []string
	Revision  uint64
}

type Config struct {
	Domains []mediaadmission.DomainID
	// MaxCalls is shared across domains (also bounded by Limits.OwnerCapacity).
	// MaxEndpointAssociations is divided among their independent registries in
	// domain order; the sum never exceeds the configured association budget.
	Processor voipprocessor.Config
	Limits    mediaadmission.Config
	// Callbacks run synchronously under the tracker lock and must not reenter.
	Match                  func(sip.Event, *pipeline.PacketEnvelope, Source) (Selection, error)
	Authorize              func(Source) error
	TrailingGrace          time.Duration
	Now                    func() time.Time
	MaxDialogsPerCall      int
	MaxTransactionsPerCall int
	MaxBytes               int
}

type Dialog struct{ FromTag, ToTag string }

type Call struct {
	Domain             mediaadmission.DomainID
	Info               callregistry.Call
	FromTag, ToTag     string
	Dialogs            []Dialog
	FilterIDs          []string
	SelectionRevision  uint64
	Endpoints          []mediaadmission.EndpointKey
	Completing         bool
	CompletionDeadline time.Time
}

type Result struct {
	Process                             *voipprocessor.ProcessResult
	Call                                *Call
	DirectFilterIDs, InheritedFilterIDs []string
}

type transaction struct {
	fromTag, toTag, method, branch string
	cseq                           uint64
}

type record struct {
	call            Call
	fromURI, toURI  string
	lastSeen        time.Time
	transactions    []transaction
	selectionEvent  sip.Event
	selectionSource Source
}

type domainState struct {
	processor *voipprocessor.Processor
	bridge    *admission.Bridge
	records   map[string]*record
	// Only valid during the synchronous, already-authorized Process boundary.
	authorized *Source
}

type Tracker struct {
	mu         sync.Mutex
	config     Config
	domains    map[mediaadmission.DomainID]*domainState
	controller *mediaadmission.Controller
	closed     bool
}

func New(config Config) (*Tracker, error) {
	if len(config.Domains) == 0 || config.Match == nil || config.Authorize == nil || config.TrailingGrace < 0 {
		return nil, errors.New("central call selection requires domains, source authorization, selection and nonnegative grace")
	}
	if config.MaxDialogsPerCall == 0 {
		config.MaxDialogsPerCall = 32
	}
	if config.MaxTransactionsPerCall == 0 {
		config.MaxTransactionsPerCall = 128
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = config.Limits.PendingBytes
	}
	if config.MaxDialogsPerCall < 1 || config.MaxTransactionsPerCall < 1 || config.MaxBytes < 1 {
		return nil, ErrCapacity
	}
	if err := config.Limits.Validate(); err != nil {
		return nil, fmt.Errorf("central call-selection limits: %w", err)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Processor.MaxCalls <= 0 {
		config.Processor.MaxCalls = voipprocessor.DefaultConfig().MaxCalls
	}
	if config.Processor.MaxEndpointAssociations <= 0 {
		config.Processor.MaxEndpointAssociations = config.Processor.MaxCalls * 4
	}
	if config.Processor.MaxEndpointAssociations < len(config.Domains) {
		return nil, fmt.Errorf("central endpoint-association budget must accommodate every observation domain: %w", ErrCapacity)
	}
	config.Domains = append([]mediaadmission.DomainID(nil), config.Domains...)
	sort.Slice(config.Domains, func(i, j int) bool { return config.Domains[i] < config.Domains[j] })
	// This is a userspace desired-state backend, not a capture backend. It lets
	// the shared bridge retain its existing proof/recovery/resource semantics.
	limits := config.Limits
	limits.Enabled = true
	limits.InterfaceDomains = make(map[string]mediaadmission.DomainID, len(config.Domains))
	for _, domain := range config.Domains {
		limits.InterfaceDomains[fmt.Sprintf("domain-%d", domain)] = domain
	}
	controller, err := mediaadmission.NewController(context.Background(), limits, &memoryBackend{keys: make(map[mediaadmission.EndpointKey]struct{})})
	if err != nil {
		return nil, fmt.Errorf("central desired media state: %w", err)
	}
	metadata, err := mediaadmission.NewMetadataStore(limits)
	if err != nil {
		closeErr := controller.Close(context.Background())
		return nil, errors.Join(err, closeErr)
	}
	tracker := &Tracker{config: config, domains: make(map[mediaadmission.DomainID]*domainState), controller: controller}
	for domainIndex, domain := range config.Domains {
		if _, duplicate := tracker.domains[domain]; duplicate {
			return nil, errors.Join(fmt.Errorf("duplicate central observation domain %d", domain), tracker.Close())
		}
		pcfg := config.Processor
		// Independent registries share this configured total; deterministic
		// allocation prevents domain count from multiplying association memory.
		pcfg.MaxEndpointAssociations = config.Processor.MaxEndpointAssociations / len(config.Domains)
		if domainIndex < config.Processor.MaxEndpointAssociations%len(config.Domains) {
			pcfg.MaxEndpointAssociations++
		}
		pcfg.DeferSDPAssociations = true
		pcfg.ApplicationFilter = nil // Selection is parsed and centrally validated.
		child := &domainState{processor: voipprocessor.New(pcfg), records: make(map[string]*record)}
		tracker.domains[domain] = child
		bridge, bridgeErr := admission.New(admission.Config{
			Limits: limits, Domain: domain, Registry: child.processor.CallRegistry(), Controller: controller, Metadata: metadata,
			Now: config.Now, RetirementGrace: config.TrailingGrace,
			AcceptSource: func(provenance pipeline.SourceProvenance) bool {
				return child.authorized != nil && sourceMatches(provenance, *child.authorized)
			},
		})
		if bridgeErr != nil {
			return nil, errors.Join(bridgeErr, tracker.Close())
		}
		child.bridge = bridge
		if observerErr := child.processor.SetMetadataObserver(bridge); observerErr != nil {
			return nil, errors.Join(observerErr, tracker.Close())
		}
	}
	return tracker, nil
}

func sourceMatches(provenance pipeline.SourceProvenance, source Source) bool {
	kind := pipeline.SourceGRPC
	if source.Local {
		kind = pipeline.SourceLiveCapture
	}
	return source.NodeID != "" && provenance.Kind == kind && provenance.NodeID == source.NodeID && provenance.InterfaceName == source.InterfaceName
}

// Process requires normalized, already framed packets and authenticated source
// context. Capture time, kind, node and interface remain unchanged throughout.
// Raw SIP metadata/Call-IDs supplied by a hunter never bypass parsing or Match.
func (t *Tracker) Process(envelope *pipeline.PacketEnvelope, source Source) (Result, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return Result{}, ErrClosed
	}
	child := t.domains[source.Domain]
	if child == nil || envelope == nil || !sourceMatches(envelope.Source, source) {
		return Result{}, ErrSource
	}
	if err := t.config.Authorize(source); err != nil {
		return Result{}, fmt.Errorf("central source authorization: %w", err)
	}
	t.sweepLocked()
	child.authorized = &source
	defer func() { child.authorized = nil }()
	var event sip.Event
	var candidate *record
	var selection Selection
	processed, err := child.processor.ProcessAuthenticatedEnvelope(envelope, voipprocessor.EnvelopePolicy{
		ValidateSource: func(provenance pipeline.SourceProvenance) error {
			if !sourceMatches(provenance, source) {
				return ErrSource
			}
			return nil
		},
		Validate: func(parsed sip.Event) error {
			event = parsed
			existing := child.records[parsed.CallID]
			if existing == nil && t.callCountLocked() >= min(t.config.Processor.MaxCalls, t.config.Limits.OwnerCapacity) {
				return ErrCapacity
			}
			candidate = cloneRecord(existing)
			if candidate == nil {
				candidate = &record{call: Call{Domain: source.Domain}, fromURI: parsed.FromURI, toURI: parsed.ToURI}
			}
			if err := t.validateEvent(candidate, existing == nil, parsed); err != nil {
				return err
			}
			return nil
		},
		Match: func(parsed sip.Event) (bool, []string, error) {
			var matchErr error
			selection, matchErr = t.config.Match(parsed, envelope, source)
			if matchErr != nil {
				return false, nil, matchErr
			}
			if selection.Selected {
				if selection.Revision == 0 {
					return false, nil, errors.New("selected call has no current selection revision")
				}
				if len(selection.FilterIDs) > t.config.MaxTransactionsPerCall {
					return false, nil, ErrCapacity
				}
				for _, id := range selection.FilterIDs {
					if id == "" || len(id) > 1024 {
						return false, nil, ErrCapacity
					}
				}
				if selection.Revision < candidate.call.SelectionRevision {
					return false, nil, errors.New("stale central call-selection revision")
				}
				if selection.Revision > candidate.call.SelectionRevision {
					candidate.call.FilterIDs = nil
				}
				candidate.call.FilterIDs = uniqueStrings(append(candidate.call.FilterIDs, selection.FilterIDs...))
				candidate.call.SelectionRevision = selection.Revision
				candidate.selectionEvent = selectionProof(parsed)
				candidate.selectionSource = source
			}
			if t.metadataBytesLocked()-recordBytes(child.records[parsed.CallID])+recordBytes(candidate) > t.config.MaxBytes {
				return false, nil, ErrCapacity
			}
			return selection.Selected, selection.FilterIDs, nil
		},
	})
	result := Result{Process: processed}
	if processed == nil {
		return result, err
	}
	if processed.PacketType == voipprocessor.PacketTypeRTP {
		if processed.MediaResolution.Status == callregistry.MediaResolved {
			if current := child.records[processed.CallID]; current != nil && current.call.Info.Lifetime == processed.CallLifetime {
				current.lastSeen = t.config.Now()
				call := t.callSnapshotLocked(child, current)
				result.Call, result.InheritedFilterIDs = &call, append([]string(nil), call.FilterIDs...)
			}
		}
		return result, err
	}
	if !processed.IsVoIP || candidate == nil {
		return result, err
	}
	candidate.call.Info, _ = child.processor.Call(processed.CallID)
	candidate.lastSeen = t.config.Now()
	if terminal(event) && !candidate.call.Completing {
		candidate.call.Completing = true
		candidate.call.CompletionDeadline = candidate.lastSeen.Add(t.config.TrailingGrace)
		child.processor.CallRegistry().NotifyCallCompleting(processed.CallID, candidate.call.Info.Lifetime)
	}
	child.records[processed.CallID] = candidate
	t.pruneLocked(child)
	call := t.callSnapshotLocked(child, candidate)
	result.Call = &call
	result.DirectFilterIDs = append([]string(nil), selection.FilterIDs...)
	if !selection.Selected {
		result.InheritedFilterIDs = append([]string(nil), call.FilterIDs...)
	}
	return result, err
}

func terminal(event sip.Event) bool {
	return event.Method == "BYE" || event.Method == "CANCEL" || (event.ResponseCode >= 200 && (event.CSeqMethod == "BYE" || event.CSeqMethod == "CANCEL"))
}

func (t *Tracker) validateEvent(current *record, initial bool, event sip.Event) error {
	if event.CallID == "" || event.FromTag == "" || event.ViaBranch == "" || event.CSeqNumber == 0 || event.CSeqMethod == "" || len(event.FromTag) > 1024 || len(event.ToTag) > 1024 || len(event.ViaBranch) > 1024 || len(event.FromURI) > 1024 || len(event.ToURI) > 1024 {
		return ErrDialog
	}
	if event.ResponseCode == 0 && event.Method != event.CSeqMethod {
		return ErrDialog
	}
	if event.ReliableHeaderEvidence.Conflicts.CSeq || (event.DuplicateReliableHeaders.CSeq && !event.ReliableHeaderEvidence.CSeqValid) {
		return ErrDialog
	}
	if initial {
		if event.Method != "INVITE" || event.ToTag != "" {
			return ErrDialog
		}
		current.call.FromTag = event.FromTag
	} else {
		forward := event.FromURI == current.fromURI && event.ToURI == current.toURI
		reverse := event.FromURI == current.toURI && event.ToURI == current.fromURI
		if !forward && !reverse {
			return ErrDialog
		}
		if current.call.Completing && event.ResponseCode == 0 && event.Method != "BYE" && event.Method != "CANCEL" {
			return ErrDialog
		}
	}
	if event.ResponseCode != 0 {
		found := false
		for _, request := range current.transactions {
			if request.fromTag == event.FromTag && request.cseq == event.CSeqNumber && request.method == event.CSeqMethod && request.branch == event.ViaBranch && (request.toTag == "" || request.toTag == event.ToTag) {
				found = true
				break
			}
		}
		if !found {
			return ErrDialog
		}
		if event.ToTag != "" && event.ResponseCode > 100 && event.ResponseCode < 300 {
			dialog := Dialog{FromTag: event.FromTag, ToTag: event.ToTag}
			if !hasDialog(current.call.Dialogs, dialog) {
				if len(current.call.Dialogs) >= t.config.MaxDialogsPerCall {
					return ErrCapacity
				}
				current.call.Dialogs = append(current.call.Dialogs, dialog)
			}
			if current.call.ToTag == "" {
				current.call.ToTag = event.ToTag
			}
		}
		if terminal(event) && !hasDialog(current.call.Dialogs, Dialog{event.FromTag, event.ToTag}) && event.CSeqMethod != "CANCEL" {
			return ErrDialog
		}
		return nil
	}
	if !initial {
		if event.ToTag == "" {
			// Only a retransmission of the initial INVITE or its exact CANCEL
			// can share an early dialog without established tags.
			if event.FromTag != current.call.FromTag || (event.Method != "INVITE" && event.Method != "CANCEL") {
				return ErrDialog
			}
			found := false
			for _, request := range current.transactions {
				if request.method == "INVITE" && request.fromTag == event.FromTag && request.cseq == event.CSeqNumber && request.branch == event.ViaBranch {
					found = true
				}
			}
			if !found {
				return ErrDialog
			}
		} else if !hasDialog(current.call.Dialogs, Dialog{event.FromTag, event.ToTag}) {
			return ErrDialog
		}
	}
	request := transaction{fromTag: event.FromTag, toTag: event.ToTag, cseq: event.CSeqNumber, method: event.CSeqMethod, branch: event.ViaBranch}
	for _, old := range current.transactions {
		if old == request {
			return nil
		}
	}
	if event.Method == "ACK" || event.Method == "CANCEL" {
		found := false
		for _, old := range current.transactions {
			if old.fromTag == event.FromTag && old.cseq == event.CSeqNumber && old.method == "INVITE" && (old.toTag == "" || old.toTag == event.ToTag) && (event.Method == "ACK" || old.branch == event.ViaBranch) {
				found = true
			}
		}
		if !found {
			return ErrDialog
		}
	}
	if event.Method != "ACK" && event.Method != "CANCEL" {
		for _, old := range current.transactions {
			if old.fromTag == event.FromTag && old.cseq >= event.CSeqNumber {
				return ErrDialog
			}
		}
	}
	if len(current.transactions) >= t.config.MaxTransactionsPerCall {
		return ErrCapacity
	}
	current.transactions = append(current.transactions, request)
	return nil
}

func hasDialog(dialogs []Dialog, dialog Dialog) bool {
	for _, known := range dialogs {
		if known == dialog || (known.FromTag == dialog.ToTag && known.ToTag == dialog.FromTag) {
			return true
		}
	}
	return false
}

func cloneRecord(value *record) *record {
	if value == nil {
		return nil
	}
	copy := *value
	copy.call.FilterIDs = append([]string(nil), value.call.FilterIDs...)
	copy.call.Dialogs = append([]Dialog(nil), value.call.Dialogs...)
	copy.transactions = append([]transaction(nil), value.transactions...)
	copy.selectionEvent = selectionProof(value.selectionEvent)
	return &copy
}

// selectionProof freezes normalized identity/header evidence, without retaining
// SIP bodies, SDP, packets, transport metadata claims or their backing buffers.
func selectionProof(event sip.Event) sip.Event {
	event.Body, event.SDP = nil, nil
	headers := make(map[string]string, len(event.Headers))
	for key, value := range event.Headers {
		headers[strings.Clone(key)] = strings.Clone(value)
	}
	event.Headers = headers
	return event
}

// Reevaluate rechecks bounded, previously parsed selection evidence against
// current configuration. It preserves the lifetime and media of still-selected
// calls and retires revoked calls immediately, including their capture rules.
// Errors fail closed for the affected call and are returned to the operator.
// The callback runs under the tracker lock and must not reenter the tracker.
func (t *Tracker) Reevaluate(match func(Call, sip.Event, Source) (Selection, error)) error {
	if match == nil {
		return errors.New("central call-selection revalidation requires a matcher")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrClosed
	}
	t.sweepLocked()
	var failures []error
	for _, child := range t.domains {
		for id, value := range child.records {
			selection, err := match(t.callSnapshotLocked(child, value), selectionProof(value.selectionEvent), value.selectionSource)
			if err == nil && selection.Selected {
				if selection.Revision == 0 || selection.Revision < value.call.SelectionRevision {
					err = errors.New("revalidated call has a stale selection revision")
				} else if len(selection.FilterIDs) > t.config.MaxTransactionsPerCall {
					err = ErrCapacity
				} else {
					for _, filterID := range selection.FilterIDs {
						if filterID == "" || len(filterID) > 1024 {
							err = ErrCapacity
							break
						}
					}
				}
				if err == nil {
					updated := cloneRecord(value)
					updated.call.FilterIDs = uniqueStrings(selection.FilterIDs)
					updated.call.SelectionRevision = selection.Revision
					if t.metadataBytesLocked()-recordBytes(value)+recordBytes(updated) > t.config.MaxBytes {
						err = ErrCapacity
					} else {
						child.records[id] = updated
						continue
					}
				}
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("revalidate selected call: %w", err))
			}
			child.processor.FinalizeCallLifetime(id, value.call.Info.Lifetime)
			delete(child.records, id)
		}
	}
	return errors.Join(failures...)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; !ok {
			result = append(result, value)
			seen[value] = struct{}{}
		}
	}
	sort.Strings(result)
	return result
}

func (t *Tracker) callSnapshotLocked(child *domainState, value *record) Call {
	call := cloneRecord(value).call
	if current, exists := child.processor.Call(call.Info.CallID); exists {
		call.Info = current
	}
	if endpoints, exists := child.processor.CallRegistry().EndpointSnapshot(call.Info.CallID); exists && endpoints.Call.Lifetime == call.Info.Lifetime {
		for _, raw := range endpoints.Endpoints {
			address, err := netip.ParseAddrPort(raw)
			if err != nil {
				continue
			} // Diagnostic port-only entries are not authority.
			key, err := mediaadmission.NewEndpoint(call.Domain, address.Addr(), address.Port())
			if err == nil {
				call.Endpoints = append(call.Endpoints, key)
			}
		}
	}
	sort.Slice(call.Endpoints, func(i, j int) bool {
		return netip.AddrPortFrom(call.Endpoints[i].Addr, call.Endpoints[i].Port).String() < netip.AddrPortFrom(call.Endpoints[j].Addr, call.Endpoints[j].Port).String()
	})
	return call
}

func (t *Tracker) Snapshot() []Call {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.sweepLocked()
	var calls []Call
	for _, child := range t.domains {
		for _, record := range child.records {
			calls = append(calls, t.callSnapshotLocked(child, record))
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].Domain != calls[j].Domain {
			return calls[i].Domain < calls[j].Domain
		}
		return calls[i].Info.CallID < calls[j].Info.CallID
	})
	return calls
}

// Sweep uses the caller's existing maintenance loop, with no per-call timers.
func (t *Tracker) Sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.sweepLocked()
	}
}

func (t *Tracker) sweepLocked() {
	now := t.config.Now()
	for _, child := range t.domains {
		for id, value := range child.records {
			timeout := t.config.Processor.CallTimeout
			if timeout <= 0 {
				timeout = voipprocessor.DefaultConfig().CallTimeout
			}
			if (value.call.Completing && !now.Before(value.call.CompletionDeadline)) || now.Sub(value.lastSeen) >= timeout {
				child.processor.FinalizeCallLifetime(id, value.call.Info.Lifetime)
				delete(child.records, id)
			}
		}
		t.pruneLocked(child)
	}
}

func (t *Tracker) pruneLocked(child *domainState) {
	for id, value := range child.records {
		call, exists := child.processor.Call(id)
		if !exists || call.Lifetime != value.call.Info.Lifetime {
			delete(child.records, id)
		}
	}
}

func recordBytes(value *record) int {
	if value == nil {
		return 0
	}
	cost := 512 + len(value.fromURI) + len(value.toURI) + len(value.call.Info.CallID)
	for _, dialog := range value.call.Dialogs {
		cost += 64 + len(dialog.FromTag) + len(dialog.ToTag)
	}
	for _, id := range value.call.FilterIDs {
		cost += 16 + len(id)
	}
	for _, request := range value.transactions {
		cost += 96 + len(request.fromTag) + len(request.toTag) + len(request.method) + len(request.branch)
	}
	proof := value.selectionEvent
	for _, field := range []string{proof.StartLine, proof.Method, proof.RequestURI, proof.CSeqMethod, proof.ViaBranch, proof.CallID, proof.From, proof.To, proof.FromUser, proof.ToUser, proof.FromURI, proof.ToURI, proof.FromTag, proof.ToTag, proof.PAssertedIdentity, proof.ContentType, proof.SourceIP, proof.DestinationIP} {
		cost += len(field)
	}
	for key, header := range proof.Headers {
		cost += 64 + len(key) + len(header)
	}
	cost += len(value.selectionSource.NodeID) + len(value.selectionSource.InterfaceName)
	return cost
}
func (t *Tracker) metadataBytesLocked() int {
	cost := 0
	for _, child := range t.domains {
		for _, record := range child.records {
			cost += recordBytes(record)
		}
	}
	return cost
}

func (t *Tracker) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var errs []error
	for _, child := range t.domains {
		if child.bridge != nil {
			errs = append(errs, child.bridge.Close())
		}
		child.processor.Close()
		clear(child.records)
	}
	errs = append(errs, t.controller.Close(context.Background()))
	return errors.Join(errs...)
}

// memoryBackend is a bounded desired-state mirror owned by Controller. It has
// no packet matching, call identity or capture-control responsibility.
type memoryBackend struct {
	mu   sync.Mutex
	keys map[mediaadmission.EndpointKey]struct{}
}

func (b *memoryBackend) PutEndpoint(_ context.Context, key mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[key] = struct{}{}
	return nil
}
func (b *memoryBackend) DeleteEndpoint(_ context.Context, key mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.keys, key)
	return nil
}
func (b *memoryBackend) ListEndpoints(_ context.Context, domain mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result []mediaadmission.EndpointKey
	for key := range b.keys {
		if key.Domain == domain {
			result = append(result, key)
		}
	}
	return result, nil
}
func (b *memoryBackend) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

// callCountLocked includes all tracked calls, including those without endpoints.
func (t *Tracker) callCountLocked() int {
	count := 0
	for _, child := range t.domains {
		count += len(child.records)
	}
	return count
}
