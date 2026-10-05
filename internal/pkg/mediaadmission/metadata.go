package mediaadmission

import (
	"container/list"
	"errors"
	"sort"
	"sync"
	"time"
)

// DialogKey deliberately includes a lifetime and transaction identity. The SIP
// adapter chooses a validated key; the store never guesses a relationship from
// Call-ID alone or promotes a different fork. Keys contain no SIP payload.
type DialogKey struct {
	Domain     DomainID
	Session    uint64
	Generation uint64
	CallID     string
	FromTag    string
	ToTag      string
	Branch     string
	CSeq       uint64
	CSeqMethod string
}

type MetadataStats struct {
	Dialogs         int
	Endpoints       int
	Bytes           int
	Evicted         uint64
	Expired         uint64
	Rejected        uint64
	PromotionMisses uint64
	Promotions      uint64
}

type metadataEntry struct {
	complete  bool
	key       DialogKey
	endpoints map[EndpointKey]struct{}
	updated   time.Time
	bytes     int
}

type pendingCall struct {
	Domain  DomainID
	Session uint64
	CallID  string
}

type MetadataRecord struct {
	Complete  bool
	Key       DialogKey
	Endpoints []EndpointKey
}

type MetadataStore struct {
	byCall  map[pendingCall]map[DialogKey]struct{}
	mu      sync.Mutex
	config  Config
	entries map[DialogKey]*list.Element
	oldest  *list.List
	stats   MetadataStats
}

func NewMetadataStore(config Config) (*MetadataStore, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &MetadataStore{config: config, entries: make(map[DialogKey]*list.Element), byCall: make(map[pendingCall]map[DialogKey]struct{}), oldest: list.New()}, nil
}

// metadataBytes is a conservative accounting charge including key strings,
// retained endpoint/map storage, and per-entry/list overhead. It bounds charged
// retained state; the Go allocator's runtime bookkeeping is not an RSS guarantee.
func metadataBytes(key DialogKey, endpoints int) int {
	return 256 + len(key.CallID) + len(key.FromTag) + len(key.ToTag) + len(key.Branch) + len(key.CSeqMethod) + endpoints*128
}

func (s *MetadataStore) Observe(key DialogKey, endpoints []EndpointKey, now time.Time) error {
	return s.ObserveDerived(key, endpoints, true, now)
}

// ObserveDerived retains bounded derivation completeness even when no safe
// endpoint exists. A zero-endpoint complete record is intentional empty media;
// an incomplete record remains unknown rather than disappearing.
func (s *MetadataStore) ObserveDerived(key DialogKey, endpoints []EndpointKey, complete bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.CallID == "" || key.Session == 0 || key.Generation == 0 || now.IsZero() {
		s.stats.Rejected++
		return errors.New("invalid pending SDP identity or time")
	}
	// Bound input copying even if one malicious SIP message supplies many keys.
	if len(endpoints) > s.config.MaxEndpointsPerOwner {
		s.stats.Rejected++
		return ErrCapacity
	}
	normalized := make(map[EndpointKey]struct{}, len(endpoints))
	for _, ep := range endpoints {
		if ep.Domain != key.Domain {
			s.stats.Rejected++
			return ErrUnknownDomain
		}
		if err := ep.Validate(); err != nil {
			s.stats.Rejected++
			return err
		}
		normalized[ep] = struct{}{}
	}
	existing := s.entries[key]
	if existing != nil {
		old := existing.Value.(*metadataEntry)
		if now.Sub(old.updated) >= s.config.PendingTTL {
			s.remove(existing)
			s.stats.Expired++
			existing = nil
		} else {
			for ep := range old.endpoints {
				normalized[ep] = struct{}{}
			}
			// Out-of-order captures must not rewind expiry or break list ordering.
			if now.Before(old.updated) {
				now = old.updated
			}
		}
	}
	cost := metadataBytes(key, len(normalized))
	if len(normalized) > s.config.MaxEndpointsPerOwner || len(normalized) > s.config.PendingEndpointCapacity || cost > s.config.PendingBytes {
		s.stats.Rejected++
		return ErrCapacity
	}
	// Remove the previous value only after validating the complete replacement.
	if existing != nil {
		s.remove(existing)
	}
	s.expire(now, s.config.ExpirationBatch)
	for len(s.entries) >= s.config.PendingDialogCapacity || s.stats.Endpoints+len(normalized) > s.config.PendingEndpointCapacity || s.stats.Bytes+cost > s.config.PendingBytes {
		oldest := s.oldest.Front()
		if oldest == nil {
			s.stats.Rejected++
			return ErrCapacity
		}
		s.remove(oldest)
		s.stats.Evicted++
	}
	entry := &metadataEntry{complete: complete, key: key, endpoints: normalized, updated: now, bytes: cost}
	// Calls normally arrive in monotonic wall-clock order. Enforce the ordering
	// when a caller replays out-of-order capture timestamps as well.
	if newest := s.oldest.Back(); newest != nil && now.Before(newest.Value.(*metadataEntry).updated) {
		entry.updated = newest.Value.(*metadataEntry).updated
	}
	s.entries[key] = s.oldest.PushBack(entry)
	indexKey := pendingCall{key.Domain, key.Session, key.CallID}
	if s.byCall[indexKey] == nil {
		s.byCall[indexKey] = make(map[DialogKey]struct{})
	}
	s.byCall[indexKey][key] = struct{}{}
	s.stats.Endpoints += len(normalized)
	s.stats.Bytes += cost
	return nil
}

func (s *MetadataStore) remove(element *list.Element) {
	entry := element.Value.(*metadataEntry)
	delete(s.entries, entry.key)
	indexKey := pendingCall{entry.key.Domain, entry.key.Session, entry.key.CallID}
	delete(s.byCall[indexKey], entry.key)
	if len(s.byCall[indexKey]) == 0 {
		delete(s.byCall, indexKey)
	}
	s.oldest.Remove(element)
	s.stats.Endpoints -= len(entry.endpoints)
	s.stats.Bytes -= entry.bytes
}
func (s *MetadataStore) lookup(key DialogKey, now time.Time) (*list.Element, bool) {
	element := s.entries[key]
	if element == nil {
		return nil, false
	}
	if now.Sub(element.Value.(*metadataEntry).updated) >= s.config.PendingTTL {
		s.remove(element)
		s.stats.Expired++
		return nil, false
	}
	return element, true
}
func copyEndpoints(entry *metadataEntry) []EndpointKey {
	result := make([]EndpointKey, 0, len(entry.endpoints))
	for ep := range entry.endpoints {
		result = append(result, ep)
	}
	return result
}
func (s *MetadataStore) Peek(key DialogKey, now time.Time) ([]EndpointKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element, ok := s.lookup(key, now)
	if !ok {
		return nil, false
	}
	return copyEndpoints(element.Value.(*metadataEntry)), true
}
func (s *MetadataStore) Take(key DialogKey, now time.Time) ([]EndpointKey, bool) {
	r, ok := s.TakeRecord(key, now)
	return r.Endpoints, ok
}

func (s *MetadataStore) TakeRecord(key DialogKey, now time.Time) (MetadataRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	element, ok := s.lookup(key, now)
	if !ok {
		s.stats.PromotionMisses++
		return MetadataRecord{}, false
	}
	entry := element.Value.(*metadataEntry)
	result := MetadataRecord{Key: key, Complete: entry.complete, Endpoints: copyEndpoints(entry)}
	s.remove(element)
	s.stats.Promotions++
	return result, true
}
func (s *MetadataStore) Delete(key DialogKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element := s.entries[key]; element != nil {
		s.remove(element)
	}
}
func (s *MetadataStore) expire(now time.Time, limit int) int {
	n := 0
	for n < limit {
		element := s.oldest.Front()
		if element == nil || now.Sub(element.Value.(*metadataEntry).updated) < s.config.PendingTTL {
			break
		}
		s.remove(element)
		s.stats.Expired++
		n++
	}
	return n
}

// Expire bounds each sweep. Lookup never returns an expired record even when a
// prior sweep hit its work limit; additional sweeps reclaim the remaining state.
func (s *MetadataStore) Expire(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expire(now, s.config.ExpirationBatch)
}
func (s *MetadataStore) Stats() MetadataStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.Dialogs = len(s.entries)
	return out
}
func (s *MetadataStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[DialogKey]*list.Element)
	s.byCall = make(map[pendingCall]map[DialogKey]struct{})
	s.oldest.Init()
	s.stats.Endpoints = 0
	s.stats.Bytes = 0
}

// Candidates returns owned metadata for one call in one observation session.
// The index and result are bounded by PendingDialogCapacity; expired candidates
// are never returned even when background expiry has not reached them.
func (s *MetadataStore) Candidates(domain DomainID, session uint64, callID string, now time.Time) []MetadataRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.byCall[pendingCall{domain, session, callID}]
	result := make([]MetadataRecord, 0, len(keys))
	for key := range keys {
		element, ok := s.lookup(key, now)
		if ok {
			result = append(result, MetadataRecord{Complete: element.Value.(*metadataEntry).complete, Key: key, Endpoints: copyEndpoints(element.Value.(*metadataEntry))})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.Generation < result[j].Key.Generation })
	return result
}
