//go:build li

package li

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var ErrCaptureAuthority = errors.New("LI capture authority is invalid, stale or outside its scope")

// HandoverFilters returns only current, enabled filters owned by active tasks.
// Local operator filters and stale stored IDs never become signed LI authority.
func (m *Manager) HandoverFilters() ([]*management.Filter, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	return m.handoverFiltersLocked()
}

func (m *Manager) handoverFiltersLocked() ([]*management.Filter, error) {
	if !m.administrativeAdmissionReady() {
		return nil, ErrCaptureAuthority
	}
	m.filters.mu.RLock()
	defer m.filters.mu.RUnlock()
	filters := make([]*management.Filter, 0, len(m.filters.filterStore))
	for id, filter := range m.filters.filterStore {
		xid, ok := m.filters.filterToXID[id]
		if !ok || filter == nil || !filter.Enabled {
			continue
		}
		task, err := m.registry.GetTaskDetails(xid)
		if err != nil || !task.IsActive() || task.IsExpired() {
			continue
		}
		filters = append(filters, proto.Clone(filter).(*management.Filter))
	}
	sort.Slice(filters, func(i, j int) bool { return filters[i].Id < filters[j].Id })
	return filters, nil
}

// HandoverAuthority is opaque to generic hunters. The containing signed policy
// authenticates these consumer-specific task facts without rewriting filter IDs.
type HandoverAuthority struct {
	Version     uint32         `json:"version"`
	Incarnation uuid.UUID      `json:"incarnation"`
	Grants      []CaptureGrant `json:"grants"`
}

type CaptureGrant struct {
	FilterID             string    `json:"filter_id"`
	FilterSHA256         string    `json:"filter_sha256"`
	XID                  uuid.UUID `json:"xid"`
	ActivationGeneration uint64    `json:"activation_generation"`
	FilterRevision       uint64    `json:"filter_revision"`
	SourceIDs            []string  `json:"source_ids"`
	ValidFromNS          int64     `json:"valid_from_ns"`
	ValidUntilNS         int64     `json:"valid_until_ns"`
}

func captureFilterDigest(filter *management.Filter) (string, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(filter)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func grantSources(configured, targeted []string) []string {
	var result []string
	for _, source := range configured {
		if len(targeted) == 0 {
			result = append(result, source)
			continue
		}
		for _, target := range targeted {
			if source == target {
				result = append(result, source)
				break
			}
		}
	}
	return result
}

// BuildHandoverAuthority binds each current filter to its actual task generation.
// Its bytes MUST be covered by the owner's policy signature before distribution.
// Calling this method alone does not authenticate a policy.
func (m *Manager) BuildHandoverAuthority(filters []*management.Filter, config HandoverConfig, issuedAt time.Time) ([]byte, error) {
	config, err := config.Normalize()
	if err != nil || !config.Enabled || issuedAt.IsZero() || issuedAt.UnixNano() <= 0 {
		return nil, errors.Join(ErrCaptureAuthority, err)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	return m.buildHandoverAuthorityLocked(filters, config, issuedAt)
}

func (m *Manager) buildHandoverAuthorityLocked(filters []*management.Filter, config HandoverConfig, issuedAt time.Time) ([]byte, error) {
	incarnation := m.StateIncarnation()
	if !m.administrativeAdmissionReady() || incarnation == uuid.Nil {
		return nil, ErrCaptureAuthority
	}
	authority := HandoverAuthority{Version: 1, Incarnation: incarnation, Grants: []CaptureGrant{}}
	for _, filter := range filters {
		if filter == nil || !filter.Enabled {
			return nil, ErrCaptureAuthority
		}
		match, ok := m.filters.LookupFilter(filter.Id)
		if !ok || !proto.Equal(filter, match.Filter) {
			return nil, ErrCaptureAuthority
		}
		task, err := m.registry.GetTaskDetails(match.XID)
		if err != nil || !task.IsActive() || task.IsExpired() || task.ActivationGeneration == 0 || (!task.StartTime.IsZero() && issuedAt.Before(task.StartTime)) {
			return nil, ErrCaptureAuthority
		}
		until := issuedAt.Add(config.LeaseDuration)
		// ADMF EndTime has expiry semantics only when implicit deactivation is
		// allowed. The independent deployment lease is bounded in either case.
		if cutoff := TaskAuthorizationCutoff(task); !cutoff.IsZero() && cutoff.Before(until) {
			until = cutoff
		}
		if !until.After(issuedAt.Add(2 * config.ClockUncertainty)) {
			return nil, ErrCaptureAuthority
		}
		sources := grantSources(config.SourceIDs, filter.TargetHunters)
		if len(sources) == 0 {
			return nil, ErrCaptureAuthority
		}
		if IsRADIUSTask(task) && task.RADIUSScope.OriginNodeID != "" {
			sources = grantSources(sources, []string{task.RADIUSScope.OriginNodeID})
			if len(sources) == 0 {
				return nil, ErrCaptureAuthority
			}
		}
		digest, err := captureFilterDigest(filter)
		if err != nil {
			return nil, err
		}
		authority.Grants = append(authority.Grants, CaptureGrant{FilterID: filter.Id, FilterSHA256: digest, XID: task.XID, ActivationGeneration: task.ActivationGeneration, FilterRevision: filter.Revision, SourceIDs: sources, ValidFromNS: issuedAt.UnixNano(), ValidUntilNS: until.UnixNano()})
	}
	sort.Slice(authority.Grants, func(i, j int) bool { return authority.Grants[i].FilterID < authority.Grants[j].FilterID })
	for i := 1; i < len(authority.Grants); i++ {
		if authority.Grants[i].FilterID == authority.Grants[i-1].FilterID {
			return nil, ErrCaptureAuthority
		}
	}
	return json.Marshal(authority)
}

// PublishHandoverAuthority holds the task lifecycle barrier until the signer has
// durably published its snapshot. The callback must only sign/store the prepared
// policy; it must not reenter LI task mutation or lifecycle admission methods.
func (m *Manager) PublishHandoverAuthority(config HandoverConfig, issuedAt time.Time, publish func([]*management.Filter, []byte) error) error {
	config, err := config.Normalize()
	if err != nil || !config.Enabled || publish == nil || issuedAt.IsZero() || issuedAt.UnixNano() <= 0 {
		return errors.Join(ErrCaptureAuthority, err)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	filters, err := m.handoverFiltersLocked()
	if err != nil {
		return err
	}
	encoded, err := m.buildHandoverAuthorityLocked(filters, config, issuedAt)
	if err != nil {
		return err
	}
	return publish(filters, encoded)
}

func DecodeHandoverAuthority(encoded []byte) (*HandoverAuthority, error) {
	if len(encoded) == 0 || len(encoded) > 16<<20 {
		return nil, ErrCaptureAuthority
	}
	var authority HandoverAuthority
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authority); err != nil {
		return nil, ErrCaptureAuthority
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, ErrCaptureAuthority
	}
	canonical, err := json.Marshal(authority)
	if err != nil || !bytes.Equal(canonical, encoded) || authority.Version != 1 || authority.Incarnation == uuid.Nil || len(authority.Grants) > 65536 {
		return nil, ErrCaptureAuthority
	}
	previous := ""
	for _, grant := range authority.Grants {
		if grant.FilterID <= previous || grant.XID == uuid.Nil || grant.ActivationGeneration == 0 || grant.ValidFromNS <= 0 || grant.ValidUntilNS <= grant.ValidFromNS || len(grant.SourceIDs) == 0 || len(grant.SourceIDs) > 65536 {
			return nil, ErrCaptureAuthority
		}
		digest, err := hex.DecodeString(grant.FilterSHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != grant.FilterSHA256 {
			return nil, ErrCaptureAuthority
		}
		previous = grant.FilterID
		previousSource := ""
		for _, source := range grant.SourceIDs {
			if source <= previousSource || len(source) > 256 {
				return nil, ErrCaptureAuthority
			}
			previousSource = source
		}
	}
	return &authority, nil
}

// ValidateHandoverAuthority checks authenticated capture facts against CURRENT
// authorization. The caller must first verify the containing policy signature.
// This does not acquire the later irreversible LI delivery admission barrier.
func (m *Manager) ValidateHandoverAuthority(encoded []byte, policyFilters []*management.Filter, matchedIDs []string, source string, capturedAt, now time.Time, config HandoverConfig) error {
	config, err := config.Normalize()
	if err != nil || !config.Enabled || capturedAt.IsZero() || now.IsZero() {
		return ErrCaptureAuthority
	}
	authority, err := DecodeHandoverAuthority(encoded)
	if err != nil || authority.Incarnation != m.StateIncarnation() {
		return ErrCaptureAuthority
	}
	if len(grantSources(config.SourceIDs, []string{source})) == 0 {
		return ErrCaptureAuthority
	}
	filters := make(map[string]*management.Filter, len(policyFilters))
	for _, filter := range policyFilters {
		if filter == nil || filters[filter.Id] != nil {
			return ErrCaptureAuthority
		}
		filters[filter.Id] = filter
	}
	grants := make(map[string]CaptureGrant, len(authority.Grants))
	for _, grant := range authority.Grants {
		grants[grant.FilterID] = grant
	}
	if len(filters) != len(grants) {
		return ErrCaptureAuthority
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	if !m.administrativeAdmissionReady() {
		return ErrCaptureAuthority
	}
	for _, id := range stableFilterUnion(matchedIDs, nil) {
		grant, ok := grants[id]
		filter := filters[id]
		if !ok || filter == nil || len(grantSources(grant.SourceIDs, []string{source})) == 0 {
			return ErrCaptureAuthority
		}
		from, until := time.Unix(0, grant.ValidFromNS), time.Unix(0, grant.ValidUntilNS)
		if capturedAt.Before(from.Add(config.ClockUncertainty)) || !capturedAt.Before(until.Add(-config.ClockUncertainty)) || now.Before(from) || until.Sub(from) > config.LeaseDuration {
			return ErrCaptureAuthority
		}
		match, ok := m.filters.LookupFilter(id)
		if !ok || match.XID != grant.XID || !proto.Equal(filter, match.Filter) || filter.Revision != grant.FilterRevision {
			return ErrCaptureAuthority
		}
		digest, err := captureFilterDigest(filter)
		if err != nil || digest != grant.FilterSHA256 {
			return ErrCaptureAuthority
		}
		task, err := m.registry.GetTaskDetails(grant.XID)
		if err != nil || !task.IsActive() || task.IsExpired() || task.ActivationGeneration != grant.ActivationGeneration || (!task.StartTime.IsZero() && capturedAt.Before(task.StartTime)) {
			return ErrCaptureAuthority
		}
		if cutoff := TaskAuthorizationCutoff(task); !cutoff.IsZero() && (!now.Before(cutoff) || !capturedAt.Before(cutoff)) {
			return ErrCaptureAuthority
		}
	}
	return nil
}

// HandoverLeaseBounds exposes the intersection needed by a generic capture
// consumer. It never extends a shorter task-specific authorization window.
func HandoverLeaseBounds(encoded []byte, issuedAt time.Time, duration time.Duration) (time.Time, error) {
	authority, err := DecodeHandoverAuthority(encoded)
	if err != nil {
		return time.Time{}, err
	}
	until := issuedAt.Add(duration)
	for _, grant := range authority.Grants {
		if grant.ValidFromNS != issuedAt.UnixNano() {
			return time.Time{}, fmt.Errorf("%w: lease start differs", ErrCaptureAuthority)
		}
		if end := time.Unix(0, grant.ValidUntilNS); end.Before(until) {
			until = end
		}
	}
	return until, nil
}

func (m *Manager) handoverMatchCurrent(authority *HandoverAuthority, match MatchResult, task *InterceptTask) bool {
	if authority == nil {
		return true // existing non-handover LI path
	}
	if authority.Incarnation != m.StateIncarnation() {
		return false
	}
	index := sort.Search(len(authority.Grants), func(i int) bool { return authority.Grants[i].FilterID >= match.FilterID })
	if index == len(authority.Grants) {
		return false
	}
	grant := authority.Grants[index]
	digest, err := captureFilterDigest(match.Filter)
	return err == nil && grant.FilterID == match.FilterID && grant.XID == task.XID && grant.ActivationGeneration == task.ActivationGeneration && grant.FilterRevision == match.Filter.Revision && grant.FilterSHA256 == digest
}
