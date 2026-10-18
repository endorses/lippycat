//go:build li

package li

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"google.golang.org/protobuf/proto"
)

// PublishCaptureSelectionAuthority retains the lifecycle barrier through durable
// publication. Only distributed selectors leave the owner; local selectors bind
// opaque references to protected task generation watermarks instead of hashes.
// The callback must not reenter the LI lifecycle or administrative mutation API.
func (m *Manager) PublishCaptureSelectionAuthority(config HandoverConfig, processorID string, scopes []*management.CaptureSelectionScope, now time.Time, publish func([]*management.Filter, []*management.CaptureSelectionGrant, []byte) error) error {
	config, err := config.Normalize()
	if err != nil || !config.Enabled || processorID == "" || publish == nil || now.IsZero() || now.UnixNano() <= 0 {
		return errors.Join(ErrCaptureAuthority, err)
	}
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	filters, err := m.handoverFiltersLocked()
	if err != nil {
		return err
	}
	public := make([]*management.Filter, 0, len(filters))
	distributed := make([]*management.Filter, 0, len(filters))
	for _, f := range filters {
		if filtering.IsDistributedFilter(f) {
			distributed = append(distributed, f)
		}
	}
	encoded, err := m.buildHandoverAuthorityLocked(distributed, config, now)
	if err != nil {
		return err
	}
	authority, err := DecodeHandoverAuthority(encoded)
	if err != nil {
		return err
	}
	var grants []*management.CaptureSelectionGrant
	for _, f := range filters {
		if filtering.IsDistributedFilter(f) {
			public = append(public, f)
			continue
		}
		match, ok := m.filters.LookupFilter(f.Id)
		if !ok || !proto.Equal(match.Filter, f) {
			return ErrCaptureAuthority
		}
		task, err := m.registry.GetTaskDetails(match.XID)
		if err != nil || !task.IsActive() || task.IsExpired() || task.ActivationGeneration == 0 || f.Revision != task.ActivationGeneration || (!task.StartTime.IsZero() && now.Before(task.StartTime)) {
			return ErrCaptureAuthority
		}
		until := now.Add(config.LeaseDuration)
		if cutoff := TaskAuthorizationCutoff(task); !cutoff.IsZero() && cutoff.Before(until) {
			until = cutoff
		}
		if !until.After(now.Add(2 * config.ClockUncertainty)) {
			return ErrCaptureAuthority
		}
		allowed := grantSources(config.SourceIDs, f.TargetHunters)
		grant := &management.CaptureSelectionGrant{Id: f.Id, Revision: task.ActivationGeneration, ProcessorId: processorID, NotBeforeNs: now.Add(config.ClockUncertainty).UnixNano(), ExpiresAtNs: until.Add(-config.ClockUncertainty).UnixNano(), Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA}
		sourceSet := make(map[string]bool)
		scopeSet := make(map[string]map[uint32]bool)
		for _, scope := range scopes {
			if scope == nil || len(grantSources(allowed, []string{scope.HunterId})) == 0 {
				continue
			}
			if scopeSet[scope.HunterId] == nil {
				scopeSet[scope.HunterId] = make(map[uint32]bool)
			}
			if scopeSet[scope.HunterId][scope.Domain] {
				continue
			}
			scopeSet[scope.HunterId][scope.Domain] = true
			sourceSet[scope.HunterId] = true
			grant.Scopes = append(grant.Scopes, proto.Clone(scope).(*management.CaptureSelectionScope))
		}
		if len(grant.Scopes) == 0 {
			return ErrCaptureAuthority
		}
		sort.Slice(grant.Scopes, func(i, j int) bool {
			a, b := grant.Scopes[i], grant.Scopes[j]
			return a.HunterId < b.HunterId || a.HunterId == b.HunterId && a.Domain < b.Domain
		})
		sources := make([]string, 0, len(sourceSet))
		for source := range sourceSet {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		authority.Version = 2
		authority.Grants = append(authority.Grants, CaptureGrant{FilterID: f.Id, LocalOnly: true, XID: task.XID, ActivationGeneration: task.ActivationGeneration, FilterRevision: task.ActivationGeneration, SourceIDs: sources, ValidFromNS: now.UnixNano(), ValidUntilNS: until.UnixNano()})
		grants = append(grants, grant)
	}
	sort.Slice(authority.Grants, func(i, j int) bool { return authority.Grants[i].FilterID < authority.Grants[j].FilterID })
	encoded, err = json.Marshal(authority)
	if err != nil {
		return err
	}
	return publish(public, grants, encoded)
}

// ValidateCaptureSelectionAuthority accepts only authenticated public grant facts.
// The processor separately authenticates the exact media rule and packet tuple.
// Lease expiry applies to capturedAt, while current task generation, revocation
// and authorization cutoff still apply at delivery time.
func (m *Manager) ValidateCaptureSelectionAuthority(encoded []byte, policyFilters []*management.Filter, grants []*management.CaptureSelectionGrant, refs []*management.CaptureSelectionRef, source string, domain uint32, capturedAt, now time.Time, config HandoverConfig) ([]string, error) {
	authority, err := DecodeHandoverAuthority(encoded)
	if err != nil || authority.Version != 2 || len(refs) == 0 {
		return nil, ErrCaptureAuthority
	}
	index := make(map[string]CaptureGrant, len(authority.Grants))
	for _, g := range authority.Grants {
		index[g.FilterID] = g
	}
	public := make(map[string]*management.CaptureSelectionGrant, len(grants))
	for _, g := range grants {
		if g == nil || public[g.Id] != nil {
			return nil, ErrCaptureAuthority
		}
		public[g.Id] = g
	}
	seen := make(map[string]bool, len(refs))
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == nil || seen[ref.Id] {
			return nil, ErrCaptureAuthority
		}
		seen[ref.Id] = true
		g := public[ref.Id]
		binding, ok := index[ref.Id]
		if !ok || !binding.LocalOnly || g == nil || ref.Revision != g.Revision || g.Revision != binding.ActivationGeneration || g.Purpose != management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA || g.NotBeforeNs != time.Unix(0, binding.ValidFromNS).Add(config.ClockUncertainty).UnixNano() || g.ExpiresAtNs > time.Unix(0, binding.ValidUntilNS).Add(-config.ClockUncertainty).UnixNano() || g.ExpiresAtNs <= g.NotBeforeNs {
			return nil, ErrCaptureAuthority
		}
		allowed := false
		for _, scope := range g.Scopes {
			if scope != nil && scope.HunterId == source && scope.Domain == domain {
				allowed = true
			}
		}
		if !allowed || capturedAt.UnixNano() < g.NotBeforeNs || capturedAt.UnixNano() >= g.ExpiresAtNs {
			return nil, ErrCaptureAuthority
		}
		ids = append(ids, ref.Id)
	}
	if err := m.ValidateHandoverAuthority(encoded, policyFilters, ids, source, capturedAt, now, config); err != nil {
		return nil, err
	}
	return ids, nil
}

// SelectLocalSIP derives matching evidence inside the current task barrier. The
// returned authority is a private lifecycle token, never serialized or exported:
// local observation does not rely on a remote media capture lease. A subsequent
// definition change invalidates its generation before task lookup/delivery.
func (m *Manager) SelectLocalSIP(event sip.Event, source string) ([]string, *HandoverAuthority, error) {
	m.lifecycleMu.RLock()
	defer m.lifecycleMu.RUnlock()
	filters, err := m.handoverFiltersLocked()
	if err != nil {
		return nil, nil, err
	}
	matcher, err := filtering.CompileSIPFilters(filters)
	if err != nil {
		return nil, nil, err
	}
	ids, err := matcher.Match(event, source)
	if err != nil {
		return nil, nil, err
	}
	authority := &HandoverAuthority{Version: 2, Incarnation: m.StateIncarnation()}
	for _, id := range ids {
		match, ok := m.filters.LookupFilter(id)
		if !ok {
			return nil, nil, ErrCaptureAuthority
		}
		task, err := m.registry.GetTaskDetails(match.XID)
		if err != nil || !task.IsActive() || task.IsExpired() {
			return nil, nil, ErrCaptureAuthority
		}
		g := CaptureGrant{FilterID: id, XID: task.XID, ActivationGeneration: task.ActivationGeneration, FilterRevision: match.Filter.Revision, LocalOnly: !filtering.IsDistributedFilter(match.Filter)}
		if !g.LocalOnly {
			g.FilterSHA256, err = captureFilterDigest(match.Filter)
			if err != nil {
				return nil, nil, err
			}
		}
		authority.Grants = append(authority.Grants, g)
	}
	sort.Slice(authority.Grants, func(i, j int) bool { return authority.Grants[i].FilterID < authority.Grants[j].FilterID })
	return ids, authority, nil
}
