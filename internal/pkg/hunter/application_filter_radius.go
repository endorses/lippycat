//go:build hunter || tap || all

package hunter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/radius"
)

type radiusApplicationFilter struct {
	id        string
	predicate *radius.Predicate
	group     *radius.Group
}

// MatchRADIUSObservation selects a validated observation and returns grouped
// direct evidence separately from ordinary IDs. Callers must correlate before
// dropping unmatched packets. It is deliberately separate from generic packet
// filter IDs, which are not RADIUS authorization provenance.
func (af *ApplicationFilter) MatchRADIUSObservation(observation *radius.Observation) (bool, []string, []radius.AttributionReference) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	var ids []string
	var references []radius.AttributionReference
	for _, f := range af.radiusFilters {
		if f.group != nil {
			ref, matched, err := f.group.Match(observation)
			if err == nil && matched {
				ids = append(ids, f.id)
				references = append(references, ref)
			}
		} else if f.predicate != nil && observation != nil {
			matched, err := f.predicate.Match(observation.Message)
			if err == nil && matched {
				ids = append(ids, f.id)
				ref, ok, refErr := f.predicate.Reference(observation)
				if refErr == nil && ok {
					references = append(references, ref)
				}
			}
		}
	}
	return len(ids) > 0, ids, references
}

// updateRADIUSFiltersLocked retains invalid configured entries as deny-only
// sentinels, so rejected criteria cannot turn into the allow-all empty policy.
func (af *ApplicationFilter) updateRADIUSFiltersLocked(filters []*management.Filter) {
	af.radiusFilters = nil
	for _, f := range filters {
		if f == nil || !f.Enabled || !filtering.IsRADIUSFilter(f.Type) {
			continue
		}
		p, g, err := filtering.CompileRADIUSFilter(f)
		if err != nil {
			logger.Warn("Rejecting invalid RADIUS application filter", "filter_id", f.Id, "error", err)
		}
		af.radiusFilters = append(af.radiusFilters, radiusApplicationFilter{id: f.Id, predicate: p, group: g})
	}
}

// SupportsRADIUS reports the observation-aware application matching capability.
func (af *ApplicationFilter) SupportsRADIUS() bool { return true }

// RADIUSEvidenceCurrent rejects removed or revised criteria before inheritance.
func (af *ApplicationFilter) RADIUSEvidenceCurrent(ref radius.AttributionReference) bool {
	af.mu.RLock()
	defer af.mu.RUnlock()
	for _, f := range af.radiusFilters {
		if f.group != nil && f.group.CurrentReference(ref) || f.predicate != nil && f.predicate.CurrentReference(ref) {
			return true
		}
	}
	return false
}
