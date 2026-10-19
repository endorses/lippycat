package learnedrules

import (
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"slices"
)

type owner struct {
	lifetime callregistry.Lifetime
	callID   string
}

// Resolve uses exact endpoints in one observation domain. When both endpoints
// have known owners, only their intersection can resolve a call. Shared or
// contradictory ownership remains ambiguous; no most-recent-writer heuristic is
// used. This is attribution evidence, not independent output authorization.
func Resolve(rules []Rule, source, destination mediaadmission.EndpointKey) Resolution {
	if source.Validate() != nil || destination.Validate() != nil || source.Domain != destination.Domain {
		return Resolution{}
	}
	left, right := make(map[owner]CallAssociation), make(map[owner]CallAssociation)
	for _, rule := range rules {
		key := owner{lifetime: rule.Call.Lifetime, callID: rule.Call.CallID}
		for _, endpoint := range rule.Endpoints {
			if endpoint.Key == source {
				left[key] = rule.Call
			}
			if endpoint.Key == destination {
				right[key] = rule.Call
			}
		}
	}
	if len(left) != 0 && len(right) != 0 {
		intersection := make(map[owner]CallAssociation)
		for key, association := range left {
			if _, ok := right[key]; ok {
				intersection[key] = association
			}
		}
		if len(intersection) == 0 {
			return Resolution{Ambiguous: true}
		}
		return resolveMediaOwners(rules, intersection, source, destination)
	}
	if len(left) != 0 {
		return resolveMediaOwners(rules, left, source, destination)
	}
	return resolveMediaOwners(rules, right, source, destination)
}

// resolveMediaOwnersLocked retains exact immutable proof. Multiple rules for the
// same call may share endpoints, but differing selection authority cannot be
// chosen by iteration order. Equivalent rules choose a stable public rule ID.
func resolveMediaOwners(rules []Rule, owners map[owner]CallAssociation, source, destination mediaadmission.EndpointKey) Resolution {
	result := resolveOwners(owners)
	if !result.Resolved {
		return result
	}
	var selected *Rule
	for _, rule := range rules {
		if rule.Call.Lifetime != result.Call.Lifetime || rule.Call.CallID != result.Call.CallID {
			continue
		}
		matches := false
		for _, endpoint := range rule.Endpoints {
			if endpoint.Key == source || endpoint.Key == destination {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if selected != nil && (len(selected.Call.SelectionGrants) > 0 || len(rule.Call.SelectionGrants) > 0) {
			a, b := selected.Call, rule.Call
			if a.SelectionRevision != b.SelectionRevision || a.CapturePolicyRevision != b.CapturePolicyRevision || a.FromTag != b.FromTag || a.ToTag != b.ToTag || !slices.Equal(a.SelectionGrants, b.SelectionGrants) || !slices.Equal(a.FilterIDs, b.FilterIDs) {
				return Resolution{Ambiguous: true}
			}
		}
		if selected == nil || rule.ID < selected.ID {
			owned := CloneRule(rule)
			selected = &owned
		}
	}
	if selected != nil {
		result.Rule = selected
		result.Call = selected.Call
	}
	return result
}

func resolveOwners(owners map[owner]CallAssociation) Resolution {
	if len(owners) > 1 {
		return Resolution{Ambiguous: true}
	}
	for _, association := range owners {
		return Resolution{Call: association, Resolved: true}
	}
	return Resolution{}
}

// ResolveDialog requires nonempty exact dialog tags and handles reverse SIP
// direction. Initial/early dialogs without both verified tags cannot be matched
// by Call-ID alone. The processor still validates the message and transaction.
func ResolveDialog(rules []Rule, hunterID string, callID, fromTag, toTag string) Resolution {
	return resolveDialog(rules, hunterID, nil, callID, fromTag, toTag)
}

// ResolveDialogInDomain additionally requires a rule scoped to this observation
// domain and configured hunter. Equal tags in another domain cannot select SIP.
func ResolveDialogInDomain(rules []Rule, hunterID string, domain mediaadmission.DomainID, callID, fromTag, toTag string) Resolution {
	return resolveDialog(rules, hunterID, &domain, callID, fromTag, toTag)
}

func resolveDialog(rules []Rule, hunterID string, domain *mediaadmission.DomainID, callID, fromTag, toTag string) Resolution {
	if callID == "" || fromTag == "" || toTag == "" {
		return Resolution{}
	}
	owners := make(map[owner]CallAssociation)
	for _, rule := range rules {
		if len(rule.Call.SelectionGrants) > 0 {
			continue
		}
		if domain != nil {
			scoped := false
			for _, scope := range rule.Scope {
				if scope.Domain == *domain && (hunterID == "" || scope.HunterID == hunterID) {
					scoped = true
					break
				}
			}
			if !scoped {
				continue
			}
		}
		call := rule.Call
		if call.CallID == callID && ((call.FromTag == fromTag && call.ToTag == toTag) || (call.FromTag == toTag && call.ToTag == fromTag)) {
			owners[owner{lifetime: call.Lifetime, callID: call.CallID}] = call
		}
	}
	return resolveOwners(owners)
}
