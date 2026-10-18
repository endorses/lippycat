//go:build processor || tap || all

package processor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capturegrant"
	sharedfilter "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/google/gopacket"
)

// captureGrantScopes maps explicit capture-policy sources to their local domain
// numbering, including configured wildcard profiles before a hunter registers.
func (p *Processor) captureGrantScopes() []*management.CaptureSelectionScope {
	var scopes []*management.CaptureSelectionScope
	seen := make(map[string]map[uint32]bool)
	for _, source := range p.config.LIHandover.SourceIDs {
		for _, mapping := range p.config.MediaRules.Sources {
			if mapping.HunterID != source && mapping.HunterID != "*" {
				continue
			}
			domain := uint32(mapping.HunterDomain)
			if seen[source] == nil {
				seen[source] = make(map[uint32]bool)
			}
			if !seen[source][domain] {
				scopes = append(scopes, &management.CaptureSelectionScope{HunterId: source, Domain: domain})
				seen[source][domain] = true
			}
		}
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].HunterId != scopes[j].HunterId {
			return scopes[i].HunterId < scopes[j].HunterId
		}
		return scopes[i].Domain < scopes[j].Domain
	})
	return scopes
}

// ValidateLocalMediaRule is tap's in-process equivalent of the hunter's signed
// grant check. The same configured issuer and installed policy own both paths.
func (p *Processor) ValidateLocalMediaRule(rule *management.MediaRule, sourceID string, domain uint32, packet gopacket.Packet, at time.Time) bool {
	if p.sharedPolicy == nil || rule == nil {
		return false
	}
	snapshot := p.sharedPolicy.installedSnapshot.Load()
	if snapshot == nil || at.UnixNano() < snapshot.ValidFromNs || at.UnixNano() >= snapshot.ValidUntilNs {
		return false
	}
	if err := p.sharedPolicy.state.Verifier().VerifyMediaRule(rule); err != nil {
		return false
	}
	return capturegrant.ValidateRule(snapshot, rule, sourceID, domain, packet, at) == nil
}

// scopedCaptureRules projects granted selections before signing. A signature is
// immutable: transport must never rewrite its scopes, endpoints or revision.
func (p *Processor) scopedCaptureRules(rules []mediarules.Rule) ([]mediarules.Rule, error) {
	if !p.config.LIHandover.Enabled || p.config.LITaskFilterDistributionScope != "local_only" {
		return rules, nil
	}
	private := make(map[string]bool)
	for _, f := range p.filterManager.GetAll() {
		if strings.HasPrefix(f.Id, "li-") && !sharedfilter.IsDistributedFilter(f) {
			private[f.Id] = true
		}
	}
	if len(private) == 0 {
		return rules, nil
	}
	var snapshot *management.PolicySnapshot
	if p.sharedPolicy != nil {
		snapshot = p.sharedPolicy.installedSnapshot.Load()
	}
	grants := make(map[string]*management.CaptureSelectionGrant)
	if snapshot != nil {
		for _, g := range snapshot.SelectionGrants {
			grants[g.Id] = g
		}
	}
	var result []mediarules.Rule
	for _, base := range rules {
		needs := false
		for _, id := range base.Call.FilterIDs {
			needs = needs || private[id]
		}
		if !needs {
			result = append(result, base)
			continue
		}
		if snapshot == nil || snapshot.ProtocolVersion != 2 || p.sharedPolicy.signer == nil {
			continue
		}
		for _, scope := range base.Scope {
			rule := base
			rule.ID = fmt.Sprintf("%s@%s/%d", base.ID, scope.HunterID, scope.Domain)
			rule.Scope = []mediarules.Scope{scope}
			rule.Endpoints = nil
			for _, e := range base.Endpoints {
				if e.Key.Domain == scope.Domain {
					rule.Endpoints = append(rule.Endpoints, e)
				}
			}
			rule.Call.FilterIDs = nil
			rule.Call.SelectionGrants = nil
			rule.Call.CapturePolicyRevision = snapshot.Revision
			if t := time.Unix(0, snapshot.ValidFromNs); t.After(rule.NotBefore) {
				rule.NotBefore = t
			}
			if t := time.Unix(0, snapshot.ValidUntilNs); t.Before(rule.ExpiresAt) {
				rule.ExpiresAt = t
			}
			for _, id := range base.Call.FilterIDs {
				if !private[id] {
					rule.Call.FilterIDs = append(rule.Call.FilterIDs, id)
					continue
				}
				g := grants[id]
				if g == nil || g.ProcessorId != base.Session.ProcessorID {
					continue
				}
				allowed := false
				for _, s := range g.Scopes {
					if s.HunterId == scope.HunterID && s.Domain == uint32(scope.Domain) {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
				rule.Call.SelectionGrants = append(rule.Call.SelectionGrants, mediarules.SelectionRef{ID: g.Id, Revision: g.Revision})
				if t := time.Unix(0, g.NotBeforeNs); t.After(rule.NotBefore) {
					rule.NotBefore = t
				}
				if t := time.Unix(0, g.ExpiresAtNs); t.Before(rule.ExpiresAt) {
					rule.ExpiresAt = t
				}
			}
			if len(rule.Call.SelectionGrants) == 0 || len(rule.Endpoints) == 0 || !rule.ExpiresAt.After(rule.NotBefore) || !rule.ExpiresAt.After(time.Now()) {
				continue
			}
			sort.Slice(rule.Call.SelectionGrants, func(i, j int) bool { return rule.Call.SelectionGrants[i].ID < rule.Call.SelectionGrants[j].ID })
			result = append(result, rule)
		}
	}
	return result, nil
}

func (p *Processor) signCaptureRule(rule *mediarules.Rule) error {
	if len(rule.Call.SelectionGrants) == 0 {
		return nil
	}
	if p.sharedPolicy == nil || p.sharedPolicy.signer == nil {
		return fmt.Errorf("capture rule signer unavailable")
	}
	signed, err := p.sharedPolicy.state.Verifier().SignMediaRule(p.sharedPolicy.signer, wire.EncodeRule(*rule))
	if err != nil {
		return err
	}
	rule.CaptureSignature = append([]byte(nil), signed.CaptureSignature...)
	return nil
}
