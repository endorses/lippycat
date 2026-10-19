package learnedrules

// Match returns complete, owned binding candidates, never subject attribution.
// Overflow discards all candidates to prevent partial-set unique resolution.
func (s *Store) Match(packet Packet, maxCandidates int) Candidates {
	return s.match(packet, maxCandidates, "")
}

// MatchForSource limits the authoritative candidate set to one actual source
// and observation domain before applying the candidate bound. A publisher can
// retain independent sources that reuse the same local domain and endpoints.
func (s *Store) MatchForSource(sourceID string, packet Packet, maxCandidates int) Candidates {
	if sourceID == "" {
		return Candidates{}
	}
	return s.match(packet, maxCandidates, sourceID)
}

func (s *Store) match(packet Packet, maxCandidates int, sourceID string) Candidates {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxCandidates <= 0 {
		s.status.CandidateOverflows++
		return Candidates{Overflow: true}
	}
	if !packet.Source.Address.IsValid() || !packet.Destination.Address.IsValid() || packet.Source.Port == 0 || packet.Destination.Port == 0 || (packet.Protocol != TCP && packet.Protocol != UDP) {
		return Candidates{}
	}
	var result Candidates
	for _, b := range s.activeLocked() {
		if !s.InScope(b, packet.Domain) || sourceID != "" && !s.InScopeForSource(b, sourceID, packet.Domain) {
			continue
		}
		a, ok := s.config.Registry.Lookup(b.AdapterID, b.ContextVersion)
		if !ok || a.Authorize(CloneBinding(b)) != nil {
			continue
		}
		for _, sel := range b.Selectors {
			if sel.Domain != packet.Domain || sel.Protocol != packet.Protocol {
				continue
			}
			left := sel.Direction != Destination && sel.Address == packet.Source.Address.Unmap() && sel.Port == packet.Source.Port
			right := sel.Direction != Source && sel.Address == packet.Destination.Address.Unmap() && sel.Port == packet.Destination.Port
			if !left && !right {
				continue
			}
			if sel.Qualifier.ID != "" && (a.Qualify == nil || !a.Qualify(CloneBinding(b), sel, packet)) {
				continue
			}
			if len(result.Bindings) == maxCandidates {
				s.status.CandidateOverflows++
				return Candidates{Overflow: true}
			}
			result.Bindings = append(result.Bindings, b)
			break
		}
	}
	return result
}
