package learnedrules

// Configuration returns owned immutable settings, including the frozen registry.
func (s *Store) Configuration() Config {
	c := s.config
	c.Domains = append([]DomainID(nil), c.Domains...)
	c.SupportedProtocols = append([]Protocol(nil), c.SupportedProtocols...)
	return c
}

func (r *Runtime) Configuration() Config { return r.Store.Configuration() }

// StatusForAdapter preserves protocol-specific count views over shared state.
// Session, publication and aggregate lifecycle/subscriber counters remain shared.
func (s *Store) StatusForAdapter(adapterID string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recountLocked()
	status := s.status
	status.Rules, status.Bytes, status.Endpoints = 0, 0, 0
	for _, entry := range s.rules {
		if entry.rule.AdapterID == adapterID {
			status.Rules++
			status.Bytes += entry.bytes
			status.Endpoints += len(entry.rule.Selectors)
		}
	}
	return status
}
