package filterpolicy

func (s *State) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latest == nil {
		return 0
	}
	return s.latest.Snapshot.Revision
}
