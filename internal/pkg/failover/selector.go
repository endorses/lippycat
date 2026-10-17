package failover

import (
	"math/rand/v2"
	"time"
)

// Selector orders connection attempts. A manager owns it on a single goroutine.
// Cooldowns belong to endpoints, so one unavailable peer never delays another.
type Selector struct {
	endpoints []Endpoint
	config    Config
	cursor    int
	retries   int
	failures  []int
	ready     []time.Time
}

func NewSelector(endpoints []Endpoint, config Config) *Selector {
	return &Selector{endpoints: append([]Endpoint(nil), endpoints...), config: config, failures: make([]int, len(endpoints)), ready: make([]time.Time, len(endpoints))}
}

// Next returns wait > 0 and index -1 when all candidates are cooling down.
func (s *Selector) Next(now time.Time) (Endpoint, int, time.Duration) {
	var earliest time.Time
	for offset := 0; offset < len(s.endpoints); offset++ {
		i := (s.cursor + offset) % len(s.endpoints)
		if !now.Before(s.ready[i]) {
			return s.endpoints[i], i, 0
		}
		if earliest.IsZero() || s.ready[i].Before(earliest) {
			earliest = s.ready[i]
		}
	}
	if earliest.IsZero() {
		return Endpoint{}, -1, time.Second
	}
	return Endpoint{}, -1, earliest.Sub(now)
}

func (s *Selector) Failed(index int, now time.Time) {
	s.failures[index]++
	backoff := s.config.RetryInitial
	for i := 1; i < s.failures[index] && backoff < s.config.RetryMax; i++ {
		if backoff > s.config.RetryMax/2 {
			backoff = s.config.RetryMax
			break
		}
		backoff *= 2
	}
	backoff = min(backoff, s.config.RetryMax)
	// Equal jitter avoids synchronized fleets while retaining a positive cooldown.
	backoff = backoff/2 + time.Duration(rand.Int64N(max(int64(backoff-backoff/2), 1)))
	s.ready[index] = now.Add(backoff)
	if s.retries > 0 {
		s.retries--
	}
	if s.retries == 0 {
		s.cursor = (index + 1) % len(s.endpoints)
	} else {
		s.cursor = index
		// Active reconnect attempts are consecutive bounded attempts. Their setup
		// deadline supplies the bound; endpoint cooldown starts after that budget.
		s.ready[index] = now
	}
}

func (s *Selector) Connected(index int) {
	s.cursor = index
	s.retries = s.config.ReconnectAttempts
	s.failures[index] = 0
	s.ready[index] = time.Time{}
}

func (s *Selector) Disconnected(index int) {
	s.cursor = index
	if s.retries == 0 {
		s.cursor = (index + 1) % len(s.endpoints)
	}
}
