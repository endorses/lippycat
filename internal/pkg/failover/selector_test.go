package failover

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSelectorOrderStickyAndIndependentCooldowns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RetryInitial = time.Hour
	cfg.RetryMax = time.Hour
	s := NewSelector([]Endpoint{{Address: "a:1"}, {Address: "b:2"}, {Address: "c:3"}}, cfg)
	now := time.Now()
	_, i, wait := s.Next(now)
	require.Zero(t, i)
	require.Zero(t, wait)
	s.Failed(i, now)
	_, i, wait = s.Next(now)
	require.Equal(t, 1, i)
	require.Zero(t, wait)
	s.Connected(i)
	_, i, _ = s.Next(now.Add(2 * time.Hour))
	require.Equal(t, 1, i, "a recovered primary must not cause failback")
	s.Disconnected(i)
	_, i, _ = s.Next(now)
	require.Equal(t, 1, i, "active endpoint receives its bounded reconnect opportunity")
	s.Failed(i, now)
	_, i, wait = s.Next(now)
	require.Equal(t, 2, i)
	require.Zero(t, wait, "unrelated cooldowns do not delay c")
	s.Failed(i, now)
	_, i, wait = s.Next(now)
	require.Equal(t, -1, i)
	require.Positive(t, wait)
}

func TestSelectorZeroReconnectAdvancesImmediately(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReconnectAttempts = 0
	s := NewSelector([]Endpoint{{Address: "a:1"}, {Address: "b:2"}}, cfg)
	s.Connected(0)
	s.Disconnected(0)
	_, i, wait := s.Next(time.Now())
	require.Equal(t, 1, i)
	require.Zero(t, wait)
}

func TestSelectorHonorsConfiguredReconnectBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReconnectAttempts = 3
	s := NewSelector([]Endpoint{{Address: "a:1"}, {Address: "b:2"}}, cfg)
	now := time.Now()
	s.Connected(0)
	s.Disconnected(0)
	for attempt := 0; attempt < 3; attempt++ {
		_, index, wait := s.Next(now)
		require.Zero(t, index)
		require.Zero(t, wait)
		s.Failed(index, now)
	}
	_, index, wait := s.Next(now)
	require.Equal(t, 1, index)
	require.Zero(t, wait)
}
