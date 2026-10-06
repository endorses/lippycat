package mediaadmission

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUncertaintyStatusDomainIsolationAndOwnedSnapshots(t *testing.T) {
	c, _ := testController(t, func(cfg *Config) { cfg.InterfaceDomains = map[string]DomainID{"a": 1, "b": 2} })
	stats := UncertaintyStats{UnknownCalls: 2, IdenticalDuplicates: 7, ConflictingDuplicates: 3}
	stats.Reasons[ReasonFaultyPRACK], stats.Reasons[ReasonPartialSDP] = 2, 1
	c.UpdateUncertainty(1, stats)
	require.Equal(t, stats, c.Status()[1].Uncertainty)
	require.Zero(t, c.Status()[2].Uncertainty.UnknownCalls)
	snapshot := c.Status()
	snapshot[1].Uncertainty.Reasons[ReasonFaultyPRACK] = 99
	require.Equal(t, uint64(2), c.Status()[1].Uncertainty.Reasons[ReasonFaultyPRACK])
	c.UpdateUncertainty(1, UncertaintyStats{IdenticalDuplicates: 7, ConflictingDuplicates: 3})
	require.Zero(t, c.Status()[1].Uncertainty.UnknownCalls)
	c.UpdateUncertainty(999, stats)
	require.Len(t, c.Status(), 3)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.UpdateUncertainty(1, stats)
				_ = c.Status()
			}
		}()
	}
	wg.Wait()
	require.NoError(t, c.Close(context.Background()))
	c.UpdateUncertainty(1, UncertaintyStats{UnknownCalls: 99})
	require.NotEqual(t, uint64(99), c.Status()[1].Uncertainty.UnknownCalls)
	disabled, err := NewController(context.Background(), DefaultConfig(), nil)
	require.NoError(t, err)
	disabled.UpdateUncertainty(1, stats)
	require.Equal(t, StateDisabled, disabled.Status()[0].State)
	require.Zero(t, disabled.Status()[0].Uncertainty.UnknownCalls)
}

func TestDegradedDurationIncludesClosedAndControlFailure(t *testing.T) {
	for _, policy := range []FailurePolicy{FailureOpen, FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			c, b := testController(t, func(cfg *Config) { cfg.FailurePolicy = policy })
			require.Error(t, c.MarkUnsynchronized(0, nil))
			st := c.Status()[0]
			require.False(t, st.DegradedSince.IsZero())
			require.GreaterOrEqual(t, st.DegradedDuration, time.Duration(0))
			require.Eventually(t, func() bool { return c.Status()[0].DegradedDuration > st.DegradedDuration }, time.Second, time.Millisecond)
			if policy == FailureClosed {
				require.Zero(t, c.Status()[0].OpenDuration)
			}
			require.NoError(t, c.ReplaceDesired(context.Background(), 0, nil))
			require.Zero(t, c.Status()[0].DegradedDuration)
			require.True(t, c.Status()[0].DegradedSince.IsZero())
			b.mu.Lock()
			b.failures["control"] = 1
			b.mu.Unlock()
			require.Error(t, c.MarkUnsynchronized(0, nil))
			require.Equal(t, StateControlFailed, c.Status()[0].State)
			require.False(t, c.Status()[0].DegradedSince.IsZero())
			require.GreaterOrEqual(t, c.Status()[0].DegradedDuration, time.Duration(0))
		})
	}
}
