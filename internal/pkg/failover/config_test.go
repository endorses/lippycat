package failover

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormalizeConfig(t *testing.T) {
	got, err := NormalizeConfig(Config{})
	require.NoError(t, err)
	require.Equal(t, DefaultConfig(), got)
	got, err = NormalizeConfig(Config{AttemptTimeout: time.Second, ReconnectAttempts: 0})
	require.NoError(t, err)
	require.Zero(t, got.ReconnectAttempts)
	require.Equal(t, time.Second, got.RetryInitial)
	require.Equal(t, time.Minute, got.RetryMax)
	for _, config := range []Config{
		{AttemptTimeout: -time.Second}, {RetryInitial: -time.Second},
		{RetryMax: -time.Second}, {ReconnectAttempts: -1},
		{RetryInitial: time.Minute, RetryMax: time.Second},
	} {
		_, err := NormalizeConfig(config)
		require.Error(t, err)
	}
}
