package eventspool

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestAnalysisPolicyRecoveryAndIdentityGuard(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	policy := sessionPolicy("old", "reliable", false)
	policy.AnalysisFingerprint = "analysis-v1:abcdef"
	require.NoError(t, s.BindSessionPolicy(policy))
	_, err = s.Enqueue(batch("hunter", "old", 1, 1, 1))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	s, err = Open(Config{Directory: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	saved, ok := s.SessionPolicy()
	require.True(t, ok)
	require.Equal(t, policy, saved)
	saved.AnalysisFingerprint = "changed"
	require.NoError(t, s.BindSessionPolicy(policy), "returned policy is a detached copy")
	require.ErrorContains(t, s.BindSessionPolicy(saved), "pending records use policy")
	require.NoError(t, s.Ack("hunter", "old", 1))
	require.ErrorContains(t, s.BindSessionPolicy(saved), "new producer session identity")
	require.ErrorContains(t, s.ResetSession(policy), "new producer session identity")
	_, session, event, sequence, err := s.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "old", session)
	require.EqualValues(t, 1, event)
	require.EqualValues(t, 1, sequence)
	saved.ProducerSessionID = "new"
	require.NoError(t, s.BindSessionPolicy(saved))
	_, session, event, sequence, err = s.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "new", session)
	require.Zero(t, event)
	require.Zero(t, sequence)
}

func TestAnalysisFingerprintBound(t *testing.T) {
	s, err := Open(Config{Directory: t.TempDir()})
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	policy := sessionPolicy("session", "reliable", false)
	policy.AnalysisFingerprint = strings.Repeat("x", 257)
	require.ErrorContains(t, s.BindSessionPolicy(policy), "fingerprint exceeds")
}
