package securestore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalSourceRingBindingCoversPriorAndLegacySelection(t *testing.T) {
	a := cryptoKey(t, "source", 71)
	b := cryptoKey(t, "prior", 72)
	c := cryptoKey(t, "other", 73)
	target := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "fresh", 74)})
	load := func(prior KeyRef, legacy string) *Keyring {
		return cryptoRing(t, KeyConfig{Active: a, Prior: []KeyRef{prior}, LegacyID: legacy})
	}
	plain, err := target.SourceRingBinding(load(b, ""))
	require.NoError(t, err)
	again, err := target.SourceRingBinding(load(b, ""))
	require.NoError(t, err)
	require.Equal(t, plain, again)
	changedPrior, err := target.SourceRingBinding(load(c, ""))
	require.NoError(t, err)
	require.NotEqual(t, plain, changedPrior)
	legacyA, err := target.SourceRingBinding(load(b, "source"))
	require.NoError(t, err)
	legacyB, err := target.SourceRingBinding(load(b, "prior"))
	require.NoError(t, err)
	require.NotEqual(t, plain, legacyA)
	require.NotEqual(t, legacyA, legacyB)
	_, err = target.SourceRingBinding(target)
	require.Error(t, err)
	_, err = target.SourceRingBinding(cryptoRing(t, KeyConfig{Active: cryptoKey(t, "fresh", 75)}))
	require.Error(t, err, "fresh material also needs a fresh identifier")
	_, err = (*Keyring)(nil).SourceRingBinding(load(b, ""))
	require.Error(t, err)
}
