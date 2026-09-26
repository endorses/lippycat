package securestore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitializationCommitmentBindsKeyPurposeAndContext(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 97)})
	first, err := ring.InitializationBinding(FilterSnapshot, []byte("source/configuration"))
	require.NoError(t, err)
	second, err := ring.InitializationBinding(AdministrativeState, []byte("source/configuration"))
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	second, err = ring.InitializationBinding(FilterSnapshot, []byte("changed/configuration"))
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	other := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 98)})
	second, err = other.InitializationBinding(FilterSnapshot, []byte("source/configuration"))
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	_, err = ring.InitializationBinding(FilterSnapshot, make([]byte, MaxInitializationContextBytes+1))
	require.Error(t, err)
}
