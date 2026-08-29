package callregistry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStickySelectionPolicy(t *testing.T) {
	policy := StickySelectionPolicy{}
	require.True(t, policy.Select(SelectionInput{}))
	require.True(t, policy.Select(SelectionInput{FilterConfigured: true, DirectMatch: true}))
	require.True(t, policy.Select(SelectionInput{FilterConfigured: true, PreviouslySelected: true}))
	require.False(t, policy.Select(SelectionInput{FilterConfigured: true}))
}
