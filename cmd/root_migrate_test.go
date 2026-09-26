//go:build all || cli || processor || tap

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrationCommandRegistered(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"migrate", "filter-store"})
	require.NoError(t, err)
	require.Equal(t, "filter-store", command.Name())
	for _, flag := range []string{"source", "source-format", "destination", "init", "in-place", "resume", "key-file", "key-id", "read-key"} {
		require.NotNil(t, command.Flags().Lookup(flag), flag)
	}
}
