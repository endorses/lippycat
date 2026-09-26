//go:build (all || cli || processor || tap) && !li

package migrate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLIStateCommandAbsentWithoutLI(t *testing.T) {
	for _, cmd := range NewCommand().Commands() {
		require.NotEqual(t, "li-state", cmd.Name())
	}
}
