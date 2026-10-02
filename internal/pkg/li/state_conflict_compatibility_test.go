//go:build li

package li

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConflictStateCompatibilityFixtures(t *testing.T) {
	for _, name := range []string{"702c2c3f", "3b387355", "disarmed"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/conflict_state_" + name + ".json")
			require.NoError(t, err)
			state, err := UnmarshalStateSnapshot(data)
			require.NoError(t, err)
			encoded, err := MarshalStateSnapshot(state)
			require.NoError(t, err)
			restored, err := UnmarshalStateSnapshot(encoded)
			require.NoError(t, err)
			require.Equal(t, state, restored)
			if name == "disarmed" {
				require.True(t, restored.Tasks[0].Definition.ConflictDisarmed)
				require.Contains(t, string(encoded), `"ConflictDisarmed":true`)
				require.Contains(t, string(encoded), `"ConflictReason":"no_common_targets"`)
			} else {
				require.NotContains(t, string(encoded), "ConflictDisarmed")
				require.NotContains(t, string(encoded), "ConflictReason")
			}
			unknown := bytes.Replace(encoded, []byte(`"Conflict":`), []byte(`"UnknownAuthorization":true,"Conflict":`), 1)
			_, err = UnmarshalStateSnapshot(unknown)
			require.ErrorIs(t, err, ErrStateSnapshot, "compatibility must not relax unknown-field rejection")
		})
	}
}
