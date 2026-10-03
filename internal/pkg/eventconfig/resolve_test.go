package eventconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveOwnsPolicyAndPreservesExplicitInvalidLimits(t *testing.T) {
	defaults, err := Resolve(nil)
	require.NoError(t, err)
	require.Equal(t, Default(), *defaults)
	original := Default()
	original.Inventory.Enabled = true
	original.Inventory.LocalCIDRs = []string{"192.0.2.0/24"}
	owned, err := Resolve(&original)
	require.NoError(t, err)
	original.Inventory.LocalCIDRs[0] = "198.51.100.0/24"
	require.Equal(t, []string{"192.0.2.0/24"}, owned.Inventory.LocalCIDRs)
	original.NTP.MaxEntries = 0
	_, err = Resolve(&original)
	require.ErrorContains(t, err, "NTP")
}
