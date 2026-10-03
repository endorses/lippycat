//go:build hunter || all

package hunter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyHunterValidationPrecedesInitialization(t *testing.T) {
	policy := eventconfig.Default()
	policy.NTP.MaxEntries = 0
	h, err := New(Config{EventAnalysis: &policy})
	require.Nil(t, h)
	require.ErrorContains(t, err, "NTP")
}

func TestEventPolicyHunterDefaultInventory(t *testing.T) {
	h, err := New(Config{ProcessorAddr: "processor:55555", HunterID: "default-policy"})
	require.NoError(t, err)
	require.True(t, h.config.EventAnalysis.Inventory.Enabled)
	require.Empty(t, h.config.EventAnalysis.Inventory.LocalCIDRs)
}
