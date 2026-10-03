//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyProcessorValidationPrecedesInitialization(t *testing.T) {
	policy := eventconfig.Default()
	policy.Inventory.LocalCIDRs = []string{"invalid-prefix"}
	p, err := New(Config{EventAnalysis: &policy})
	require.Nil(t, p)
	require.ErrorContains(t, err, "local CIDR")
}

func TestEventPolicyProcessorDefaultInventory(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	require.True(t, p.config.EventAnalysis.Inventory.Enabled)
	require.Empty(t, p.config.EventAnalysis.Inventory.LocalCIDRs)
}
