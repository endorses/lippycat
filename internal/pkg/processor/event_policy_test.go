//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyProcessorValidationPrecedesInitialization(t *testing.T) {
	policy := eventconfig.Default()
	policy.Inventory.Enabled = true
	p, err := New(Config{EventAnalysis: &policy})
	require.Nil(t, p)
	require.ErrorContains(t, err, "local CIDRs")
}
