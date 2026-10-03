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
