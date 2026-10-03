package remotecapture

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyRemoteValidationPrecedesDial(t *testing.T) {
	policy := eventconfig.Default()
	policy.NTP.MaxEntries = 0
	client, err := NewClientWithConfig(&ClientConfig{Address: "invalid address", EventAnalysis: &policy}, &types.NoopEventHandler{})
	require.Nil(t, client)
	require.ErrorContains(t, err, "NTP")
	client, err = NewClientWithConfig(nil, &types.NoopEventHandler{})
	require.Nil(t, client)
	require.ErrorContains(t, err, "configuration is required")
}
