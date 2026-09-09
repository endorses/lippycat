//go:build (processor || all) && li

package process

import (
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRADIUSLIConfigBridge(t *testing.T) {
	cmd := &cobra.Command{}
	radiusconfig.RegisterLIFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--li-radius-operator-scope", "operator-a", "--li-radius-profile-revision", "v1", "--li-radius-origin-node", "hunter-a", "--li-radius-source", "eth0", "--li-radius-mac-profile", radius.MACProfileUppercaseHyphen, "--li-radius-correlation-state-file", "/tmp/hunter-a"}))
	var config processor.Config
	require.NoError(t, applyRADIUSLIConfig(cmd, &config))
	require.Equal(t, radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1", OriginNodeID: "hunter-a", SourceID: "eth0"}, config.LIRADIUSScope)
	require.Equal(t, "/tmp/hunter-a", config.LIRADIUSCorrelationStateFile)
	require.Equal(t, radius.MACProfileUppercaseHyphen, config.LIRADIUSMACProfile)
}
