//go:build li

package radiusconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func liSetup(t *testing.T, yaml string, args ...string) (*cobra.Command, *viper.Viper) {
	t.Helper()
	cmd := &cobra.Command{}
	RegisterLIFlags(cmd)
	require.NoError(t, cmd.ParseFlags(args))
	v := viper.New()
	v.SetConfigType("yaml")
	if yaml != "" {
		require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
	}
	return cmd, v
}
func TestLIConfigDefaultsDoNotAuthorize(t *testing.T) {
	cmd, v := liSetup(t, "")
	c, err := ResolveLI(cmd, v)
	require.NoError(t, err)
	require.Equal(t, LIConfig{TransactionTimeout: 30 * time.Second}, c)
}
func TestLIConfigPrecedenceAndScope(t *testing.T) {
	t.Setenv("LIPPYCAT_LI_RADIUS_OPERATOR_SCOPE", "env-domain")
	cmd, v := liSetup(t, "li:\n  radius:\n    operator_scope: yaml-domain\n    profile_revision: rev-1\n    source: eth0\n", "--li-radius-operator-scope", "flag-domain", "--li-radius-origin-node", "poi-a", "--li-radius-mac-profile", radius.MACProfileUppercaseHyphen, "--li-radius-correlation-state-file", "/tmp/poi-state")
	c, err := ResolveLI(cmd, v)
	require.NoError(t, err)
	require.Equal(t, radius.ScopeBinding{OperatorScope: "flag-domain", ProfileRevision: "rev-1", OriginNodeID: "poi-a", SourceID: "eth0"}, c.Scope)
	require.Equal(t, radius.MACProfileUppercaseHyphen, c.MACProfile)
	require.Equal(t, "/tmp/poi-state", c.CorrelationStateFile)
	other, v := liSetup(t, "li:\n  radius:\n    operator_scope: yaml-domain\n    profile_revision: rev-1\n")
	c, err = ResolveLI(other, v)
	require.NoError(t, err)
	require.Equal(t, "env-domain", c.Scope.OperatorScope)
}
func TestLIConfigRejectsIncompleteAndUnsupportedProfiles(t *testing.T) {
	for _, args := range [][]string{{"--li-radius-operator-scope", "operator"}, {"--li-radius-profile-revision", "v1"}, {"--li-radius-origin-node", "poi"}, {"--li-radius-source", "eth0"}, {"--li-radius-mac-profile", radius.MACProfileUppercaseHyphen}, {"--li-radius-operator-scope", " "}, {"--li-radius-mac-profile", "ethernet"}} {
		cmd, v := liSetup(t, "", args...)
		_, err := ResolveLI(cmd, v)
		require.Error(t, err, "%v", args)
	}
	cmd, v := liSetup(t, "li:\n  radius:\n    operator_scope: [a,b]\n")
	_, err := ResolveLI(cmd, v)
	require.Error(t, err)
}

func TestLITransactionTimeoutValidation(t *testing.T) {
	for _, value := range []string{"0s", "500ms", "301s", "bad"} {
		cmd, v := liSetup(t, "")
		v.Set("li.radius.transaction_timeout", value)
		_, err := ResolveLI(cmd, v)
		require.Error(t, err, value)
	}
	cmd, v := liSetup(t, "li:\n  radius:\n    transaction_timeout: 45s\n")
	c, err := ResolveLI(cmd, v)
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, c.TransactionTimeout)
	cmd, v = liSetup(t, "li:\n  radius:\n    transaction_timeout: 45\n")
	_, err = ResolveLI(cmd, v)
	require.Error(t, err)
}
