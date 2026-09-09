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

func setup(t *testing.T, yaml string, args ...string) (*cobra.Command, *viper.Viper) {
	t.Helper()
	cmd := &cobra.Command{}
	RegisterFlags(cmd)
	require.NoError(t, cmd.ParseFlags(args))
	v := viper.New()
	v.SetConfigType("yaml")
	if yaml != "" {
		require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
	}
	return cmd, v
}
func TestResolvePrecedence(t *testing.T) {
	t.Setenv("LIPPYCAT_RADIUS_USERNAME", "env-user")
	cmd, v := setup(t, "radius:\n  username: yaml-user\n  ports: [1812, 1912]\n  transaction_timeout: 15s\n", "--radius-username", "flag-user")
	c, err := Resolve(cmd, v)
	require.NoError(t, err)
	require.Equal(t, []uint16{1812, 1912}, c.Ports)
	require.Equal(t, 15*time.Second, c.Correlation.Lifetime)
	require.Equal(t, "flag-user", c.Matcher.(*matcher).group.Spec().Criteria[0].Value)
	cmd, v = setup(t, "radius:\n  username: yaml-user\n")
	c, err = Resolve(cmd, v)
	require.NoError(t, err)
	require.Equal(t, "env-user", c.Matcher.(*matcher).group.Spec().Criteria[0].Value)
}
func TestResolveValidation(t *testing.T) {
	for _, args := range [][]string{{"--radius-port", "0"}, {"--radius-port", "65536"}, {"--radius-max-per-key", "17"}, {"--radius-max-candidates", "0"}, {"--radius-transaction-timeout", "31s"}, {"--radius-protocol-scope", "radsec"}, {"--radius-mac", "AA-BB-CC-DD-EE-FF"}, {"--radius-mac-profile", "any"}, {"--radius-line-profile", "inventory", "--radius-line-id", "line"}, {"--radius-line-profile", "nas-port-id", "--radius-line-id", "line"}, {"--radius-username", ""}, {"--radius-attribute", "020378"}} {
		cmd, v := setup(t, "", args...)
		_, err := Resolve(cmd, v)
		require.Error(t, err, "%v", args)
	}
	for _, yaml := range []string{"radius:\n  max_per_key: 1.5\n", "radius:\n  username: [alice]\n", "radius:\n  username: ''\n", "radius:\n  attribute: [123]\n", "radius:\n  attribute: []\n", "radius:\n  transaction_timeout: 30\n"} {
		cmd, v := setup(t, yaml)
		_, err := Resolve(cmd, v)
		require.Error(t, err, yaml)
	}
}
func TestLineProfilesAndConjunction(t *testing.T) {
	for _, profile := range []string{"nas-port-id", "agent-circuit-id"} {
		cmd, v := setup(t, "", "--radius-line-profile", profile, "--radius-line-id", "line-A", "--radius-operator-scope", "operator-A", "--radius-profile-revision", "v1", "--radius-username", "Alice@example.test")
		c, err := Resolve(cmd, v)
		require.NoError(t, err)
		spec := c.Matcher.(*matcher).group.Spec()
		require.Len(t, spec.Criteria, 2)
		require.Equal(t, "account", spec.Criteria[0].TargetKind)
		require.Equal(t, "line", spec.Criteria[1].TargetKind)
		require.Empty(t, spec.TaskID)
	}
	cmd, v := setup(t, "", "--radius-mac", "AA-BB-CC-DD-EE-FF", "--radius-mac-profile", radius.MACProfileUppercaseHyphen)
	_, err := Resolve(cmd, v)
	require.NoError(t, err)
}
func TestAttributeEnvironmentAndIndependentCommands(t *testing.T) {
	t.Setenv("LIPPYCAT_RADIUS_ATTRIBUTE", "010361,010362")
	cmd, v := setup(t, "")
	c, err := Resolve(cmd, v)
	require.NoError(t, err)
	require.Len(t, c.Matcher.(*matcher).group.Spec().Criteria, 2)
	first, _ := setup(t, "", "--radius-username", "first")
	second, _ := setup(t, "", "--radius-username", "second")
	c, err = Resolve(first, v)
	require.NoError(t, err)
	require.Equal(t, "first", c.Matcher.(*matcher).group.Spec().Criteria[0].Value)
	c, err = Resolve(second, v)
	require.NoError(t, err)
	require.Equal(t, "second", c.Matcher.(*matcher).group.Spec().Criteria[0].Value)
}
