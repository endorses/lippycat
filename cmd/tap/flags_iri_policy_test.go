//go:build all && li

package tap

import (
	"strings"
	"testing"

	othercmd "github.com/endorses/lippycat/cmd/process"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func iriProfileSettingsCommand(t *testing.T) *cobra.Command {
	t.Helper()
	previous := liIRIPolicyProfileFile
	t.Cleanup(func() { liIRIPolicyProfileFile = previous })
	t.Setenv("LIPPYCAT_LI_IRI_POLICY_PROFILE", "")
	return selectionSettingsCommand(t)
}

func TestLIIRIPolicyProfileConfigurationPrecedence(t *testing.T) {
	command := iriProfileSettingsCommand(t)
	require.Empty(t, GetLIConfig().IRIPolicyProfileFile)
	require.Empty(t, command.PersistentFlags().Lookup("li-iri-policy-profile").DefValue)
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  iri_policy_profile: configured-profile.json\n")))
	require.Equal(t, "configured-profile.json", GetLIConfig().IRIPolicyProfileFile)
	t.Setenv("LIPPYCAT_LI_IRI_POLICY_PROFILE", "environment-profile.json")
	require.Equal(t, "environment-profile.json", GetLIConfig().IRIPolicyProfileFile)
	require.NoError(t, command.ParseFlags([]string{"--li-iri-policy-profile=flag-profile.json"}))
	require.Equal(t, "flag-profile.json", GetLIConfig().IRIPolicyProfileFile)
	require.NoError(t, command.ParseFlags([]string{"--li-iri-policy-profile="}))
	require.Empty(t, GetLIConfig().IRIPolicyProfileFile, "explicit empty overrides environment and YAML")
}

func TestLIIRIPolicyProfileIgnoresForeignCommandBindings(t *testing.T) {
	command := iriProfileSettingsCommand(t)
	foreign := othercmd.ProcessCmd
	flag := foreign.Flags().Lookup("li-iri-policy-profile")
	require.NotNil(t, flag)
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(previous)); flag.Changed = changed })
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  iri_policy_profile: configured-profile.json\n")))
	require.NoError(t, foreign.ParseFlags([]string{"--li-iri-policy-profile=foreign-profile.json"}))
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "configured-profile.json", GetLIConfig().IRIPolicyProfileFile)
	require.NoError(t, command.ParseFlags([]string{"--li-iri-policy-profile=local-profile.json"}))
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "local-profile.json", GetLIConfig().IRIPolicyProfileFile)
}

func TestLIIRIPolicyProfileInheritedAndAppliedToTap(t *testing.T) {
	parent := iriProfileSettingsCommand(t)
	child := &cobra.Command{Use: "voip"}
	parent.AddCommand(child)
	require.NoError(t, child.ParseFlags([]string{"--li-iri-policy-profile=child-profile.json"}))
	var config processor.Config
	applyLIDeliveryConfig(&config, GetLIConfig())
	require.Equal(t, "child-profile.json", config.LIIRIPolicyProfileFile)
}
