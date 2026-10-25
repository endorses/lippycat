package eventconfig

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSSHPolicyDefaultsValidationOwnershipAndIdentity(t *testing.T) {
	v := viper.New()
	config := FromViper(v)
	require.NoError(t, config.Validate())
	require.True(t, config.EffectiveSSH().Enabled)
	before := config.Fingerprint()
	copy := config.Clone()
	copy.SSH.MaxFlows++
	require.NotEqual(t, before, copy.Fingerprint())
	require.Equal(t, DefaultSSH().MaxFlows, config.EffectiveSSH().MaxFlows)
	v.Set("events.ssh.enabled", false)
	require.False(t, FromViper(v).EffectiveSSH().Enabled)
	for _, key := range []string{"events.ssh.max_flows", "events.ssh.max_bytes"} {
		for _, value := range []int{0, -1} {
			invalid := viper.New()
			invalid.Set(key, value)
			require.ErrorContains(t, FromViper(invalid).Validate(), "SSH")
		}
	}
}

func TestSSHFlagsUseExplicitPolicy(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	flags := pflag.NewFlagSet("ssh", pflag.ContinueOnError)
	Register(flags)
	require.NoError(t, flags.Parse([]string{"--ssh-analysis=false", "--ssh-analysis-max-flows=2", "--ssh-analysis-max-bytes=99"}))
	policy := FromViper(viper.GetViper()).EffectiveSSH()
	require.False(t, policy.Enabled)
	require.Equal(t, 2, policy.MaxFlows)
	require.EqualValues(t, 99, policy.MaxBytes)
}
