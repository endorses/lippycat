package cmdutil

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestMediaAdmissionOptInPrecedence(t *testing.T) {
	for _, prefix := range []string{"hunter.voip.rtp_ebpf", "tap.voip.rtp_ebpf"} {
		t.Run(prefix, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{Use: "voip"}
			RegisterMediaAdmissionFlags(cmd, v, prefix)
			config, err := ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.False(t, config.Enabled)
			require.NoError(t, cmd.ParseFlags([]string{"--rtp-ebpf-mode=shadow"}))
			config, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.False(t, config.Enabled)
			require.Equal(t, mediaadmission.ModeShadow, config.Mode)
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(strings.NewReader(strings.ReplaceAll(`ROOT:
  voip:
    rtp_ebpf:
      enabled: true
      failure_policy: closed
      pending_ttl: 45s
      replay_window: 90s
      replay_guard_capacity: 12
      replay_guard_bytes: 1536
      endpoint_capacity: 2048
      interface_domains:
        eth1: 7
`, "ROOT", strings.Split(prefix, ".")[0]))))
			config, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.True(t, config.Enabled)
			require.Equal(t, 45*time.Second, config.PendingTTL)
			require.Equal(t, 90*time.Second, config.ReplayWindow)
			require.Equal(t, 12, config.ReplayGuardCapacity)
			require.Equal(t, 1536, config.ReplayGuardBytes)
			require.Equal(t, mediaadmission.FailureClosed, config.FailurePolicy)
			require.Equal(t, 2048, config.EndpointCapacity)
			require.Equal(t, mediaadmission.DomainID(7), config.DomainForInterface("eth1"))
			require.NoError(t, cmd.ParseFlags([]string{"--rtp-ebpf=false", "--rtp-ebpf-failure-policy=open"}))
			config, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.False(t, config.Enabled)
			require.Equal(t, mediaadmission.FailureOpen, config.FailurePolicy)
		})
	}
}

func TestMediaAdmissionInvalidSettings(t *testing.T) {
	for key, value := range map[string]any{"mode": "automatic", "failure_policy": "ignore", "endpoint_capacity": 0, "pending_ttl": "-1s", "owner_capacity": -1, "replay_window": "0s", "replay_guard_capacity": 0, "replay_guard_bytes": -1} {
		t.Run(key, func(t *testing.T) {
			v := viper.New()
			cmd := &cobra.Command{Use: "voip"}
			RegisterMediaAdmissionFlags(cmd, v, "tap.voip.rtp_ebpf")
			v.Set("tap.voip.rtp_ebpf."+key, value)
			_, err := ReadMediaAdmissionConfig(v, "tap.voip.rtp_ebpf")
			require.Error(t, err)
		})
	}
}

func TestShadowSamplingFlagPrecedenceAndBounds(t *testing.T) {
	for _, prefix := range []string{"tap.voip.rtp_ebpf", "hunter.voip.rtp_ebpf"} {
		t.Run(prefix, func(t *testing.T) {
			cmd := &cobra.Command{Use: "synthetic"}
			v := viper.New()
			RegisterMediaAdmissionFlags(cmd, v, prefix)
			cfg, err := ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.Equal(t, uint32(1), cfg.ShadowSampleEvery)
			v.Set(prefix+".shadow_sample_every", uint32(7))
			cfg, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.Equal(t, uint32(7), cfg.ShadowSampleEvery)
			// Config-file values have lower precedence than a changed bound flag.
			v = viper.New()
			cmd = &cobra.Command{Use: "synthetic"}
			RegisterMediaAdmissionFlags(cmd, v, prefix)
			v.SetDefault(prefix+".shadow_sample_every", uint32(7))
			require.NoError(t, cmd.Flags().Set("rtp-ebpf-shadow-sample-every", "3"))
			cfg, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.Equal(t, uint32(3), cfg.ShadowSampleEvery)
			require.False(t, cfg.Enabled, "sampling alone does not enable capture admission")
			require.NoError(t, cmd.Flags().Set("rtp-ebpf-shadow-sample-every", "0"))
			_, err = ReadMediaAdmissionConfig(v, prefix)
			require.ErrorContains(t, err, "shadow_sample_every")
		})
	}
}
