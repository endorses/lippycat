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
      endpoint_capacity: 2048
      interface_domains:
        eth1: 7
`, "ROOT", strings.Split(prefix, ".")[0]))))
			config, err = ReadMediaAdmissionConfig(v, prefix)
			require.NoError(t, err)
			require.True(t, config.Enabled)
			require.Equal(t, 45*time.Second, config.PendingTTL)
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
	for key, value := range map[string]any{"mode": "automatic", "failure_policy": "ignore", "endpoint_capacity": 0, "pending_ttl": "-1s", "owner_capacity": -1} {
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
