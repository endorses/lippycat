//go:build hunter || all

package hunt

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func hunterSelectorFixture(t *testing.T, yaml string) {
	t.Helper()
	for _, name := range []string{"processor", "processors", "processor-attempt-timeout", "processor-reconnect-attempts", "insecure"} {
		flag := HuntCmd.PersistentFlags().Lookup(name)
		original, originalChanged := flag.Value.String(), flag.Changed
		if slice, ok := flag.Value.(pflag.SliceValue); ok {
			items := append([]string(nil), slice.GetSlice()...)
			require.NoError(t, slice.Replace(nil))
			t.Cleanup(func() { require.NoError(t, slice.Replace(items)); flag.Changed = originalChanged })
		} else {
			require.NoError(t, flag.Value.Set(flag.DefValue))
			t.Cleanup(func() { require.NoError(t, flag.Value.Set(original)); flag.Changed = originalChanged })
		}
		flag.Changed = false
	}
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(yaml)))
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
}

func TestHunterProcessorListAllProtocols(t *testing.T) {
	hunterSelectorFixture(t, `hunter:
  processors:
    - address: 192.0.2.1:55555
      tls_server_name: relay-a.example
    - relay-b.example:55555
  failover:
    attempt_timeout: 4s
    reconnect_attempts: 0
  forward_mode: events
  events:
    delivery_profile: memory-only
`)
	for _, protocol := range []string{"generic", "dns", "http", "tls", "email", "voip", "radius"} {
		t.Run(protocol, func(t *testing.T) {
			config, err := buildHunterConfigChecked(protocolHunterConfigSpec(protocol, ""))
			require.NoError(t, err)
			require.Equal(t, []failover.Endpoint{{Address: "192.0.2.1:55555", TLSServerName: "relay-a.example"}, {Address: "relay-b.example:55555"}}, config.Processors)
			require.Equal(t, config.Processors[0].Address, config.ProcessorAddr)
			require.Equal(t, 4*time.Second, config.Failover.AttemptTimeout)
			require.Zero(t, config.Failover.ReconnectAttempts)
			require.Equal(t, "events", config.ForwardMode)
			require.Equal(t, "memory_only", config.EventDeliveryProfile)
		})
	}
}

func TestHunterProcessorListCLIOverridesLegacyYAML(t *testing.T) {
	hunterSelectorFixture(t, "hunter:\n  processor_addr: old:55555")
	require.NoError(t, HuntCmd.PersistentFlags().Set("processors", "new-a:55555,new-b:55555"))
	config, err := buildHunterConfigChecked(genericHunterConfigSpec(""))
	require.NoError(t, err)
	require.Equal(t, []failover.Endpoint{{Address: "new-a:55555"}, {Address: "new-b:55555"}}, config.Processors)
	require.Equal(t, "new-a:55555", config.ProcessorAddr)
	require.NoError(t, HuntCmd.PersistentFlags().Set("processor", "conflicting:55555"))
	_, err = buildHunterConfigChecked(genericHunterConfigSpec(""))
	require.ErrorContains(t, err, "both")
}

func TestHunterRejectsEndpointTLSIdentityWithoutTLS(t *testing.T) {
	hunterSelectorFixture(t, "hunter:\n  processors:\n    - address: 192.0.2.1:55555\n      tls_server_name: station.example")
	require.NoError(t, HuntCmd.PersistentFlags().Set("insecure", "true"))
	_, err := buildHunterConfigChecked(genericHunterConfigSpec(""))
	require.ErrorContains(t, err, "requires TLS")
}

func TestHunterProcessorFlagNotIndividuallyRequired(t *testing.T) {
	flag := HuntCmd.PersistentFlags().Lookup("processor")
	require.Empty(t, flag.Annotations["cobra_annotation_bash_completion_one_required_flag"])
}
