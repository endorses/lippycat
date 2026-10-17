//go:build tap || all

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestTapUpstreamSelectionConfiguration(t *testing.T) {
	viper.SetConfigType("yaml")
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
	cmd := &cobra.Command{}
	cmd.Flags().AddFlagSet(TapCmd.PersistentFlags())
	for _, test := range []struct {
		name, yaml string
		want       []string
		err        string
	}{
		{"local only", "{}", nil, ""},
		{"legacy", "tap:\n  processor_addr: one:55555", []string{"one:55555"}, ""},
		{"old alias", "tap:\n  upstream_addr: old:55555", []string{"old:55555"}, ""},
		{"list", "tap:\n  processors: [one:55555, two:55555]", []string{"one:55555", "two:55555"}, ""},
		{"conflict", "tap:\n  processor_addr: one:55555\n  processors: [two:55555]", nil, "cannot configure both"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, viper.ReadConfig(strings.NewReader(test.yaml)))
			config := processor.Config{TLSEnabled: true}
			err := applyTapUpstreamConfig(cmd, &config)
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
				return
			}
			require.NoError(t, err)
			var addresses []string
			for _, endpoint := range config.UpstreamProcessors {
				addresses = append(addresses, endpoint.Address)
			}
			require.Equal(t, test.want, addresses)
		})
	}
}

func TestTapFailoverFlagsInheritedByEveryProtocol(t *testing.T) {
	for _, cmd := range []*cobra.Command{dnsTapCmd, httpTapCmd, tlsTapCmd, emailTapCmd, voipTapCmd, radiusTapCmd} {
		for _, name := range []string{"processors", "processor-attempt-timeout", "processor-reconnect-attempts"} {
			require.NotNil(t, cmd.InheritedFlags().Lookup(name), "%s --%s", cmd.Name(), name)
		}
	}
}
func TestTapExcludesScopedCandidateTransports(t *testing.T) {
	exclusions, err := failover.NewExclusions("127.0.0.1:55555", []failover.Endpoint{{Address: "192.0.2.1:443"}, {Address: "[2001:db8::1]:8443"}})
	require.NoError(t, err)
	require.Contains(t, exclusions.Filter(), "tcp and host 192.0.2.1 and port 443")
	require.Contains(t, exclusions.Filter(), "tcp and host 2001:db8::1 and port 8443")
	require.NotContains(t, exclusions.Filter(), "not port")
}
