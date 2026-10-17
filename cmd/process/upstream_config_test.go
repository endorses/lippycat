//go:build processor || all

package process

import (
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestProcessUpstreamSelectionConfiguration(t *testing.T) {
	viper.SetConfigType("yaml")
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
	cmd := &cobra.Command{}
	cmd.Flags().AddFlagSet(ProcessCmd.Flags())
	for _, test := range []struct {
		name, yaml string
		want       []string
		err        string
	}{
		{"local only", "{}", nil, ""},
		{"legacy", "processor:\n  processor_addr: one:55555", []string{"one:55555"}, ""},
		{"old alias", "processor:\n  upstream_addr: old:55555", []string{"old:55555"}, ""},
		{"list", "processor:\n  processors: [one:55555, two:55555]", []string{"one:55555", "two:55555"}, ""},
		{"conflict", "processor:\n  processor_addr: one:55555\n  processors: [two:55555]", nil, "cannot configure both"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, viper.ReadConfig(strings.NewReader(test.yaml)))
			config := processor.Config{TLSEnabled: true}
			err := applyProcessUpstreamConfig(cmd, &config)
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
