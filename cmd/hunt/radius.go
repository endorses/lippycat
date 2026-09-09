//go:build hunter || all

package hunt

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var radiusHuntCmd = &cobra.Command{Use: "radius", Short: "Capture visible RADIUS authentication and accounting UDP traffic", Long: "Capture RADIUS with exact ordinary criteria and bounded observational response association. Distributed LI release verification remains pending.", RunE: func(cmd *cobra.Command, args []string) error {
	c, err := radiusconfig.Resolve(cmd, viper.GetViper())
	if err != nil {
		return err
	}
	return runHuntProtocol(cmd, args, "radius", c.BPF(cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter)), func(config *hunter.Config) {
		config.RADIUSOnly = true
		config.RADIUSPorts = c.Ports
		config.RADIUSScope = c.Scope
		config.RADIUSCorrelation = c.Correlation
		config.RADIUSMatcher = c.Matcher
	})
}}

func init() { radiusconfig.RegisterFlags(radiusHuntCmd); HuntCmd.AddCommand(radiusHuntCmd) }
