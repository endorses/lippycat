//go:build tap || all

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/logflags"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var radiusTapCmd = &cobra.Command{Use: "radius", Short: "Standalone RADIUS capture with processor outputs", Long: "Capture visible RADIUS authentication/accounting UDP traffic. Ordinary capture needs no LI task. LI builds can independently enable X1-authorized format-11 X2 delivery.", RunE: func(cmd *cobra.Command, args []string) error {
	logflags.Bind(TapCmd.PersistentFlags())
	c, err := radiusconfig.Resolve(cmd, viper.GetViper())
	if err != nil {
		return err
	}
	return runTapProtocol(cmd, args, protocolcatalog.MustLookup("radius"), c.BPF(cmdutil.GetStringConfig("tap.bpf_filter", bpfFilter)), tapRuntimeHooks{ConfigureSourceConfig: func(config *source.LocalSourceConfig) {
		config.RADIUSPorts = c.Ports
		config.RADIUSScope = c.Scope
		config.RADIUSCorrelation = c.Correlation
		config.RADIUSMatcher = c.Matcher
	}})
}}

func init() { radiusconfig.RegisterFlags(radiusTapCmd); TapCmd.AddCommand(radiusTapCmd) }
