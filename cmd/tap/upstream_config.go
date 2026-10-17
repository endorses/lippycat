//go:build tap || all

package tap

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func applyTapUpstreamConfig(cmd *cobra.Command, config *processor.Config) error {
	flags := cmd.Flags()
	legacyFlag := "processor"
	legacyKey := "tap.processor_addr"
	if flags.Changed("upstream") {
		if flags.Changed("processor") || flags.Changed("processors") {
			return fmt.Errorf("cannot combine --upstream with --processor or --processors")
		}
		legacyFlag = "upstream"
	}
	if !flags.Changed("processor") && !flags.Changed("processors") && !flags.Changed("upstream") {
		if viper.InConfig("tap.upstream_addr") {
			if viper.InConfig(legacyKey) {
				return fmt.Errorf("cannot configure both tap.processor_addr and tap.upstream_addr")
			}
			legacyKey = "tap.upstream_addr"
		}
	}
	endpoints, settings, err := failover.Resolve(viper.GetViper(), flags, "tap", legacyKey, legacyFlag)
	if err != nil {
		return err
	}
	if !config.TLSEnabled {
		for _, endpoint := range endpoints {
			if endpoint.TLSServerName != "" {
				return fmt.Errorf("tls_server_name requires TLS")
			}
		}
	}
	config.FilterPolicy, err = filterpolicy.FromViper(viper.GetViper(), "tap")
	if err != nil {
		return err
	}
	config.UpstreamAddr = ""
	config.UpstreamProcessors = endpoints
	config.UpstreamFailover = settings
	return nil
}
