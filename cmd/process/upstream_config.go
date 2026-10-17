//go:build processor || all

package process

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func applyProcessUpstreamConfig(cmd *cobra.Command, config *processor.Config) error {
	flags := cmd.Flags()
	legacyFlag := "processor"
	legacyKey := "processor.processor_addr"
	if flags.Changed("upstream") {
		if flags.Changed("processor") || flags.Changed("processors") {
			return fmt.Errorf("cannot combine --upstream with --processor or --processors")
		}
		legacyFlag = "upstream"
	}
	if !flags.Changed("processor") && !flags.Changed("processors") && !flags.Changed("upstream") {
		if viper.InConfig("processor.upstream_addr") {
			if viper.InConfig(legacyKey) {
				return fmt.Errorf("cannot configure both processor.processor_addr and processor.upstream_addr")
			}
			legacyKey = "processor.upstream_addr"
		}
	}
	endpoints, settings, err := failover.Resolve(viper.GetViper(), flags, "processor", legacyKey, legacyFlag)
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
	config.FilterPolicy, err = filterpolicy.FromViper(viper.GetViper(), "processor")
	if err != nil {
		return err
	}
	config.UpstreamAddr = ""
	config.UpstreamProcessors = endpoints
	config.UpstreamFailover = settings
	return nil
}
