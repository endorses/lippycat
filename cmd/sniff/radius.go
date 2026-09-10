//go:build cli || all

package sniff

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/logflags"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/radiusconfig"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var radiusCmd = &cobra.Command{Use: "radius", Short: "Sniff visible RADIUS authentication and accounting UDP traffic", Long: "Capture supported RADIUS UDP messages with exact conjunctive identity criteria and bounded observational response association. Supports text/JSON, PCAP, structured logs and virtual-interface outputs independently of LI.", RunE: func(cmd *cobra.Command, args []string) error {
	logflags.Bind(SniffCmd.PersistentFlags())
	c, err := radiusconfig.Resolve(cmd, viper.GetViper())
	if err != nil {
		return err
	}
	_ = protocolcatalog.MustLookup("radius")
	// Resolve parent bindings without overwriting YAML/environment defaults.
	format = viper.GetString("sniff.format")
	quiet = viper.GetBool("sniff.quiet")
	if format != "json" && format != "text" {
		return fmt.Errorf("unsupported output format %q", format)
	}
	sniffConfigured(cmd, args, &c, c.BPF(filter))
	return nil
}}

func init() {
	radiusconfig.RegisterFlags(radiusCmd)
	radiusCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "Write selected RADIUS packets to PCAP")
	SniffCmd.AddCommand(radiusCmd)
}
